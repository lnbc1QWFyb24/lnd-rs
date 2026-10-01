use super::*;

#[test]
fn cancelling_the_async_owner_wakes_a_blocking_bridge_before_runtime_drop() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let handle = runtime.handle().clone();
    let (cancel, mut cancelled) = watch::channel(false);
    let owner = CancelHandshake(cancel);
    let (entered, started) = std::sync::mpsc::channel();
    let (result, finished) = std::sync::mpsc::channel();
    let _task = runtime.spawn_blocking(move || {
        // Adjacent positive control: ordinary control results are preserved.
        assert_eq!(
            wait_control(&handle, &mut cancelled, async { Ok(17) }).unwrap(),
            17
        );
        let blocked: Result<(), ClientConnError> = wait_control(&handle, &mut cancelled, async {
            entered.send(()).unwrap();
            std::future::pending().await
        });
        result
            .send(matches!(blocked, Err(ClientConnError::Closed)))
            .unwrap();
    });
    started
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    drop(owner);
    assert!(finished
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap());
    // This is ordinary drop, with no shutdown_background/timeout escape hatch.
    drop(runtime);
}

#[test]
fn cancellation_before_an_operation_prevents_polling_it() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let (cancel, mut cancelled) = watch::channel(false);
    let owner = CancelHandshake(cancel);
    drop(owner);
    let result: Result<(), ClientConnError> =
        wait_control(runtime.handle(), &mut cancelled, async {
            panic!("a cancelled handshake must not begin another control operation");
        });
    assert!(matches!(result, Err(ClientConnError::Closed)));
}
