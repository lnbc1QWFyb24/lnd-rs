use super::*;

#[test]
fn busy_queue_rejects_and_dropped_queued_work_is_skipped() {
    let (started, observed) = mpsc::channel();
    let (release, gates) = mpsc::channel();
    let worker = spawn_worker(move |entropy| {
        started.send(entropy[0]).unwrap();
        gates.recv().unwrap();
        Ok(vec![entropy[0]])
    })
    .unwrap();

    let active = worker.submit(vec![0; PAIRING_ENTROPY_BYTES]).unwrap();
    assert_eq!(observed.recv().unwrap(), 0);
    let queued = worker.submit(vec![1; PAIRING_ENTROPY_BYTES]).unwrap();
    let error = worker.submit(vec![9; PAIRING_ENTROPY_BYTES]).unwrap_err();
    assert!(error.to_string().contains("pairing worker busy"));
    drop(queued);

    release.send(()).unwrap();
    assert_eq!(active.blocking_recv().unwrap().unwrap(), vec![0]);
    // A bounded synchronous send is a test synchronization probe: it waits for
    // the abandoned queue entry to be consumed without sleeps or polling.
    let (reply, probe) = oneshot::channel();
    worker
        .sender
        .send(Request {
            entropy: vec![2; PAIRING_ENTROPY_BYTES],
            reply,
        })
        .unwrap();
    assert_eq!(
        observed.recv().unwrap(),
        2,
        "abandoned queued work must not run"
    );
    release.send(()).unwrap();
    assert_eq!(probe.blocking_recv().unwrap().unwrap(), vec![2]);
    let Worker {
        sender,
        _thread: thread,
    } = worker;
    drop(sender);
    thread.join().unwrap();
}

#[test]
fn invalid_entropy_never_enters_the_worker() {
    let worker = spawn_worker(|entropy| Ok(entropy.to_vec())).unwrap();
    let valid = worker.submit(vec![7; PAIRING_ENTROPY_BYTES]).unwrap();
    assert_eq!(valid.blocking_recv().unwrap().unwrap(), vec![7; 14]);
    for size in [0, 13, 15, 4096] {
        let error = worker.submit(vec![7; size]).unwrap_err();
        assert!(error.to_string().contains("invalid pairing entropy length"));
    }
    let Worker {
        sender,
        _thread: thread,
    } = worker;
    drop(sender);
    thread.join().unwrap();
}

#[test]
fn abandoned_active_reply_does_not_block_the_next_request() {
    let (started, observed) = mpsc::channel();
    let (release, gates) = mpsc::channel();
    let worker = spawn_worker(move |entropy| {
        started.send(entropy[0]).unwrap();
        gates.recv().unwrap();
        Ok(vec![entropy[0]])
    })
    .unwrap();
    let abandoned = worker.submit(vec![3; PAIRING_ENTROPY_BYTES]).unwrap();
    assert_eq!(observed.recv().unwrap(), 3);
    drop(abandoned);
    let next = worker.submit(vec![4; PAIRING_ENTROPY_BYTES]).unwrap();
    release.send(()).unwrap();
    assert_eq!(observed.recv().unwrap(), 4);
    release.send(()).unwrap();
    assert_eq!(next.blocking_recv().unwrap().unwrap(), vec![4]);
    let Worker {
        sender,
        _thread: thread,
    } = worker;
    drop(sender);
    thread.join().unwrap();
}
