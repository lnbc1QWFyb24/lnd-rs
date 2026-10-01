use super::*;

#[tokio::test]
async fn final_slice_owner_retains_capacity_and_exhaustion_is_terminal() {
    let (shutdown, receiver) = watch::channel(false);
    let budget = ReceiveBudget::new(1024, shutdown);
    let mut buffer = budget.allocate(512).unwrap();
    buffer.as_mut_slice()[511] = 42;
    let bytes = buffer.finish(512);
    let clone = bytes.clone();
    let slice = bytes.slice(511..);
    drop(bytes);
    drop(clone);
    assert_eq!(slice.as_ref(), &[42]);
    assert_eq!(budget.used(), 768);
    let remainder = budget.reserve(256).unwrap();
    assert!(budget.reserve(1).is_err());
    assert!(
        *receiver.borrow(),
        "saturation shuts down every session task"
    );
    budget.closed().await;
    drop(remainder);
    drop(slice);
    assert_eq!(budget.used(), 0);
    assert!(
        budget.reserve(1).is_err(),
        "a saturated session cannot reconnect"
    );
}
