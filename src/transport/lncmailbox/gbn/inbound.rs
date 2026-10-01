use bytes::Bytes;
use tokio::sync::mpsc;

use super::super::receive_budget::ReceiveBudget;

pub(super) enum Inbound {
    Public(mpsc::Receiver<Vec<u8>>),
    Budgeted(mpsc::Receiver<Bytes>),
}

impl Inbound {
    pub(super) async fn recv(&mut self, budget: Option<&ReceiveBudget>) -> Option<Bytes> {
        let receive = async {
            match self {
                Self::Public(rx) => rx.recv().await.map(Bytes::from),
                Self::Budgeted(rx) => rx.recv().await,
            }
        };
        tokio::select! {
            biased;
            () = closed(budget) => None,
            item = receive => item,
        }
    }
}

pub(super) async fn closed(budget: Option<&ReceiveBudget>) {
    match budget {
        Some(budget) => budget.closed().await,
        None => std::future::pending().await,
    }
}
