//! Scoped trace capture for dependency privacy regressions.
#[path = "../tests/mailbox_json_memory/relay.rs"]
pub(crate) mod mailbox_relay;

use std::{
    io,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct Writer(Arc<Mutex<Vec<u8>>>);
impl io::Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn trace_capture() -> (tracing::Dispatch, Arc<Mutex<Vec<u8>>>) {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = Writer(bytes.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    (tracing::Dispatch::new(subscriber), bytes)
}
