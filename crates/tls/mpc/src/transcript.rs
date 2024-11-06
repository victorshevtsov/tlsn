use mpz_memory_core::{binary::U8, Vector};
use tls_core::msgs::enums::ContentType;

/// A transcript for TLS traffic
///
/// Records traffic bytes using VM references.
#[derive(Default)]
pub(crate) struct Transcript {
    pub(crate) seq: u64,
    pub(crate) size: usize,
    pub(crate) bytes: Vec<Vector<U8>>,
}

impl Transcript {
    pub(crate) fn record(&mut self, typ: ContentType, traffic: Vector<U8>) {
        self.seq += 1;
        if let ContentType::ApplicationData = typ {
            self.size += traffic.len();
            self.bytes.push(traffic);
        }
    }

    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    pub(crate) fn size(&self) -> usize {
        self.size
    }

    pub(crate) fn into_inner(self) -> Vec<Vector<U8>> {
        self.bytes
    }
}
