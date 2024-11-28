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
    /// Records traffic bytes.
    ///
    /// # Arguments
    ///
    /// * `typ` - Content type of the TLS message.
    /// * `traffic` - The byte references to the TLS traffic.
    pub(crate) fn record(&mut self, typ: ContentType, traffic: Vector<U8>) {
        if let ContentType::ApplicationData = typ {
            self.size += traffic.len();
            self.bytes.push(traffic);
        }
    }

    /// Returns the current TLS sequence number and increments it.
    pub(crate) fn inc_seq(&mut self) -> u64 {
        let seq = self.seq;
        self.seq += 1;

        seq
    }

    /// Returns the current TLS sequence number.
    pub(crate) fn seq(&mut self) -> u64 {
        self.seq
    }

    /// Returns the transcript size in bytes.
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// Returns the inner traffic bytes.
    pub(crate) fn into_inner(self) -> Vec<Vector<U8>> {
        self.bytes
    }
}
