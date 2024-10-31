use mpz_memory_core::Vector;
use tls_core::msgs::enums::ContentType;

/// A transcript for TLS traffic
///
/// Records traffic bytes using VM references.
#[derive(Default)]
pub(crate) struct Transcript {
    sent: InnerTranscript,
    recv: InnerTranscript,
}

impl Transcript {
    pub(crate) fn record_sent(&mut self, typ: ContentType, traffic: Vector<U8>) {
        self.sent.record(typ, traffic);
    }

    pub(crate) fn record_recv(&mut self, typ: ContentType, traffic: Vector<U8>) {
        self.recv.record(typ, traffic);
    }

    pub(crate) fn seq(&self) -> (u64, u64) {
        (self.sent.seq, self.recv.seq)
    }

    pub(crate) fn size(&self) -> (u64, u64) {
        (self.sent.size, self.recv.size)
    }

    pub(crate) fn into_inner(self) -> (Vec<Vector<U8>>, Vec<Vector<U8>>) {
        (self.sent.bytes, self.recv.bytes)
    }
}

#[derive(Default)]
struct InnerTranscript {
    pub(crate) seq: u64,
    pub(crate) size: usize,
    pub(crate) bytes: Vec<Vector<U8>>,
}

impl InnerTranscript {
    pub(crate) fn record(&mut self, typ: ContentType, traffic: Vector<U8>) {
        self.seq += 1;
        if let ContentType::ApplicationData = typ {
            self.size += traffic.len();
            self.bytes.push(traffic);
        }
    }
}
