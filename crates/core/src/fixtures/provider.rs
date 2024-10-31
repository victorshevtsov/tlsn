use crate::transcript::{
    encoding::{Encoder, EncodingProvider},
    Direction, Idx, Transcript,
};

struct LabelEncoder;

/// A ChaCha encoding provider fixture.
pub struct ChaChaProvider {
    encoder: LabelEncoder,
    transcript: Transcript,
}

impl ChaChaProvider {
    /// Creates a new ChaCha encoding provider.
    pub(crate) fn new(seed: [u8; 32], transcript: Transcript) -> Self {
        todo!()
    }
}

impl EncodingProvider for ChaChaProvider {
    fn provide_encoding(&self, direction: Direction, idx: &Idx) -> Option<Vec<u8>> {
        todo!()
    }
}
