use crate::transcript::{Direction, Subsequence};

pub(crate) struct LabelEncoder;

pub(crate) fn new_encoder(_seed: [u8; 32]) -> impl Encoder {
    todo!();
    LabelEncoder
}

/// A transcript encoder.
///
/// This is an internal implementation detail that should not be exposed to the
/// public API.
pub(crate) trait Encoder {
    /// Returns the encoding for the given subsequence of the transcript.
    ///
    /// # Arguments
    ///
    /// * `seq` - The subsequence to encode.
    fn encode_subsequence(&self, direction: Direction, seq: &Subsequence) -> Vec<u8>;
}

impl Encoder for LabelEncoder {
    fn encode_subsequence(&self, _direction: Direction, _seq: &Subsequence) -> Vec<u8> {
        todo!()
    }
}
