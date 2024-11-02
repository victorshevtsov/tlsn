use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
/// Configuration struct for [Ghash](crate::ghash::Ghash).
pub struct GhashConfig {
    /// Number of block shares to provision.
    #[builder(default = "1026")]
    pub block_count: usize,
}

impl GhashConfig {
    /// Creates a new builder for the [GhashConfig].
    pub fn builder() -> GhashConfigBuilder {
        GhashConfigBuilder::default()
    }
}
