//! This module implements [`UniversalHash`](super::UniversalHash) for Ghash.

mod ghash_core;
mod ghash_inner;

pub use ghash_inner::{Ghash, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};
