//! This crate provides tooling for instantiating MPC TLS machinery for leader
//! and follower.

//! The main API objects are [MpcTlsLeader] and [MpcTlsFollower], which wrap the
//! necessary cryptographic machinery and also an [MpcTlsChannel] for
//! communication.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod components;
mod config;
mod error;
//pub(crate) mod follower;
pub(crate) mod leader;
pub mod msg;

mod decode;
mod record_layer;
mod transcript;
//mod dump;

pub use components::{build_follower, build_leader};
pub use config::{
    MpcTlsCommonConfig, MpcTlsCommonConfigBuilder, MpcTlsCommonConfigBuilderError,
    MpcTlsFollowerConfig, MpcTlsFollowerConfigBuilder, MpcTlsFollowerConfigBuilderError,
    MpcTlsLeaderConfig, MpcTlsLeaderConfigBuilder, MpcTlsLeaderConfigBuilderError,
    TranscriptConfig, TranscriptConfigBuilder, TranscriptConfigBuilderError,
};
pub use error::MpcTlsError;
//pub use follower::{FollowerCtrl, MpcTlsFollower, MpcTlsFollowerData};
//pub use leader::{LeaderCtrl, MpcTlsData, MpcTlsLeader};
use tls_core::msgs::message::{OpaqueMessage, PlainMessage};
use utils_aio::duplex::Duplex;

/// A channel for sending and receiving messages between leader and follower
pub type MpcTlsChannel = Box<dyn Duplex<msg::MpcTlsMessage>>;

/// Sets the role of a party
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRole {
    Leader,
    Follower,
}

/// The direction of a message
pub(crate) enum Direction {
    /// Data sent to the TLS peer
    Sent,
    /// Data received from the TLS peer
    Recv,
}

/// Wrapper for TLS records that need to be encrypted.
struct EncryptRecord {
    info: EncryptInfo,
    visibility: Visibility,
}

/// Either contains the message or the length of the message.
enum EncryptInfo {
    Message(PlainMessage),
    Length(usize),
}

/// Wrapper for TLS records that need to be decrypted.
struct DecryptRecord {
    msg: OpaqueMessage,
    visibility: Visibility,
}

/// Sets the visibility for en-/decryption operations.
enum Visibility {
    Private,
    Public,
}
