use std::{fmt, io, net::AddrParseError, sync::PoisonError};

use crate::client::connection::ConnectionId;
use bevy::prelude::{Deref, DerefMut, Resource};
use rcgen::RcgenError;
use tokio::runtime::Runtime;

use self::channel::ChannelId;

pub const DEFAULT_MESSAGE_QUEUE_SIZE: usize = 150;
pub const DEFAULT_KILL_MESSAGE_QUEUE_SIZE: usize = 10;
pub const DEFAULT_KEEP_ALIVE_INTERVAL_S: u64 = 4;

pub type ClientId = u64;

pub mod channel;

#[derive(Resource, Deref, DerefMut)]
pub struct AsyncRuntime(pub(crate) Runtime);
pub(crate) type InternalConnectionRef = quinn::Connection;

/// Enum with possibles errors that can occur in Bevy Quinnet
#[derive(thiserror::Error, Debug)]
pub enum QuinnetError {
    #[error("IP/socket address is invalid")]
    InvalidAddress(#[from] AddrParseError),
    #[error("failed to generate a self-signed certificate")]
    CertificateGenerationFailed(#[from] RcgenError),
    #[error("client with id `{0}` is unknown")]
    UnknownClient(ClientId),
    #[error("client with id `{0}` is already disconnected")]
    ClientAlreadyDisconnected(ClientId),
    #[error("connection with id `{0}` is unknown")]
    UnknownConnection(ConnectionId),
    #[error("connection is 'disconnected'")]
    ConnectionClosed,
    #[error("connection is already closed")]
    ConnectionAlreadyClosed,
    #[error("channel with id `{0}` is unknown")]
    UnknownChannel(ChannelId),
    #[error("channel is already closed")]
    ChannelAlreadyClosed,
    #[error("connection has no default channel")]
    NoDefaultChannel,
    #[error("endpoint is already closed")]
    EndpointAlreadyClosed,
    #[error("failed serialization")]
    Serialization,
    #[error("failed deserialization")]
    Deserialization,
    #[error("data could not be sent on the channel because the channel is currently full and sending would require blocking")]
    FullQueue,
    #[error("receiving half of the internal channel was explicitly closed or has been dropped")]
    InternalChannelClosed,
    #[error("hosts file is invalid")]
    InvalidHostFile,
    #[error("lock acquisition failure")]
    LockAcquisitionFailure,
    #[error("certificate action was already sent for a CertificateInteractionEvent")]
    CertificateActionAlreadyApplied,
    #[error("failed to read/write file(s)")]
    IoError(#[from] io::Error),
    #[error("rustls protocol error")]
    RustlsError(#[from] rustls::Error),
}

impl<T> From<PoisonError<T>> for QuinnetError {
    fn from(_: PoisonError<T>) -> Self {
        Self::LockAcquisitionFailure
    }
}

/// SHA-256 hash of the certificate data in DER form
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CertificateFingerprint([u8; 32]);

impl CertificateFingerprint {
    pub fn new(buf: [u8; 32]) -> Self {
        CertificateFingerprint(buf)
    }

    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }
}

impl From<&rustls::Certificate> for CertificateFingerprint {
    fn from(cert: &rustls::Certificate) -> CertificateFingerprint {
        let hash = ring::digest::digest(&ring::digest::SHA256, &cert.0);
        let fingerprint_bytes = hash.as_ref().try_into().unwrap();
        CertificateFingerprint(fingerprint_bytes)
    }
}

impl fmt::Display for CertificateFingerprint {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.to_base64(), f)
    }
}
