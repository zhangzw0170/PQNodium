use thiserror::Error;

/// Errors for the P2P layer.
#[derive(Debug, Error)]
pub enum PqP2pError {
    /// Generic transport-layer error.
    #[error("transport error: {0}")]
    Transport(String),
    /// No encrypted session exists with the given peer.
    #[error("no session established with peer: {0}")]
    NoSession(String),
    /// Cryptographic handshake failure.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// Dialing a remote peer failed.
    #[error("dial failed: {0}")]
    DialFailed(String),
    /// Message exceeds the configured maximum size.
    #[error("message too large: {0} bytes")]
    MessageTooLarge(usize),
    /// Multiaddr is malformed or missing required components.
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    /// Underlying I/O error from the OS or network stack.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl PqP2pError {
    pub fn transport(msg: impl Into<String>) -> Self {
        Self::Transport(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = PqP2pError::Transport("connection reset".to_string());
        assert_eq!(format!("{err}"), "transport error: connection reset");
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err = PqP2pError::from(io_err);
        assert!(err.to_string().contains("io error"));
    }

    #[test]
    fn message_too_large() {
        let err = PqP2pError::MessageTooLarge(99999);
        assert!(err.to_string().contains("99999"));
    }

    #[test]
    fn invalid_address() {
        let err = PqP2pError::InvalidAddress("not-an-address".to_string());
        assert!(err.to_string().contains("not-an-address"));
    }
}
