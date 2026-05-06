use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::identity::Keypair;
use libp2p::{quic, Transport};

/// Build a QUIC transport for the given identity keypair.
///
/// QUIC has TLS 1.3 encryption and stream multiplexing built in,
/// so no additional Noise or yamux upgrade is needed.
pub fn create_transport(
    id_keys: &Keypair,
) -> Result<Boxed<(libp2p::PeerId, StreamMuxerBox)>, crate::error::PqP2pError> {
    let transport = quic::tokio::Transport::new(quic::Config::new(id_keys))
        .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)))
        .boxed();

    Ok(transport)
}

/// Generate a random Ed25519 keypair for libp2p transport identity.
pub fn generate_transport_keypair() -> Keypair {
    Keypair::generate_ed25519()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair() {
        let kp = generate_transport_keypair();
        let peer_id = kp.public().to_peer_id();
        assert!(!peer_id.to_string().is_empty());
    }

    #[test]
    fn generate_distinct_keypairs() {
        let kp1 = generate_transport_keypair();
        let kp2 = generate_transport_keypair();
        let pid1 = kp1.public().to_peer_id();
        let pid2 = kp2.public().to_peer_id();
        assert_ne!(pid1, pid2);
    }

    #[test]
    fn create_transport_succeeds() {
        let kp = generate_transport_keypair();
        let transport = create_transport(&kp);
        assert!(transport.is_ok());
    }
}
