use futures::future::Either;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, OrTransport};
use libp2p::identity::Keypair;
use libp2p::{noise, quic, tcp, Transport};
use std::time::Duration;

/// Build a combined QUIC + TCP transport for the given identity keypair.
///
/// QUIC has TLS 1.3 encryption and stream multiplexing built in.
/// TCP falls back to Noise + Yamux for environments where QUIC has issues
/// (e.g. some Windows network configurations).
pub fn create_transport(
    id_keys: &Keypair,
) -> Result<Boxed<(libp2p::PeerId, StreamMuxerBox)>, crate::error::PqP2pError> {
    let quic_transport = quic::tokio::Transport::new(quic::Config::new(id_keys))
        .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)));

    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::new().nodelay(true))
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise::Config::new(id_keys).unwrap())
        .multiplex(libp2p::yamux::Config::default())
        .timeout(Duration::from_secs(10))
        .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)));

    let transport = OrTransport::new(quic_transport, tcp_transport)
        .map(|either_output, _| match either_output {
            Either::Left((peer_id, muxer)) => (peer_id, muxer),
            Either::Right((peer_id, muxer)) => (peer_id, muxer),
        })
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
