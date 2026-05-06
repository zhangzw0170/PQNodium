use libp2p::Multiaddr;
use std::fmt;

/// Events emitted by a PqNode.
#[derive(Debug, Clone)]
pub enum PqEvent {
    Listening {
        address: Multiaddr,
    },
    PeerConnected {
        peer_id: String,
    },
    PeerDisconnected {
        peer_id: String,
    },
    PeerDiscovered {
        peer_id: String,
        addresses: Vec<Multiaddr>,
    },
    KademliaBootstrapResult {
        success: bool,
        peers_found: usize,
    },
    MessageReceived {
        from: String,
        data: Vec<u8>,
    },
    InboundConnectionError {
        error: String,
    },
    OutboundConnectionError {
        peer_id: String,
        error: String,
    },
    UnknownEvent {
        description: String,
    },
}

impl fmt::Display for PqEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqEvent::Listening { address } => write!(f, "listening on {address}"),
            PqEvent::PeerConnected { peer_id } => write!(f, "peer connected: {peer_id}"),
            PqEvent::PeerDisconnected { peer_id } => write!(f, "peer disconnected: {peer_id}"),
            PqEvent::PeerDiscovered { peer_id, addresses } => {
                write!(f, "discovered {peer_id} at {addresses:?}")
            }
            PqEvent::KademliaBootstrapResult {
                success,
                peers_found,
            } => write!(
                f,
                "Kademlia bootstrap: {} ({} peers)",
                if *success { "ok" } else { "failed" },
                peers_found
            ),
            PqEvent::MessageReceived { from, data } => {
                write!(f, "message from {from} ({} bytes)", data.len())
            }
            PqEvent::InboundConnectionError { error } => {
                write!(f, "inbound connection error: {error}")
            }
            PqEvent::OutboundConnectionError { peer_id, error } => {
                write!(f, "outbound error to {peer_id}: {error}")
            }
            PqEvent::UnknownEvent { description } => {
                write!(f, "unknown event: {description}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_display_listening() {
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/1234/quic-v1".parse().unwrap();
        let event = PqEvent::Listening {
            address: addr.clone(),
        };
        let s = event.to_string();
        assert!(s.contains("listening"));
        assert!(s.contains(&addr.to_string()));
    }

    #[test]
    fn event_display_peer_connected() {
        let event = PqEvent::PeerConnected {
            peer_id: "QmTest".to_string(),
        };
        assert!(event.to_string().contains("QmTest"));
    }

    #[test]
    fn event_display_peer_discovered() {
        let addr: Multiaddr = "/ip4/1.2.3.4/udp/4001/quic-v1".parse().unwrap();
        let event = PqEvent::PeerDiscovered {
            peer_id: "QmPeer".to_string(),
            addresses: vec![addr],
        };
        assert!(event.to_string().contains("QmPeer"));
    }

    #[test]
    fn event_display_message() {
        let event = PqEvent::MessageReceived {
            from: "QmSender".to_string(),
            data: vec![1, 2, 3],
        };
        let s = event.to_string();
        assert!(s.contains("QmSender"));
        assert!(s.contains("3 bytes"));
    }

    #[test]
    fn event_clone() {
        let event = PqEvent::PeerConnected {
            peer_id: "QmTest".to_string(),
        };
        let _event2 = event.clone();
    }
}
