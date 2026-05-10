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
    NatStatus {
        is_public: bool,
    },
    RelayReservation {
        relay_peer_id: String,
        accepted: bool,
    },
    DirectConnectionUpgraded {
        peer_id: String,
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
            PqEvent::NatStatus { is_public } => {
                write!(
                    f,
                    "NAT status: {}",
                    if *is_public { "public" } else { "private" }
                )
            }
            PqEvent::RelayReservation {
                relay_peer_id,
                accepted,
            } => {
                write!(
                    f,
                    "relay reservation with {relay_peer_id}: {}",
                    if *accepted { "accepted" } else { "failed" }
                )
            }
            PqEvent::DirectConnectionUpgraded { peer_id } => {
                write!(f, "direct connection upgraded with {peer_id}")
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

    #[test]
    fn event_display_nat_status_public() {
        let event = PqEvent::NatStatus { is_public: true };
        assert!(event.to_string().contains("public"));
    }

    #[test]
    fn event_display_nat_status_private() {
        let event = PqEvent::NatStatus { is_public: false };
        assert!(event.to_string().contains("private"));
    }

    #[test]
    fn event_display_relay_reservation_accepted() {
        let event = PqEvent::RelayReservation {
            relay_peer_id: "12D3Relay".to_string(),
            accepted: true,
        };
        let s = event.to_string();
        assert!(s.contains("12D3Relay"));
        assert!(s.contains("accepted"));
    }

    #[test]
    fn event_display_relay_reservation_failed() {
        let event = PqEvent::RelayReservation {
            relay_peer_id: "12D3Relay".to_string(),
            accepted: false,
        };
        assert!(event.to_string().contains("failed"));
    }

    #[test]
    fn event_display_dcutr_upgrade() {
        let event = PqEvent::DirectConnectionUpgraded {
            peer_id: "12D3Peer".to_string(),
        };
        let s = event.to_string();
        assert!(s.contains("12D3Peer"));
        assert!(s.contains("upgraded"));
    }

    #[test]
    fn event_display_bootstrap_ok() {
        let event = PqEvent::KademliaBootstrapResult {
            success: true,
            peers_found: 42,
        };
        let s = event.to_string();
        assert!(s.contains("ok"));
        assert!(s.contains("42"));
    }

    #[test]
    fn event_display_bootstrap_failed() {
        let event = PqEvent::KademliaBootstrapResult {
            success: false,
            peers_found: 0,
        };
        assert!(event.to_string().contains("failed"));
    }

    #[test]
    fn event_display_inbound_error() {
        let event = PqEvent::InboundConnectionError {
            error: "timeout".to_string(),
        };
        assert!(event.to_string().contains("timeout"));
    }

    #[test]
    fn event_display_outbound_error() {
        let event = PqEvent::OutboundConnectionError {
            peer_id: "12D3P".to_string(),
            error: "refused".to_string(),
        };
        let s = event.to_string();
        assert!(s.contains("12D3P"));
        assert!(s.contains("refused"));
    }

    #[test]
    fn event_display_unknown() {
        let event = PqEvent::UnknownEvent {
            description: "mystery".to_string(),
        };
        assert!(event.to_string().contains("mystery"));
    }
}
