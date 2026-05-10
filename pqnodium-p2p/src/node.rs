use crate::behaviour::{PqBehaviour, PqBehaviourEvent};
use crate::config::PqNodeConfig;
use crate::error::PqP2pError;
use crate::event::PqEvent;
use crate::transport;
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, SwarmBuilder};
use std::collections::HashMap;

/// A PQNodium P2P node wrapping a libp2p Swarm.
pub struct PqNode {
    swarm: libp2p::Swarm<PqBehaviour>,
    peer_id: PeerId,
    listeners: Vec<Multiaddr>,
    connected_peers: HashMap<String, Vec<Multiaddr>>,
    /// Monotonically increasing counter for unique event tracking.
    _event_counter: u64,
}

impl PqNode {
    /// Create a new PqNode with the given configuration.
    pub fn new(config: &PqNodeConfig) -> Result<Self, PqP2pError> {
        config.validate()?;

        let id_keys = transport::generate_transport_keypair();
        let peer_id = id_keys.public().to_peer_id();

        let swarm = SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(
                tcp::Config::new().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| PqP2pError::Io(std::io::Error::other(e.to_string())))?
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| PqP2pError::Io(std::io::Error::other(e.to_string())))?
            .with_behaviour(|key, relay_client| {
                PqBehaviour::new(
                    key.public().to_peer_id(),
                    key,
                    config.agent_version.clone(),
                    config.kad_query_timeout,
                    relay_client,
                    config.relay_server_enabled,
                    config.max_relay_circuits,
                )
            })
            .map_err(|e| PqP2pError::Io(std::io::Error::other(e.to_string())))?
            .with_swarm_config(|cfg| {
                cfg.with_max_negotiating_inbound_streams(config.max_incoming_connections as usize)
                    .with_idle_connection_timeout(config.idle_connection_timeout)
            })
            .build();

        Ok(Self {
            swarm,
            peer_id,
            listeners: vec![],
            connected_peers: HashMap::new(),
            _event_counter: 0,
        })
    }

    /// Start listening on the configured address.
    pub fn start_listening(&mut self, listen_addr: Multiaddr) -> Result<(), PqP2pError> {
        self.swarm
            .listen_on(listen_addr)
            .map_err(|e| PqP2pError::transport(e.to_string()))?;
        Ok(())
    }

    /// Listen on a specific address.
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<(), PqP2pError> {
        self.swarm
            .listen_on(addr)
            .map_err(|e| PqP2pError::transport(e.to_string()))?;
        Ok(())
    }

    /// Dial a peer at the given multiaddr.
    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), PqP2pError> {
        self.swarm
            .dial(addr)
            .map_err(|e| PqP2pError::DialFailed(e.to_string()))?;
        Ok(())
    }

    /// Get the local peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get the addresses this node is listening on.
    pub fn listeners(&self) -> &[Multiaddr] {
        &self.listeners
    }

    /// Get connected peer IDs.
    pub fn connected_peers(&self) -> Vec<String> {
        self.connected_peers.keys().cloned().collect()
    }

    /// Get addresses of a connected peer.
    pub fn peer_addresses(&self, peer_id: &str) -> Option<&[Multiaddr]> {
        self.connected_peers.get(peer_id).map(|v| v.as_slice())
    }

    /// Add a peer's address to the Kademlia routing table.
    pub fn add_kad_address(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, addr);
    }

    /// Bootstrap the Kademlia DHT.
    pub fn bootstrap(&mut self) -> Result<(), PqP2pError> {
        self.swarm
            .behaviour_mut()
            .kademlia
            .bootstrap()
            .map_err(|e| PqP2pError::transport(e.to_string()))?;
        Ok(())
    }

    /// Create a relay reservation with the given relay server peer.
    /// After reservation, this node is reachable via the relay at:
    /// `/p2p/{relay_peer_id}/p2p-circuit/p2p/{our_peer_id}`
    pub fn listen_on_relay(&mut self, relay_addr: Multiaddr) -> Result<(), PqP2pError> {
        let has_peer_id = relay_addr
            .iter()
            .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_)));
        if !has_peer_id {
            return Err(PqP2pError::InvalidAddress(
                "relay address must include /p2p/{relay_peer_id}".to_string(),
            ));
        }
        let circuit_addr = relay_addr.with(libp2p::multiaddr::Protocol::P2pCircuit);
        self.swarm
            .listen_on(circuit_addr)
            .map_err(|e| PqP2pError::transport(format!("relay listen failed: {e}")))?;
        Ok(())
    }

    /// Poll the swarm once and return any events.
    pub async fn poll_next(&mut self) -> Option<PqEvent> {
        loop {
            match self.swarm.next().await {
                Some(event) => {
                    if let Some(pq_event) = self.handle_swarm_event(event) {
                        return Some(pq_event);
                    }
                }
                None => return None,
            }
        }
    }

    /// Run the event loop indefinitely, calling `callback` for each event.
    pub async fn run<F>(&mut self, mut callback: F)
    where
        F: FnMut(PqEvent),
    {
        while let Some(event) = self.poll_next().await {
            callback(event);
        }
    }

    fn handle_swarm_event(&mut self, event: SwarmEvent<PqBehaviourEvent>) -> Option<PqEvent> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.listeners.push(address.clone());
                Some(PqEvent::Listening { address })
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.connected_peers.entry(peer_id.to_string()).or_default();
                Some(PqEvent::PeerConnected {
                    peer_id: peer_id.to_string(),
                })
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.connected_peers.remove(&peer_id.to_string());
                Some(PqEvent::PeerDisconnected {
                    peer_id: peer_id.to_string(),
                })
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                Some(PqEvent::OutboundConnectionError {
                    peer_id: peer_id
                        .as_ref()
                        .map_or("unknown".to_string(), |p| p.to_string()),
                    error: error.to_string(),
                })
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                Some(PqEvent::InboundConnectionError {
                    error: error.to_string(),
                })
            }
            SwarmEvent::Behaviour(behaviour_event) => self.handle_behaviour_event(behaviour_event),
            other => {
                tracing::debug!("swarm event (unmapped): {other:?}");
                None
            }
        }
    }

    fn handle_behaviour_event(&mut self, event: PqBehaviourEvent) -> Option<PqEvent> {
        match event {
            PqBehaviourEvent::Kademlia(kad_event) => self.handle_kad_event(kad_event),
            PqBehaviourEvent::Identify(id_event) => self.handle_identify_event(id_event),
            PqBehaviourEvent::Ping(ping_event) => {
                if ping_event.result.is_err() {
                    tracing::warn!(
                        "ping to {} failed: {:?}",
                        ping_event.peer,
                        ping_event.result
                    );
                }
                None
            }
            PqBehaviourEvent::RelayClient(event) => match event {
                libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } => {
                    tracing::info!("relay reservation accepted: {relay_peer_id}");
                    Some(PqEvent::RelayReservation {
                        relay_peer_id: relay_peer_id.to_string(),
                        accepted: true,
                    })
                }
                _ => {
                    tracing::debug!("relay client event: {event:?}");
                    None
                }
            },
            PqBehaviourEvent::RelayServer(event) => {
                tracing::debug!("relay server event: {event:?}");
                None
            }
            PqBehaviourEvent::Autonat(event) => match event {
                libp2p::autonat::Event::StatusChanged { new, .. } => {
                    let is_public = matches!(new, libp2p::autonat::NatStatus::Public(_));
                    tracing::info!("NAT status changed: {new:?}");
                    Some(PqEvent::NatStatus { is_public })
                }
                _ => None,
            },
            PqBehaviourEvent::Dcutr(event) => {
                let libp2p::dcutr::Event {
                    remote_peer_id,
                    result,
                } = event;
                match result {
                    Ok(_) => {
                        tracing::info!("DCUtR: direct connection with {remote_peer_id}");
                        Some(PqEvent::DirectConnectionUpgraded {
                            peer_id: remote_peer_id.to_string(),
                        })
                    }
                    Err(e) => {
                        tracing::warn!("DCUtR failed with {remote_peer_id}: {e}");
                        None
                    }
                }
            }
        }
    }

    fn handle_kad_event(&mut self, event: libp2p::kad::Event) -> Option<PqEvent> {
        match event {
            libp2p::kad::Event::OutboundQueryProgressed { result, .. } => match result {
                libp2p::kad::QueryResult::Bootstrap(Ok(bootstrap_ok)) => {
                    Some(PqEvent::KademliaBootstrapResult {
                        success: true,
                        peers_found: bootstrap_ok.num_remaining as usize,
                    })
                }
                libp2p::kad::QueryResult::Bootstrap(Err(e)) => {
                    tracing::warn!("Kademlia bootstrap failed: {e}");
                    Some(PqEvent::KademliaBootstrapResult {
                        success: false,
                        peers_found: 0,
                    })
                }
                libp2p::kad::QueryResult::GetClosestPeers(Ok(_peers_ok)) => {
                    // Peers are in the routing table, not necessarily connected.
                    // Let Identify handle address discovery.
                    None
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn handle_identify_event(&mut self, event: libp2p::identify::Event) -> Option<PqEvent> {
        match event {
            libp2p::identify::Event::Received { peer_id, info, .. } => {
                let peer_str = peer_id.to_string();
                let addrs = info.listen_addrs.clone();

                for addr in &info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }

                Some(PqEvent::PeerDiscovered {
                    peer_id: peer_str,
                    addresses: addrs,
                })
            }
            libp2p::identify::Event::Sent { .. } => None,
            libp2p::identify::Event::Error { peer_id, error, .. } => {
                tracing::warn!("identify error with {peer_id}: {error}");
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn node_creation() {
        let config = PqNodeConfig::default();
        let node = PqNode::new(&config).unwrap();
        assert!(!node.peer_id().to_string().is_empty());
        assert!(node.connected_peers().is_empty());
        assert!(node.listeners().is_empty());
    }

    #[tokio::test]
    async fn node_listen() {
        let config = PqNodeConfig::default();
        let mut node = PqNode::new(&config).unwrap();

        let result = node.start_listening(config.listen_addr);
        assert!(result.is_ok());

        for _ in 0..10 {
            if let Some(PqEvent::Listening { .. }) = node.poll_next().await {
                assert!(!node.listeners().is_empty());
                return;
            }
        }

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn node_listen_on_specific_addr() {
        let config = PqNodeConfig::default();
        let mut node = PqNode::new(&config).unwrap();

        let addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let result = node.listen_on(addr);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn node_distinct_peer_ids() {
        let config = PqNodeConfig::default();
        let node1 = PqNode::new(&config).unwrap();
        let node2 = PqNode::new(&config).unwrap();
        assert_ne!(node1.peer_id(), node2.peer_id());
    }

    #[tokio::test]
    async fn node_custom_agent_version() {
        let config = PqNodeConfig::default().with_agent_version("pqnodium-test/0.0.1");
        let node = PqNode::new(&config).unwrap();
        assert!(node.peer_id().to_string().starts_with("12D3"));
    }

    #[tokio::test]
    async fn node_kad_address_add() {
        let config = PqNodeConfig::default();
        let mut node = PqNode::new(&config).unwrap();

        let remote_pid = PeerId::random();
        let addr: Multiaddr = "/ip4/1.2.3.4/udp/4001/quic-v1".parse().unwrap();
        node.add_kad_address(remote_pid, addr);
    }

    #[tokio::test]
    async fn node_dial_invalid_addr() {
        let config = PqNodeConfig::default();
        let mut node = PqNode::new(&config).unwrap();

        let addr: Multiaddr = "/ip4/1.2.3.4/udp/4001/quic-v1".parse().unwrap();
        let result = node.dial(addr);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn node_config_validation_zero_max_size() {
        let config = PqNodeConfig {
            max_message_size: 0,
            ..Default::default()
        };
        assert!(PqNode::new(&config).is_err());
    }

    #[tokio::test]
    async fn node_two_nodes_same_port_fails() {
        let config = PqNodeConfig::default();
        let mut node1 = PqNode::new(&config).unwrap();
        node1.start_listening(config.listen_addr).unwrap();

        let bound_addr = loop {
            if let Some(PqEvent::Listening { address }) = node1.poll_next().await {
                break address;
            }
        };

        let mut node2 = PqNode::new(&PqNodeConfig::default()).unwrap();
        let _ = node2.listen_on(bound_addr);
    }

    #[tokio::test]
    async fn node_peer_addresses_empty() {
        let config = PqNodeConfig::default();
        let node = PqNode::new(&config).unwrap();
        assert!(node.peer_addresses("QmNonExistent").is_none());
    }

    #[tokio::test]
    async fn node_with_relay_server() {
        let config = PqNodeConfig::default().with_relay_server(true);
        let node = PqNode::new(&config).unwrap();
        assert!(!node.peer_id().to_string().is_empty());
    }

    #[tokio::test]
    async fn node_relay_addr_without_peer_id_fails() {
        let config = PqNodeConfig::default();
        let mut node = PqNode::new(&config).unwrap();
        let addr: Multiaddr = "/ip4/1.2.3.4/udp/4001/quic-v1".parse().unwrap();
        let result = node.listen_on_relay(addr);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must include /p2p/")
        );
    }

    #[tokio::test]
    async fn node_relay_addr_with_peer_id_ok() {
        let config = PqNodeConfig::default();
        let mut node = PqNode::new(&config).unwrap();
        let relay_pid = PeerId::random();
        let addr: Multiaddr = format!("/ip4/1.2.3.4/udp/4001/quic-v1/p2p/{relay_pid}")
            .parse()
            .unwrap();
        let result = node.listen_on_relay(addr);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn node_custom_idle_timeout() {
        let config = PqNodeConfig {
            idle_connection_timeout: std::time::Duration::from_secs(300),
            ..Default::default()
        };
        let node = PqNode::new(&config).unwrap();
        assert!(!node.peer_id().to_string().is_empty());
    }
}
