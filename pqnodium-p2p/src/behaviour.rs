use libp2p::autonat;
use libp2p::dcutr;
use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig};
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{Behaviour as Kademlia, Config as KademliaConfig};
use libp2p::ping::Behaviour as Ping;
use libp2p::relay;
use libp2p::swarm::NetworkBehaviour;
use libp2p::PeerId;
use std::time::Duration;

/// Combined NetworkBehaviour for PQNodium.
///
/// Includes Kademlia DHT, Identify, Ping, Relay client/server, and Relay transport.
/// mDNS is intentionally excluded — it causes stale peer discovery on shared networks.
#[derive(NetworkBehaviour)]
pub struct PqBehaviour {
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
    pub ping: Ping,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: relay::Behaviour,
    pub autonat: autonat::Behaviour,
    pub dcutr: dcutr::Behaviour,
}

impl PqBehaviour {
    /// Create a new PqBehaviour with all NAT traversal protocols.
    pub fn new(
        peer_id: PeerId,
        id_keys: &Keypair,
        agent_version: String,
        kad_timeout: Duration,
        relay_client: relay::client::Behaviour,
        relay_server_enabled: bool,
        max_relay_circuits: usize,
    ) -> Self {
        let kad_config = {
            let mut cfg = KademliaConfig::default();
            cfg.set_query_timeout(kad_timeout);
            cfg
        };
        let kademlia = Kademlia::with_config(peer_id, MemoryStore::new(peer_id), kad_config);

        let identify = Identify::new(IdentifyConfig::new(agent_version, id_keys.public()));

        let ping = Ping::new(libp2p::ping::Config::new());

        let relay_server = if relay_server_enabled {
            relay::Behaviour::new(
                peer_id,
                relay::Config {
                    max_circuits: max_relay_circuits,
                    ..Default::default()
                },
            )
        } else {
            relay::Behaviour::new(
                peer_id,
                relay::Config {
                    max_reservations: 0,
                    max_circuits: 0,
                    ..Default::default()
                },
            )
        };

        let autonat = autonat::Behaviour::new(
            peer_id,
            autonat::Config {
                ..Default::default()
            },
        );

        let dcutr = dcutr::Behaviour::new(peer_id);

        Self {
            kademlia,
            identify,
            ping,
            relay_client,
            relay_server,
            autonat,
            dcutr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_behaviour(relay_server_enabled: bool) -> PqBehaviour {
        let kp = Keypair::generate_ed25519();
        let peer_id = kp.public().to_peer_id();

        // Create relay client transport pair for testing
        let (relay_transport, relay_client) = relay::client::new(peer_id);
        drop(relay_transport); // not needed in test

        PqBehaviour::new(
            peer_id,
            &kp,
            "pqnodium-test/0.0.1".to_string(),
            Duration::from_secs(30),
            relay_client,
            relay_server_enabled,
            16,
        )
    }

    #[test]
    fn behaviour_creation() {
        let _b = make_behaviour(false);
    }

    #[test]
    fn behaviour_with_relay_server() {
        let _b = make_behaviour(true);
    }

    #[test]
    fn behaviour_different_peers() {
        let _b1 = make_behaviour(false);
        let _b2 = make_behaviour(false);
    }
}
