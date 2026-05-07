use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig};
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{Behaviour as Kademlia, Config as KademliaConfig};
use libp2p::ping::Behaviour as Ping;
use libp2p::swarm::NetworkBehaviour;
use libp2p::PeerId;
use std::time::Duration;

/// Combined NetworkBehaviour for PQNodium.
///
/// Note: mDNS is intentionally excluded — it causes stale peer discovery
/// on shared networks and conflicts with Kademlia-based DHT discovery.
#[derive(NetworkBehaviour)]
pub struct PqBehaviour {
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
    pub ping: Ping,
}

impl PqBehaviour {
    pub fn new(
        peer_id: PeerId,
        id_keys: &Keypair,
        agent_version: String,
        kad_timeout: Duration,
    ) -> Self {
        let kad_config = {
            let mut cfg = KademliaConfig::default();
            cfg.set_query_timeout(kad_timeout);
            cfg
        };
        let kademlia = Kademlia::with_config(peer_id, MemoryStore::new(peer_id), kad_config);

        let identify = Identify::new(IdentifyConfig::new(agent_version, id_keys.public()));

        let ping = Ping::new(libp2p::ping::Config::new());

        Self {
            kademlia,
            identify,
            ping,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaviour_creation() {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = kp.public().to_peer_id();
        let behaviour = PqBehaviour::new(
            peer_id,
            &kp,
            "pqnodium-test/0.0.1".to_string(),
            Duration::from_secs(30),
        );
        let _ = behaviour;
    }

    #[test]
    fn behaviour_different_peers() {
        let kp1 = libp2p::identity::Keypair::generate_ed25519();
        let kp2 = libp2p::identity::Keypair::generate_ed25519();
        let pid1 = kp1.public().to_peer_id();
        let pid2 = kp2.public().to_peer_id();
        let _b1 = PqBehaviour::new(pid1, &kp1, "test".to_string(), Duration::from_secs(30));
        let _b2 = PqBehaviour::new(pid2, &kp2, "test".to_string(), Duration::from_secs(30));
    }

    #[test]
    fn behaviour_custom_timeout() {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = kp.public().to_peer_id();
        let behaviour =
            PqBehaviour::new(peer_id, &kp, "test".to_string(), Duration::from_secs(120));
        let _ = behaviour;
    }
}
