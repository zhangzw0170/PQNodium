use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig};
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{Behaviour as Kademlia, Config as KademliaConfig};
use libp2p::mdns::tokio::Behaviour as Mdns;
use libp2p::ping::Behaviour as Ping;
use libp2p::swarm::NetworkBehaviour;
use libp2p::PeerId;
use std::time::Duration;

/// Combined NetworkBehaviour for PQNodium.
#[derive(NetworkBehaviour)]
pub struct PqBehaviour {
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
    pub mdns: Mdns,
    pub ping: Ping,
}

impl PqBehaviour {
    pub fn new(peer_id: PeerId, agent_version: String, kad_timeout: Duration) -> Self {
        let kad_config = {
            let mut cfg = KademliaConfig::default();
            cfg.set_query_timeout(kad_timeout);
            cfg
        };
        let kademlia = Kademlia::with_config(peer_id, MemoryStore::new(peer_id), kad_config);

        let identify = Identify::new(IdentifyConfig::new(agent_version, {
            let kp = libp2p::identity::Keypair::generate_ed25519();
            kp.public()
        }));

        let mdns = Mdns::new(libp2p::mdns::Config::default(), peer_id).expect("mDNS available");

        let ping = Ping::new(libp2p::ping::Config::new());

        Self {
            kademlia,
            identify,
            mdns,
            ping,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaviour_creation() {
        let peer_id = PeerId::random();
        let behaviour = PqBehaviour::new(
            peer_id,
            "pqnodium-test/0.0.1".to_string(),
            Duration::from_secs(30),
        );
        // Just verify it was created without panic
        let _ = behaviour;
    }

    #[test]
    fn behaviour_different_peers() {
        let pid1 = PeerId::random();
        let pid2 = PeerId::random();
        let _b1 = PqBehaviour::new(pid1, "test".to_string(), Duration::from_secs(30));
        let _b2 = PqBehaviour::new(pid2, "test".to_string(), Duration::from_secs(30));
    }

    #[test]
    fn behaviour_custom_timeout() {
        let peer_id = PeerId::random();
        let behaviour = PqBehaviour::new(peer_id, "test".to_string(), Duration::from_secs(120));
        let _ = behaviour;
    }
}
