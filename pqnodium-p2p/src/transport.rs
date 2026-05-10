use libp2p::identity::Keypair;

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
}
