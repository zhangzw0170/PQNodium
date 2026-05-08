use libp2p::Multiaddr;
use std::time::Duration;

/// Configuration for a PqNode.
#[derive(Debug, Clone)]
pub struct PqNodeConfig {
    pub listen_addr: Multiaddr,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub agent_version: String,
    pub kad_query_timeout: Duration,
    pub max_message_size: usize,
    /// Maximum number of concurrent incoming connections.
    pub max_incoming_connections: u32,
    /// Duration after which an idle connection is closed.
    /// Must be longer than the Ping interval (default 15s) to prevent premature disconnects.
    pub idle_connection_timeout: Duration,
}

impl Default for PqNodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/udp/0/quic-v1"
                .parse()
                .expect("default listen addr"),
            bootstrap_peers: vec![],
            agent_version: format!("pqnodium/{}", env!("CARGO_PKG_VERSION")),
            kad_query_timeout: Duration::from_secs(60),
            max_message_size: 4 * 1024 * 1024, // 4 MiB
            max_incoming_connections: 128,
            idle_connection_timeout: Duration::from_secs(24 * 60 * 60), // 24h; QUIC keepalive (5s) keeps transport alive
        }
    }
}

impl PqNodeConfig {
    pub fn new(listen_addr: Multiaddr) -> Self {
        Self {
            listen_addr,
            ..Default::default()
        }
    }

    pub fn with_bootstrap_peers(mut self, peers: Vec<Multiaddr>) -> Self {
        self.bootstrap_peers = peers;
        self
    }

    pub fn with_agent_version(mut self, version: impl Into<String>) -> Self {
        self.agent_version = version.into();
        self
    }

    pub fn with_kad_timeout(mut self, timeout: Duration) -> Self {
        self.kad_query_timeout = timeout;
        self
    }

    pub fn validate(&self) -> Result<(), crate::error::PqP2pError> {
        if self.max_message_size == 0 {
            return Err(crate::error::PqP2pError::MessageTooLarge(0));
        }
        if self.max_message_size > 64 * 1024 * 1024 {
            return Err(crate::error::PqP2pError::MessageTooLarge(
                self.max_message_size,
            ));
        }
        if self.max_incoming_connections == 0 {
            return Err(crate::error::PqP2pError::transport(
                "max_incoming_connections must be > 0",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = PqNodeConfig::default();
        assert!(config.bootstrap_peers.is_empty());
        assert!(config.agent_version.starts_with("pqnodium/"));
        assert_eq!(config.kad_query_timeout, Duration::from_secs(60));
        assert_eq!(config.max_message_size, 4 * 1024 * 1024);
        assert_eq!(config.idle_connection_timeout, Duration::from_secs(24 * 60 * 60));
    }

    #[test]
    fn custom_listen_addr() {
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let config = PqNodeConfig::new(addr.clone());
        assert_eq!(config.listen_addr, addr);
    }

    #[test]
    fn builder_pattern() {
        let peer_id = libp2p::PeerId::random();
        let peer_addr: Multiaddr = format!("/ip4/1.2.3.4/udp/4001/quic-v1/p2p/{peer_id}")
            .parse()
            .unwrap();
        let config = PqNodeConfig::default()
            .with_bootstrap_peers(vec![peer_addr.clone()])
            .with_agent_version("pqnodium-test/0.0.1")
            .with_kad_timeout(Duration::from_secs(30));
        assert_eq!(config.bootstrap_peers.len(), 1);
        assert_eq!(config.agent_version, "pqnodium-test/0.0.1");
        assert_eq!(config.kad_query_timeout, Duration::from_secs(30));
    }

    #[test]
    fn validate_ok() {
        let config = PqNodeConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_zero_size() {
        let config = PqNodeConfig {
            max_message_size: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_oversized() {
        let config = PqNodeConfig {
            max_message_size: 65 * 1024 * 1024,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_zero_max_connections() {
        let config = PqNodeConfig {
            max_incoming_connections: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
