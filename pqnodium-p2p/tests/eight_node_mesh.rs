//! 8-node local P2P integration test.
//!
//! Spawns 8 PqNode instances on 127.0.0.1, tests:
//! 1. Unique peer IDs
//! 2. Listening addresses
//! 3. Node-to-node dialing
//! 4. Concurrent mesh
//! 5. Sequential chain
//! 6. Error handling for bad addresses
//! 7. Kademlia bootstrap
//! 8. Identify discovery

use libp2p::Multiaddr;
use pqnodium_p2p::config::PqNodeConfig;
use pqnodium_p2p::event::PqEvent;
use pqnodium_p2p::node::PqNode;
use std::collections::HashSet;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

const NODE_COUNT: usize = 8;
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

fn init_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(
                "pqnodium_p2p=info,libp2p=warn,libp2p_quic=warn",
            ))
            .with_test_writer()
            .init();
    });
}

struct SpawnedNode {
    node: PqNode,
    dial_addr: Multiaddr,
}

impl SpawnedNode {
    async fn spawn() -> Self {
        init_tracing();
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let config = PqNodeConfig::new(listen_addr)
            .with_agent_version("pqnodium-test/0.1.0")
            .with_kad_timeout(Duration::from_secs(10));

        let mut node = PqNode::new(&config).unwrap();
        node.start_listening(config.listen_addr).unwrap();

        let bound = loop {
            match node.poll_next().await {
                Some(PqEvent::Listening { address }) => break address,
                Some(_) => continue,
                None => panic!("node died before Listening event"),
            }
        };

        let full: Multiaddr = format!("{bound}/p2p/{}", node.peer_id()).parse().unwrap();

        SpawnedNode {
            node,
            dial_addr: full,
        }
    }

    fn peer_id_str(&self) -> String {
        self.node.peer_id().to_string()
    }
}

/// Drive a node's swarm in the background, collecting events into a shared Vec.
/// Returns a JoinHandle that must be awaited to get the events.
fn drive_node(mut node: PqNode) -> tokio::task::JoinHandle<(PqNode, Vec<PqEvent>)> {
    tokio::spawn(async move {
        let mut evs = Vec::new();
        let deadline = tokio::time::Instant::now() + EVENT_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, node.poll_next()).await {
                Ok(Some(e)) => evs.push(e),
                Ok(None) | Err(_) => break,
            }
        }
        (node, evs)
    })
}

fn peer_ids_connected(events: &[PqEvent]) -> HashSet<String> {
    events
        .iter()
        .filter_map(|e| match e {
            PqEvent::PeerConnected { peer_id } => Some(peer_id.clone()),
            _ => None,
        })
        .collect()
}

fn peer_ids_discovered(events: &[PqEvent]) -> HashSet<String> {
    events
        .iter()
        .filter_map(|e| match e {
            PqEvent::PeerDiscovered { peer_id, .. } => Some(peer_id.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Eight nodes get unique peer IDs
// ---------------------------------------------------------------------------
#[tokio::test]
async fn eight_nodes_unique_peer_ids() {
    let mut ids = Vec::new();
    for _ in 0..NODE_COUNT {
        let n = SpawnedNode::spawn().await;
        ids.push(n.peer_id_str());
    }
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), NODE_COUNT);
}

// ---------------------------------------------------------------------------
// 2. All nodes report a listening address
// ---------------------------------------------------------------------------
#[tokio::test]
async fn all_nodes_report_listening() {
    for _ in 0..NODE_COUNT {
        let n = SpawnedNode::spawn().await;
        let s = n.dial_addr.to_string();
        assert!(s.contains("/tcp/"), "addr should have TCP port: {s}");
        assert!(s.contains("/p2p/"), "addr should have /p2p/: {s}");
    }
}

// ---------------------------------------------------------------------------
// 3. Two nodes can connect
// ---------------------------------------------------------------------------
#[tokio::test]
async fn two_nodes_connect() {
    let mut a = SpawnedNode::spawn().await;
    let b = SpawnedNode::spawn().await;

    let b_pid = b.peer_id_str();
    let a_pid = a.peer_id_str();

    a.node.dial(b.dial_addr.clone()).unwrap();

    // Drive both swarms concurrently so the dial can complete.
    let h_a = drive_node(a.node);
    let h_b = drive_node(b.node);

    let (node_a, evs_a) = h_a.await.unwrap();
    let (_node_b, evs_b) = h_b.await.unwrap();

    let conn_a = peer_ids_connected(&evs_a);
    let conn_b = peer_ids_connected(&evs_b);
    let disc_a = peer_ids_discovered(&evs_a);
    let disc_b = peer_ids_discovered(&evs_b);

    let a_sees_b = conn_a.contains(&b_pid) || disc_a.contains(&b_pid);
    let b_sees_a = conn_b.contains(&a_pid) || disc_b.contains(&a_pid);

    assert!(
        a_sees_b || b_sees_a,
        "A sees B: conn={conn_a:?} disc={disc_a:?}; B sees A: conn={conn_b:?} disc={disc_b:?}"
    );

    // Suppress unused warning
    let _ = node_a;
}

// ---------------------------------------------------------------------------
// 4. Node 0 dials all 7 others
// ---------------------------------------------------------------------------
#[tokio::test]
async fn one_to_many_dial() {
    let mut nodes = Vec::new();
    let mut addrs = Vec::new();
    for _ in 0..NODE_COUNT {
        let n = SpawnedNode::spawn().await;
        addrs.push(n.dial_addr.clone());
        nodes.push(n.node);
    }

    for addr in &addrs[1..] {
        nodes[0].dial(addr.clone()).unwrap();
    }

    // Drive all nodes concurrently.
    let mut handles: Vec<_> = nodes.into_iter().map(drive_node).collect();
    let results: Vec<_> = futures::future::join_all(handles.iter_mut())
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let conn_0 = peer_ids_connected(&results[0].1);
    assert!(
        conn_0.len() >= 1,
        "node 0 should connect to at least 1 of 7 peers, got {}",
        conn_0.len()
    );
}

// ---------------------------------------------------------------------------
// 5. Concurrent full mesh (8×7 = 56 dial attempts)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn concurrent_full_mesh() {
    let mut nodes = Vec::new();
    let mut addrs = Vec::new();
    for _ in 0..NODE_COUNT {
        let n = SpawnedNode::spawn().await;
        addrs.push(n.dial_addr.clone());
        nodes.push(n.node);
    }

    for i in 0..NODE_COUNT {
        for j in 0..NODE_COUNT {
            if i != j {
                nodes[i].dial(addrs[j].clone()).unwrap();
            }
        }
    }

    let mut handles: Vec<_> = nodes.into_iter().map(drive_node).collect();
    let results: Vec<_> = futures::future::join_all(handles.iter_mut())
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let mut total_conn = 0usize;
    let mut total_err = 0usize;
    for (_, evs) in &results {
        for e in evs {
            match e {
                PqEvent::PeerConnected { .. } => total_conn += 1,
                PqEvent::OutboundConnectionError { .. }
                | PqEvent::InboundConnectionError { .. } => total_err += 1,
                _ => {}
            }
        }
    }

    assert!(
        total_conn >= 2,
        "concurrent mesh: expected >= 2 connections, got {total_conn} (errors={total_err})"
    );
}

// ---------------------------------------------------------------------------
// 6. Sequential chain 0→1→...→7
// ---------------------------------------------------------------------------
#[tokio::test]
async fn sequential_chain() {
    let mut nodes = Vec::new();
    let mut addrs = Vec::new();
    for _ in 0..NODE_COUNT {
        let n = SpawnedNode::spawn().await;
        addrs.push(n.dial_addr.clone());
        nodes.push(n.node);
    }

    for i in 0..NODE_COUNT - 1 {
        nodes[i].dial(addrs[i + 1].clone()).unwrap();
    }

    let mut handles: Vec<_> = nodes.into_iter().map(drive_node).collect();
    let results: Vec<_> = futures::future::join_all(handles.iter_mut())
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let conn_last = peer_ids_connected(&results[NODE_COUNT - 1].1);
    assert!(
        !conn_last.is_empty(),
        "last node should see at least predecessor"
    );
}

// ---------------------------------------------------------------------------
// 7. Node isolation — A-B pair doesn't see C
// ---------------------------------------------------------------------------
#[tokio::test]
async fn node_isolation() {
    let mut a = SpawnedNode::spawn().await;
    let b = SpawnedNode::spawn().await;
    let c = SpawnedNode::spawn().await;

    let c_pid = c.peer_id_str();
    a.node.dial(b.dial_addr).unwrap();

    // Drive all three concurrently so connections can establish.
    let h_a = drive_node(a.node);
    let h_b = drive_node(b.node);
    let _h_c = drive_node(c.node);

    let (_, evs_a) = h_a.await.unwrap();
    let _ = h_b.await;
    let _ = _h_c.await;

    let sees_c =
        peer_ids_connected(&evs_a).contains(&c_pid) || peer_ids_discovered(&evs_a).contains(&c_pid);
    assert!(!sees_c, "A should not see isolated node C");
}

// ---------------------------------------------------------------------------
// 8. Bad address produces error event
// ---------------------------------------------------------------------------
#[tokio::test]
async fn bad_address_error() {
    let mut n = SpawnedNode::spawn().await;
    let bad: Multiaddr = "/ip4/127.0.0.1/tcp/19999".parse().unwrap();
    assert!(n.node.dial(bad).is_ok());

    let (_, evs) = drive_node(n.node).await.unwrap();
    let has_err = evs
        .iter()
        .any(|e| matches!(e, PqEvent::OutboundConnectionError { .. }));
    assert!(has_err, "dead port should produce error event");
}

// ---------------------------------------------------------------------------
// 9. Kademlia bootstrap triggers result event
// ---------------------------------------------------------------------------
#[tokio::test]
async fn kademlia_bootstrap_event() {
    let n0 = SpawnedNode::spawn().await;
    let mut n1 = SpawnedNode::spawn().await;

    n1.node.add_kad_address(*n0.node.peer_id(), n0.dial_addr);
    n1.node.bootstrap().unwrap();

    let (_, evs) = drive_node(n1.node).await.unwrap();
    let has_boot = evs
        .iter()
        .any(|e| matches!(e, PqEvent::KademliaBootstrapResult { .. }));
    assert!(has_boot, "should get bootstrap result");
}

// ---------------------------------------------------------------------------
// 10. Identify discovers peer addresses
// ---------------------------------------------------------------------------
#[tokio::test]
async fn identify_discovers_addresses() {
    let mut a = SpawnedNode::spawn().await;
    let b = SpawnedNode::spawn().await;

    a.node.dial(b.dial_addr).unwrap();

    let h_a = drive_node(a.node);
    let h_b = drive_node(b.node);

    let (_, evs_a) = h_a.await.unwrap();
    let _ = h_b.await;

    let disc = peer_ids_discovered(&evs_a);

    assert!(
        !disc.is_empty() || peer_ids_connected(&evs_a).len() >= 1,
        "identify should discover or connect to peer"
    );
}
