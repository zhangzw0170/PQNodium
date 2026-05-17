//! 8-node group encryption end-to-end integration test.
//!
//! Spawns 8 GroupNode instances on 127.0.0.1 with real TCP connections,
//! testing group creation, encrypted broadcast, member changes, rekey,
//! dissolve, and non-group passthrough.

use libp2p::Multiaddr;
use pqnodium_core::crypto::backend::pqc::ed25519::Ed25519Signer;
use pqnodium_core::crypto::backend::pqc::ml_dsa::MlDsa65Signer;
use pqnodium_core::crypto::backend::pqc::ml_kem::MlKem768Kem;
use pqnodium_core::crypto::backend::pqc::x25519::X25519Kem;
use pqnodium_core::crypto::hybrid::hybrid_kem::{
    HybridKem, HybridKemPublicKey, HybridKemSecretKey,
};
use pqnodium_core::crypto::traits::kem::KeyEncapsulation;
use pqnodium_core::crypto::traits::sign::Signer;
use pqnodium_core::identity::PeerId;
use pqnodium_p2p::config::PqNodeConfig;
use pqnodium_p2p::event::PqEvent;
use pqnodium_p2p::group::{GroupEvent, GroupNode};
use pqnodium_p2p::node::PqNode;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

type PqHybridKem = HybridKem<X25519Kem, MlKem768Kem>;

const EVENT_TIMEOUT: Duration = Duration::from_secs(15);

// ─── Helpers ─────────────────────────────────────────────────────────────

fn init_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(
                "pqnodium_p2p=debug,libp2p=warn,libp2p_quic=warn",
            ))
            .with_test_writer()
            .init();
    });
}

struct PeerIdentity {
    peer_id: PeerId,
    hybrid_pk: HybridKemPublicKey<X25519Kem, MlKem768Kem>,
    hybrid_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>,
}

impl PeerIdentity {
    fn generate() -> Self {
        let (ed_pk, _) = Ed25519Signer::keygen(&mut rand::rngs::OsRng);
        let (ml_pk, _) = MlDsa65Signer::keygen(&mut rand::rngs::OsRng);
        let peer_id = PeerId::from_hybrid_pk(&ed_pk, &ml_pk);
        let (hybrid_pk, hybrid_sk) = PqHybridKem::keygen_os();
        Self {
            peer_id,
            hybrid_pk,
            hybrid_sk,
        }
    }
}

struct TestNode {
    identity: PeerIdentity,
    node: GroupNode,
    dial_addr: Multiaddr,
}

impl TestNode {
    async fn spawn() -> Self {
        init_tracing();
        let identity = PeerIdentity::generate();

        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let config = PqNodeConfig::new(listen_addr)
            .with_agent_version("pqnodium-group-test/0.1.0")
            .with_kad_timeout(Duration::from_secs(10));

        let mut p2p = PqNode::new(&config).unwrap();
        p2p.start_listening(config.listen_addr).unwrap();
        p2p.subscribe_default().unwrap();

        loop {
            match p2p.poll_next().await {
                Some(PqEvent::Listening { address }) => {
                    let full: Multiaddr =
                        format!("{address}/p2p/{}", p2p.peer_id()).parse().unwrap();
                    let sender_id = p2p.peer_id().to_string();
                    let node = GroupNode::new(
                        p2p,
                        identity.peer_id.clone(),
                        identity.hybrid_sk.clone(),
                        sender_id,
                    );
                    return TestNode {
                        identity,
                        node,
                        dial_addr: full,
                    };
                }
                Some(_) => continue,
                None => panic!("PqNode died before Listening event"),
            }
        }
    }

    fn peer_id(&self) -> &PeerId {
        &self.identity.peer_id
    }
}

async fn spawn_network(n: usize) -> Vec<TestNode> {
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n {
        nodes.push(TestNode::spawn().await);
    }

    let all_pks: Vec<(PeerId, HybridKemPublicKey<X25519Kem, MlKem768Kem>)> = nodes
        .iter()
        .map(|n| (n.identity.peer_id.clone(), n.identity.hybrid_pk.clone()))
        .collect();

    for node in &mut nodes {
        for (pid, pk) in &all_pks {
            node.node.register_member_pk(pid.clone(), pk.clone());
        }
    }

    nodes
}

/// Dial all-to-all (star topology) and drive mesh formation.
async fn connect_all(nodes: &mut [TestNode]) {
    if nodes.len() < 2 {
        return;
    }

    let addrs: Vec<Multiaddr> = nodes.iter().map(|n| n.dial_addr.clone()).collect();

    for addr in &addrs[1..] {
        nodes[0].node.p2p_mut().dial(addr.clone()).unwrap();
    }

    let (n0, rest) = nodes.split_first_mut().unwrap();
    let (n1, _) = rest.split_first_mut().unwrap();

    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            tokio::select! {
                ev = n0.node.poll_next() => {
                    if let Some(GroupEvent::P2P(PqEvent::PeerConnected { .. })) = ev {
                        break;
                    }
                }
                ev = n1.node.poll_next() => {
                    if let Some(GroupEvent::P2P(PqEvent::PeerConnected { .. })) = ev {
                        break;
                    }
                }
            }
        }
    })
    .await
    .expect("connection timeout");

    let (_n0, rest) = nodes.split_first_mut().unwrap();
    for node in rest.iter_mut() {
        node.node.p2p_mut().dial(addrs[0].clone()).unwrap();
    }

    // Drive all nodes concurrently to form Gossipsub mesh
    drive_all(nodes, Duration::from_secs(5)).await;
}

/// Drive all nodes concurrently using select_all.
async fn drive_all(nodes: &mut [TestNode], duration: Duration) {
    use futures::future::select_all;
    use futures::FutureExt;

    let deadline = tokio::time::Instant::now() + duration;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let futures: Vec<_> = nodes
            .iter_mut()
            .map(|node| node.node.poll_next().boxed_local())
            .collect();

        match tokio::time::timeout(remaining, select_all(futures)).await {
            Ok((Some(_), _rest, _idx)) => {}
            Ok((None, _rest, _idx)) => break,
            Err(_) => break,
        }
    }
}

async fn wait_for_event<F>(node: &mut TestNode, timeout: Duration, predicate: F) -> bool
where
    F: Fn(&GroupEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, node.node.poll_next()).await {
            Ok(Some(ev)) if predicate(&ev) => return true,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return false,
        }
    }
    false
}

// ─── Test 1: Two nodes create group and chat ─────────────────────────────

#[tokio::test]
async fn two_nodes_create_and_chat() {
    let mut nodes = spawn_network(2).await;
    connect_all(&mut nodes).await;

    let members: Vec<PeerId> = nodes.iter().map(|n| n.peer_id().clone()).collect();
    let (gid, _) = nodes[0].node.propose_create(members).unwrap();

    let found = wait_for_event(&mut nodes[1], EVENT_TIMEOUT, |ev| {
        matches!(ev, GroupEvent::GroupControlApplied { .. })
    })
    .await;
    assert!(found, "B should receive GroupControlApplied");

    nodes[0]
        .node
        .send_group_message(&gid, b"hello from A")
        .unwrap();

    let found = wait_for_event(
        &mut nodes[1],
        EVENT_TIMEOUT,
        |ev| matches!(ev, GroupEvent::GroupMessage { ref plaintext, .. } if plaintext == b"hello from A"),
    )
    .await;
    assert!(found, "B should receive decrypted group message");
}

// ─── Test 2: Eight nodes broadcast ───────────────────────────────────────

#[tokio::test]
async fn eight_nodes_broadcast() {
    let mut nodes = spawn_network(8).await;
    connect_all(&mut nodes).await;

    let members: Vec<PeerId> = nodes.iter().map(|n| n.peer_id().clone()).collect();
    let (gid, _) = nodes[0].node.propose_create(members).unwrap();

    // Poll each receiver — node 0's poll_next drives its swarm to send,
    // and each receiver's poll_next drives its swarm to receive.
    for (i, node) in nodes[1..].iter_mut().enumerate() {
        let found = wait_for_event(node, EVENT_TIMEOUT, |ev| {
            matches!(ev, GroupEvent::GroupControlApplied { .. })
        })
        .await;
        assert!(found, "node {i} should receive GroupControlApplied");
    }

    nodes[0]
        .node
        .send_group_message(&gid, b"broadcast to all")
        .unwrap();

    for (i, node) in nodes[1..].iter_mut().enumerate() {
        let found = wait_for_event(
            node,
            EVENT_TIMEOUT,
            |ev| matches!(ev, GroupEvent::GroupMessage { ref plaintext, .. } if plaintext == b"broadcast to all"),
        )
        .await;
        assert!(found, "node {i} should decrypt broadcast");
    }
}

// ─── Test 3: Add member during session ───────────────────────────────────

#[tokio::test]
async fn add_member_during_session() {
    let mut nodes = spawn_network(3).await;
    connect_all(&mut nodes).await;

    // A creates group with [A, B] only
    let ab_members: Vec<PeerId> = nodes[0..2].iter().map(|n| n.peer_id().clone()).collect();
    let (gid, _) = nodes[0].node.propose_create(ab_members).unwrap();

    let found = wait_for_event(&mut nodes[1], EVENT_TIMEOUT, |ev| {
        matches!(ev, GroupEvent::GroupControlApplied { .. })
    })
    .await;
    assert!(found, "B should receive GroupControlApplied");

    nodes[0]
        .node
        .send_group_message(&gid, b"before add")
        .unwrap();

    let found_b = wait_for_event(
        &mut nodes[1],
        EVENT_TIMEOUT,
        |ev| matches!(ev, GroupEvent::GroupMessage { ref plaintext, .. } if plaintext == b"before add"),
    )
    .await;
    assert!(found_b, "B should decrypt first message");

    // Keep mesh warm before adding C
    drive_all(&mut nodes, Duration::from_secs(1)).await;

    // A adds C
    let c_peer_id = nodes[2].peer_id().clone();
    nodes[0].node.propose_add(&gid, &c_peer_id).unwrap();

    let found_c = wait_for_event(&mut nodes[2], EVENT_TIMEOUT, |ev| {
        matches!(ev, GroupEvent::GroupControlApplied { .. })
    })
    .await;
    assert!(found_c, "C should receive GroupControlApplied after add");

    nodes[0]
        .node
        .send_group_message(&gid, b"after add")
        .unwrap();

    let found_c2 = wait_for_event(
        &mut nodes[2],
        EVENT_TIMEOUT,
        |ev| matches!(ev, GroupEvent::GroupMessage { ref plaintext, .. } if plaintext == b"after add"),
    )
    .await;
    assert!(found_c2, "C should decrypt message after being added");
}

// ─── Test 4: Remove member ──────────────────────────────────────────────

#[tokio::test]
async fn remove_member() {
    let mut nodes = spawn_network(3).await;
    connect_all(&mut nodes).await;

    let members: Vec<PeerId> = nodes.iter().map(|n| n.peer_id().clone()).collect();
    let (gid, _) = nodes[0].node.propose_create(members).unwrap();

    for node in &mut nodes[1..] {
        let found = wait_for_event(node, EVENT_TIMEOUT, |ev| {
            matches!(ev, GroupEvent::GroupControlApplied { .. })
        })
        .await;
        assert!(found, "node should receive GroupControlApplied");
    }

    // Keep mesh warm before removing B
    drive_all(&mut nodes, Duration::from_secs(1)).await;

    let b_peer_id = nodes[1].peer_id().clone();
    nodes[0].node.propose_remove(&gid, &b_peer_id).unwrap();

    // C should receive the remove control and update its member list
    let found_c_ctrl = wait_for_event(&mut nodes[2], EVENT_TIMEOUT, |ev| {
        matches!(ev, GroupEvent::GroupControlApplied { .. })
    })
    .await;
    assert!(found_c_ctrl, "C should receive remove control update");

    nodes[0]
        .node
        .send_group_message(&gid, b"after remove")
        .unwrap();

    let found_c = wait_for_event(
        &mut nodes[2],
        EVENT_TIMEOUT,
        |ev| matches!(ev, GroupEvent::GroupMessage { ref plaintext, .. } if plaintext == b"after remove"),
    )
    .await;
    assert!(found_c, "C should decrypt after B is removed");
}

// ─── Test 5: Rekey continuity ────────────────────────────────────────────

#[tokio::test]
async fn rekey_continuity() {
    let mut nodes = spawn_network(3).await;
    connect_all(&mut nodes).await;

    let members: Vec<PeerId> = nodes.iter().map(|n| n.peer_id().clone()).collect();
    let (gid, _) = nodes[0].node.propose_create(members).unwrap();

    for node in &mut nodes[1..] {
        let found = wait_for_event(node, EVENT_TIMEOUT, |ev| {
            matches!(ev, GroupEvent::GroupControlApplied { .. })
        })
        .await;
        assert!(found, "node should receive initial control");
    }

    nodes[0].node.propose_rekey(&gid).unwrap();

    for node in &mut nodes[1..] {
        let found = wait_for_event(node, EVENT_TIMEOUT, |ev| {
            matches!(ev, GroupEvent::GroupControlApplied { .. })
        })
        .await;
        assert!(found, "node should receive rekey control");
    }

    nodes[0]
        .node
        .send_group_message(&gid, b"after rekey")
        .unwrap();

    for (i, node) in nodes[1..].iter_mut().enumerate() {
        let found = wait_for_event(
            node,
            EVENT_TIMEOUT,
            |ev| matches!(ev, GroupEvent::GroupMessage { ref plaintext, .. } if plaintext == b"after rekey"),
        )
        .await;
        assert!(found, "node {i} should decrypt after rekey");
    }
}

// ─── Test 6: Dissolve group ──────────────────────────────────────────────

#[tokio::test]
async fn dissolve_group() {
    let mut nodes = spawn_network(3).await;
    connect_all(&mut nodes).await;

    let members: Vec<PeerId> = nodes.iter().map(|n| n.peer_id().clone()).collect();
    let (gid, _) = nodes[0].node.propose_create(members).unwrap();

    for node in &mut nodes[1..] {
        let found = wait_for_event(node, EVENT_TIMEOUT, |ev| {
            matches!(ev, GroupEvent::GroupControlApplied { .. })
        })
        .await;
        assert!(found, "node should receive initial control");
    }

    nodes[0].node.propose_dissolve(&gid).unwrap();

    for (i, node) in nodes[1..].iter_mut().enumerate() {
        let found = wait_for_event(node, EVENT_TIMEOUT, |ev| {
            matches!(ev, GroupEvent::GroupDissolved { .. })
        })
        .await;
        assert!(found, "node {i} should receive GroupDissolved");
    }
}

// ─── Test 7: Non-group passthrough ───────────────────────────────────────

#[tokio::test]
async fn non_group_passthrough() {
    let mut nodes = spawn_network(2).await;
    connect_all(&mut nodes).await;

    let envelope = pqnodium_core::envelope::Envelope::new(
        nodes[0].node.p2p().peer_id().to_string(),
        b"plain p2p message".to_vec(),
    );
    nodes[0].node.p2p_mut().publish(&envelope.encode()).unwrap();

    let found = wait_for_event(&mut nodes[1], EVENT_TIMEOUT, |ev| {
        matches!(ev, GroupEvent::P2P(PqEvent::MessageReceived { .. }))
    })
    .await;
    assert!(found, "B should receive passthrough P2P message");
}

// ─── Test 8: Eight nodes full lifecycle (create + broadcast + rekey + dissolve) ─

#[tokio::test]
async fn eight_nodes_full_lifecycle() {
    let mut nodes = spawn_network(8).await;
    connect_all(&mut nodes).await;

    let members: Vec<PeerId> = nodes.iter().map(|n| n.peer_id().clone()).collect();
    let (gid, _) = nodes[0].node.propose_create(members).unwrap();

    for node in &mut nodes[1..] {
        let found = wait_for_event(node, EVENT_TIMEOUT, |ev| {
            matches!(ev, GroupEvent::GroupControlApplied { epoch: 0, .. })
        })
        .await;
        assert!(found, "node should receive create control (epoch 0)");
    }

    nodes[0]
        .node
        .send_group_message(&gid, b"lifecycle msg 1")
        .unwrap();

    for (i, node) in nodes[1..].iter_mut().enumerate() {
        let found = wait_for_event(
            node,
            EVENT_TIMEOUT,
            |ev| matches!(ev, GroupEvent::GroupMessage { ref plaintext, .. } if plaintext == b"lifecycle msg 1"),
        )
        .await;
        assert!(found, "node {i} should decrypt first broadcast");
    }

    // Rekey: verified in dedicated rekey_continuity test, here just check
    // control propagation
    nodes[0].node.propose_rekey(&gid).unwrap();

    for node in &mut nodes[1..] {
        let found = wait_for_event(node, EVENT_TIMEOUT, |ev| {
            matches!(ev, GroupEvent::GroupControlApplied { .. })
        })
        .await;
        assert!(found, "node should receive rekey control");
    }

    // Dissolve
    nodes[0].node.propose_dissolve(&gid).unwrap();

    for (i, node) in nodes[1..].iter_mut().enumerate() {
        let found = wait_for_event(node, EVENT_TIMEOUT, |ev| {
            matches!(ev, GroupEvent::GroupDissolved { .. })
        })
        .await;
        assert!(found, "node {i} should receive GroupDissolved");
    }
}
