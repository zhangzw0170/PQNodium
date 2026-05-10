use libp2p::Multiaddr;
use pqnodium_core::envelope::Envelope;
use pqnodium_p2p::config::PqNodeConfig;
use pqnodium_p2p::event::PqEvent;
use pqnodium_p2p::node::PqNode;
use std::time::Duration;
use tokio::time::timeout;

/// Helper: create a node, start listening, subscribe to gossip, return (node, listen_addr).
async fn create_listening_node() -> (PqNode, Multiaddr) {
    let config = PqNodeConfig::default();
    let mut node = PqNode::new(&config).unwrap();
    node.start_listening(config.listen_addr.clone()).unwrap();
    node.subscribe_default().unwrap();

    let addr = loop {
        if let Some(PqEvent::Listening { address }) = node.poll_next().await {
            break address;
        }
    };
    (node, addr)
}

#[tokio::test]
async fn two_nodes_gossipsub_message_delivery() {
    let (mut node_a, addr_a) = create_listening_node().await;
    let (mut node_b, _) = create_listening_node().await;

    let peer_id_a = node_a.peer_id().to_string();

    // Connect B → A
    node_b.dial(addr_a.clone()).unwrap();

    // Wait for connection established
    timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                ev = node_a.poll_next() => {
                    if let Some(PqEvent::PeerConnected { .. }) = &ev { break; }
                }
                ev = node_b.poll_next() => {
                    if let Some(PqEvent::PeerConnected { .. }) = &ev { break; }
                }
            }
        }
    })
    .await
    .expect("connection timeout");

    // Give gossipsub a moment to establish mesh
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain pending events
    while let Ok(ev) = timeout(Duration::from_millis(100), node_a.poll_next()).await {
        let _ = ev;
    }
    while let Ok(ev) = timeout(Duration::from_millis(100), node_b.poll_next()).await {
        let _ = ev;
    }

    // A publishes a message via envelope
    let envelope = Envelope::new(peer_id_a.clone(), b"hello from A".to_vec());
    let encoded = envelope.encode();
    node_a.publish(&encoded).unwrap();

    // B should receive the message
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(PqEvent::MessageReceived { data, .. }) = node_b.poll_next().await {
                break data;
            }
        }
    })
    .await
    .expect("message delivery timeout");

    let decoded = Envelope::decode(&received).unwrap();
    assert_eq!(decoded.sender_id, peer_id_a);
    assert_eq!(decoded.payload, b"hello from A");
}

#[tokio::test]
async fn gossipsub_subscribe_unsubscribe() {
    let config = PqNodeConfig::default();
    let mut node = PqNode::new(&config).unwrap();
    // subscribe_default is idempotent — calling twice should not panic
    node.subscribe_default().unwrap();
    node.subscribe_default().unwrap();
}

#[tokio::test]
async fn gossipsub_publish_without_subscribers() {
    let config = PqNodeConfig::default();
    let mut node = PqNode::new(&config).unwrap();
    node.subscribe_default().unwrap();
    node.start_listening(config.listen_addr.clone()).unwrap();

    // Wait for listen event
    timeout(Duration::from_secs(2), async {
        loop {
            if let Some(PqEvent::Listening { .. }) = node.poll_next().await {
                break;
            }
        }
    })
    .await
    .unwrap();

    let envelope = Envelope::new("test-sender".to_string(), b"test".to_vec());
    // Gossipsub may reject publish without mesh peers — that's OK, it doesn't panic
    let _ = node.publish(&envelope.encode());
}

#[tokio::test]
async fn three_nodes_broadcast() {
    let (mut node_a, addr_a) = create_listening_node().await;
    let (mut node_b, _) = create_listening_node().await;
    let (mut node_c, _) = create_listening_node().await;

    let peer_id_a = node_a.peer_id().to_string();

    // Connect B and C to A
    node_b.dial(addr_a.clone()).unwrap();
    node_c.dial(addr_a.clone()).unwrap();

    // Wait for connections
    let mut a_connected = 0;
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                ev = node_a.poll_next() => {
                    if let Some(PqEvent::PeerConnected { .. }) = &ev {
                        a_connected += 1;
                        if a_connected >= 2 { break; }
                    }
                }
                _ = node_b.poll_next() => {}
                _ = node_c.poll_next() => {}
            }
        }
    })
    .await
    .expect("connection timeout for 3-node mesh");

    // Let gossipsub mesh establish
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Drain events
    for node in [&mut node_a, &mut node_b, &mut node_c] {
        while let Ok(ev) = timeout(Duration::from_millis(50), node.poll_next()).await {
            let _ = ev;
        }
    }

    // A broadcasts
    let envelope = Envelope::new(peer_id_a.clone(), b"broadcast msg".to_vec());
    node_a.publish(&envelope.encode()).unwrap();

    // Both B and C should receive
    for (name, node) in [("B", &mut node_b), ("C", &mut node_c)] {
        let received = timeout(Duration::from_secs(8), async {
            loop {
                if let Some(PqEvent::MessageReceived { data, .. }) = node.poll_next().await {
                    break data;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{name} did not receive broadcast"));

        let decoded = Envelope::decode(&received).unwrap();
        assert_eq!(decoded.sender_id, peer_id_a);
        assert_eq!(decoded.payload, b"broadcast msg");
    }
}
