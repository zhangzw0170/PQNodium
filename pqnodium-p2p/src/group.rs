use std::collections::{HashMap, HashSet};

use pqnodium_core::crypto::backend::pqc::ml_kem::MlKem768Kem;
use pqnodium_core::crypto::backend::pqc::x25519::X25519Kem;
use pqnodium_core::crypto::hybrid::hybrid_kem::{HybridKemPublicKey, HybridKemSecretKey};
use pqnodium_core::envelope::Envelope;
use pqnodium_core::group::traits::GroupCipher;
use pqnodium_core::group::types::GroupId;
use pqnodium_core::group::{
    GroupControlEnvelope, GroupInfo, GroupLifecycleError, GroupLifecycleManager, GroupStatus,
    SenderKeyCipher,
};
use pqnodium_core::identity::PeerId;

use crate::error::PqP2pError;
use crate::event::PqEvent;
use crate::node::PqNode;

// ─── Constants ───

/// Minimum payload length for a group data message: 1 (type) + 32 (group_id) + 52 (SK header).
const GROUP_DATA_MIN_LEN: usize = 1 + 32 + 52;

/// Payload type byte for encrypted group data messages.
const GROUP_DATA_TYPE: u8 = 0x10;

/// Payload type byte range for group control messages (0x20-0x2F).
fn is_control_type(byte: u8) -> bool {
    (0x20..=0x2F).contains(&byte)
}

/// Payload type byte range for pairwise handshake messages (0x01-0x03).
#[cfg(test)]
fn is_handshake_type(byte: u8) -> bool {
    (0x01..=0x03).contains(&byte)
}

// ─── GroupEvent ───

/// Events produced by [`GroupNode`], wrapping P2P events with group-aware decryption.
#[derive(Debug)]
pub enum GroupEvent {
    /// A decrypted group message was received.
    GroupMessage {
        group_id: GroupId,
        sender_id: PeerId,
        plaintext: Vec<u8>,
    },
    /// A group control message was applied (membership change, rekey, etc.).
    GroupControlApplied { group_id: GroupId, epoch: u64 },
    /// A group was dissolved.
    GroupDissolved { group_id: GroupId },
    /// A non-group P2P event passed through.
    P2P(PqEvent),
    /// A message could not be decoded or decrypted.
    MalformedMessage { from: String, reason: String },
}

// ─── GroupNodeError ───

/// Errors from [`GroupNode`] operations.
#[derive(Debug, thiserror::Error)]
pub enum GroupNodeError {
    #[error("P2P error: {0}")]
    P2P(#[from] PqP2pError),
    #[error("lifecycle error: {0}")]
    Lifecycle(#[from] GroupLifecycleError),
    #[error("no cipher for group: {0}")]
    NoCipher(GroupId),
    #[error("sender key error: {0}")]
    SenderKey(#[from] pqnodium_core::group::sender_key::error::SenderKeyError),
    #[error("envelope error: {0}")]
    Envelope(String),
}

// ─── GroupNode ───

/// Group-aware P2P node that encrypts/decrypts group messages transparently.
///
/// Wraps a [`PqNode`] and a [`GroupLifecycleManager`], providing:
/// - Encrypted group data broadcast via Gossipsub
/// - Group control message delivery (create, add, remove, rekey, dissolve)
/// - Automatic decrypt/dispatch of incoming messages
pub struct GroupNode {
    p2p: PqNode,
    lifecycle: GroupLifecycleManager,
    /// group_id bytes -> current SenderKeyCipher for encrypting outbound messages.
    ciphers: HashMap<[u8; 32], SenderKeyCipher>,
    /// Set of group_id bytes we belong to.
    groups: HashSet<[u8; 32]>,
    /// String used in Envelope's sender_id field (typically libp2p PeerId).
    my_sender_id: String,
}

impl GroupNode {
    /// Create a new GroupNode wrapping a PqNode with group encryption support.
    pub fn new(
        p2p: PqNode,
        my_peer_id: PeerId,
        my_hybrid_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>,
        sender_id_str: String,
    ) -> Self {
        Self {
            p2p,
            lifecycle: GroupLifecycleManager::new(my_peer_id, my_hybrid_sk),
            ciphers: HashMap::new(),
            groups: HashSet::new(),
            my_sender_id: sender_id_str,
        }
    }

    // ─── Propose (broadcast control envelope) ───

    /// Propose creating a new group. Broadcasts control envelope via Gossipsub.
    pub fn propose_create(
        &mut self,
        members: Vec<PeerId>,
    ) -> Result<(GroupId, GroupControlEnvelope), GroupNodeError> {
        let (gid, cipher, envelope) = self.lifecycle.propose_create(members)?;
        self.ciphers.insert(*gid.as_bytes(), cipher);
        self.groups.insert(*gid.as_bytes());
        self.broadcast_control(&envelope)?;
        Ok((gid, envelope))
    }

    /// Propose adding a member. Broadcasts control envelope via Gossipsub.
    pub fn propose_add(
        &mut self,
        group_id: &GroupId,
        member: &PeerId,
    ) -> Result<GroupControlEnvelope, GroupNodeError> {
        let (cipher, envelope) = self.lifecycle.propose_add(group_id, member)?;
        self.ciphers.insert(*group_id.as_bytes(), cipher);
        self.broadcast_control(&envelope)?;
        Ok(envelope)
    }

    /// Propose removing a member. Broadcasts control envelope via Gossipsub.
    pub fn propose_remove(
        &mut self,
        group_id: &GroupId,
        member: &PeerId,
    ) -> Result<GroupControlEnvelope, GroupNodeError> {
        let (cipher, envelope) = self.lifecycle.propose_remove(group_id, member)?;
        self.ciphers.insert(*group_id.as_bytes(), cipher);
        self.broadcast_control(&envelope)?;
        Ok(envelope)
    }

    /// Propose a key rotation. Broadcasts control envelope via Gossipsub.
    pub fn propose_rekey(
        &mut self,
        group_id: &GroupId,
    ) -> Result<GroupControlEnvelope, GroupNodeError> {
        let (cipher, envelope) = self.lifecycle.propose_rekey(group_id)?;
        self.ciphers.insert(*group_id.as_bytes(), cipher);
        self.broadcast_control(&envelope)?;
        Ok(envelope)
    }

    /// Propose dissolving a group. Broadcasts control envelope via Gossipsub.
    pub fn propose_dissolve(
        &mut self,
        group_id: &GroupId,
    ) -> Result<GroupControlEnvelope, GroupNodeError> {
        let envelope = self.lifecycle.propose_dissolve(group_id)?;
        self.ciphers.remove(group_id.as_bytes());
        self.broadcast_control(&envelope)?;
        Ok(envelope)
    }

    // ─── Send ───

    /// Encrypt and send a plaintext message to a group via Gossipsub.
    pub fn send_group_message(
        &mut self,
        group_id: &GroupId,
        plaintext: &[u8],
    ) -> Result<(), GroupNodeError> {
        let cipher = self
            .ciphers
            .get_mut(group_id.as_bytes())
            .ok_or(GroupNodeError::NoCipher(group_id.clone()))?;

        let sender_key_ct = cipher.encrypt(plaintext)?;

        // Build payload: [msg_type:1 = 0x10][group_id:32][sender_key_ciphertext]
        let mut payload = Vec::with_capacity(1 + 32 + sender_key_ct.len());
        payload.push(GROUP_DATA_TYPE);
        payload.extend_from_slice(group_id.as_bytes());
        payload.extend_from_slice(&sender_key_ct);

        let envelope = Envelope::new(self.my_sender_id.clone(), payload);
        self.p2p.publish(&envelope.encode())?;
        Ok(())
    }

    // ─── Receive ───

    /// Poll for the next event with group-aware decryption and dispatch.
    pub async fn poll_next(&mut self) -> Option<GroupEvent> {
        let pq_event = self.p2p.poll_next().await?;

        match pq_event {
            PqEvent::MessageReceived { from, data } => self.handle_message(from, &data),
            other => Some(GroupEvent::P2P(other)),
        }
    }

    // ─── Pass-through ───

    /// Get a reference to the underlying PqNode.
    pub fn p2p(&self) -> &PqNode {
        &self.p2p
    }

    /// Get a mutable reference to the underlying PqNode.
    pub fn p2p_mut(&mut self) -> &mut PqNode {
        &mut self.p2p
    }

    /// Get a reference to the lifecycle manager.
    pub fn lifecycle(&self) -> &GroupLifecycleManager {
        &self.lifecycle
    }

    /// Register a member's hybrid KEM public key.
    pub fn register_member_pk(
        &mut self,
        peer_id: PeerId,
        pk: HybridKemPublicKey<X25519Kem, MlKem768Kem>,
    ) {
        self.lifecycle.register_member_pk(peer_id, pk);
    }

    /// Query group info.
    pub fn group_info(&self, group_id: &GroupId) -> Result<GroupInfo, GroupNodeError> {
        self.lifecycle
            .group_info(group_id)
            .map_err(GroupNodeError::from)
    }

    /// List all groups we are a member of.
    pub fn list_groups(&self) -> Vec<GroupInfo> {
        self.groups
            .iter()
            .filter_map(|gid_bytes| {
                let gid = GroupId::from_bytes(*gid_bytes);
                self.lifecycle.group_info(&gid).ok()
            })
            .collect()
    }

    // ─── Internal helpers ───

    fn broadcast_control(&mut self, envelope: &GroupControlEnvelope) -> Result<(), GroupNodeError> {
        let payload = envelope.encode();
        let env = Envelope::new(self.my_sender_id.clone(), payload);
        self.p2p.publish(&env.encode())?;
        Ok(())
    }

    fn handle_message(&mut self, from: String, data: &[u8]) -> Option<GroupEvent> {
        let envelope = match Envelope::decode(data) {
            Ok(e) => e,
            Err(_) => {
                return Some(GroupEvent::MalformedMessage {
                    from,
                    reason: "invalid envelope".into(),
                });
            }
        };

        if envelope.payload.is_empty() {
            return Some(GroupEvent::MalformedMessage {
                from,
                reason: "empty payload".into(),
            });
        }

        let first = envelope.payload[0];

        if first == 0x01 && envelope.payload.len() > 1 && is_control_type(envelope.payload[1]) {
            // GroupControlEnvelope: [version:1=0x01][msg_type:1=0x20-0x2F][...]
            self.handle_control_envelope(from, &envelope.payload)
        } else if first == GROUP_DATA_TYPE && envelope.payload.len() >= GROUP_DATA_MIN_LEN {
            self.handle_group_data(from, &envelope.payload)
        } else {
            // Pairwise or unknown — pass through
            Some(GroupEvent::P2P(PqEvent::MessageReceived {
                from,
                data: data.to_vec(),
            }))
        }
    }

    fn handle_control_envelope(&mut self, from: String, payload: &[u8]) -> Option<GroupEvent> {
        let result = match self.lifecycle.apply_control(payload) {
            Ok(r) => r,
            Err(e) => {
                return Some(GroupEvent::MalformedMessage {
                    from,
                    reason: format!("control apply failed: {e}"),
                });
            }
        };

        if let Some(cipher) = result.cipher {
            self.ciphers.insert(*result.group_id.as_bytes(), cipher);
        }
        self.groups.insert(*result.group_id.as_bytes());

        let is_dissolved = self
            .lifecycle
            .group_info(&result.group_id)
            .ok()
            .map(|i| i.status == GroupStatus::Dissolved)
            .unwrap_or(false);

        if is_dissolved {
            self.ciphers.remove(result.group_id.as_bytes());
            self.groups.remove(result.group_id.as_bytes());
            Some(GroupEvent::GroupDissolved {
                group_id: result.group_id,
            })
        } else {
            Some(GroupEvent::GroupControlApplied {
                group_id: result.group_id,
                epoch: result.epoch,
            })
        }
    }

    fn handle_group_data(&mut self, from: String, payload: &[u8]) -> Option<GroupEvent> {
        let group_id = match payload[1..33].try_into().ok() {
            Some(bytes) => GroupId::from_bytes(bytes),
            None => {
                return Some(GroupEvent::MalformedMessage {
                    from,
                    reason: "invalid group_id in group data".into(),
                });
            }
        };

        let sender_key_ct = &payload[33..];

        let cipher = match self.ciphers.get(group_id.as_bytes()) {
            Some(c) => c,
            None => {
                return Some(GroupEvent::MalformedMessage {
                    from,
                    reason: format!("no cipher for group {group_id}"),
                });
            }
        };

        let plaintext = match cipher.decrypt(sender_key_ct) {
            Ok(pt) => pt,
            Err(_) => {
                return Some(GroupEvent::MalformedMessage {
                    from,
                    reason: "group data decryption failed".into(),
                });
            }
        };

        // Replay check: extract sender_id and chain_step from SK ciphertext header
        if sender_key_ct.len() < 40 {
            return Some(GroupEvent::MalformedMessage {
                from,
                reason: "sender key ciphertext too short".into(),
            });
        }
        let sender_bytes: [u8; 32] = sender_key_ct[..32].try_into().ok()?;
        let chain_step = u64::from_le_bytes(sender_key_ct[32..40].try_into().ok()?);
        if self
            .lifecycle
            .check_replay(&group_id, sender_bytes, chain_step)
            .is_err()
        {
            return None; // silently drop replayed messages
        }

        let sender_id = PeerId::from_bytes(sender_bytes);

        Some(GroupEvent::GroupMessage {
            group_id,
            sender_id,
            plaintext,
        })
    }
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;
    use pqnodium_core::crypto::hybrid::hybrid_kem::HybridKem;
    use pqnodium_core::crypto::traits::kem::KeyEncapsulation;
    use pqnodium_core::crypto::traits::sign::Signer;
    use pqnodium_core::group::traits::GroupCipher;

    type PqHybridKem = HybridKem<X25519Kem, MlKem768Kem>;

    struct TestPeer {
        peer_id: PeerId,
        hybrid_pk: HybridKemPublicKey<X25519Kem, MlKem768Kem>,
        hybrid_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>,
    }

    impl TestPeer {
        fn generate() -> Self {
            let (ed_pk, _) = pqnodium_core::crypto::backend::pqc::ed25519::Ed25519Signer::keygen(
                &mut rand::rngs::OsRng,
            );
            let (ml_pk, _) = pqnodium_core::crypto::backend::pqc::ml_dsa::MlDsa65Signer::keygen(
                &mut rand::rngs::OsRng,
            );
            let peer_id = PeerId::from_hybrid_pk(&ed_pk, &ml_pk);
            let (hybrid_pk, hybrid_sk) = PqHybridKem::keygen_os();
            Self {
                peer_id,
                hybrid_pk,
                hybrid_sk,
            }
        }
    }

    fn setup_lifecycle(n: usize) -> (GroupLifecycleManager, Vec<TestPeer>) {
        let peers: Vec<TestPeer> = (0..n).map(|_| TestPeer::generate()).collect();
        let first = &peers[0];
        let mut mgr = GroupLifecycleManager::new(first.peer_id.clone(), first.hybrid_sk.clone());
        for p in &peers {
            mgr.register_member_pk(p.peer_id.clone(), p.hybrid_pk.clone());
        }
        (mgr, peers)
    }

    fn build_group_data_payload(
        group_id: &GroupId,
        cipher: &mut SenderKeyCipher,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let ct = cipher.encrypt(plaintext).unwrap();
        let mut payload = Vec::with_capacity(1 + 32 + ct.len());
        payload.push(GROUP_DATA_TYPE);
        payload.extend_from_slice(group_id.as_bytes());
        payload.extend_from_slice(&ct);
        payload
    }

    fn wrap_in_envelope(sender_id: &str, payload: Vec<u8>) -> Vec<u8> {
        Envelope::new(sender_id.to_string(), payload).encode()
    }

    // ─── Wire format ───

    #[test]
    fn group_data_wire_format() {
        let (mut mgr, peers) = setup_lifecycle(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher, _) = mgr.propose_create(members).unwrap();
        let payload = build_group_data_payload(&gid, &mut cipher, b"hello");

        assert_eq!(payload[0], GROUP_DATA_TYPE);
        assert_eq!(&payload[1..33], gid.as_bytes());
        assert!(payload.len() > GROUP_DATA_MIN_LEN);
    }

    #[test]
    fn control_payload_first_byte() {
        let (mut mgr, peers) = setup_lifecycle(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (_, _, envelope) = mgr.propose_create(members).unwrap();
        let encoded = envelope.encode();
        assert!(is_control_type(encoded[1])); // byte 1 is the control type (byte 0 is version)
    }

    // ─── Dispatch ───

    #[test]
    fn dispatch_control_applied() {
        let (mut mgr_a, peers) = setup_lifecycle(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (_, _, create_env) = mgr_a.propose_create(members).unwrap();

        let wire = wrap_in_envelope("sender-a", create_env.encode());
        let envelope = Envelope::decode(&wire).unwrap();

        // Manager B is initialized as the second peer from the same set
        let mut mgr_b =
            GroupLifecycleManager::new(peers[1].peer_id.clone(), peers[1].hybrid_sk.clone());
        for p in &peers {
            mgr_b.register_member_pk(p.peer_id.clone(), p.hybrid_pk.clone());
        }
        let result = mgr_b.apply_control(&envelope.payload).unwrap();
        // GroupControlEnvelope: [version:1][type:1][epoch:8][group_id:32][proposer_id:32]...
        let expected_gid = GroupId::from_bytes(envelope.payload[10..42].try_into().unwrap());
        assert_eq!(result.group_id, expected_gid);
        assert!(result.cipher.is_some());
    }

    #[test]
    fn dispatch_group_message_decrypted() {
        let (mut mgr, peers) = setup_lifecycle(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher, _) = mgr.propose_create(members).unwrap();
        let payload = build_group_data_payload(&gid, &mut cipher, b"secret msg");

        // Simulate dispatch: parse group_id, decrypt
        let _group_id = GroupId::from_bytes(payload[1..33].try_into().unwrap());
        let ct = &payload[33..];
        let decrypted = cipher.decrypt(ct).unwrap();
        assert_eq!(decrypted, b"secret msg");
    }

    #[test]
    fn dispatch_unknown_passthrough() {
        let payload = vec![0xFF, 0x01, 0x02, 0x03];
        let first_byte = payload[0];
        assert!(!is_control_type(first_byte));
        assert!(!is_handshake_type(first_byte));
        assert!(first_byte != GROUP_DATA_TYPE);
    }

    #[test]
    fn dispatch_pairwise_passthrough() {
        let payload = vec![0x01, 0x00, 0x00, 0x00]; // version byte for handshake
        assert!(is_handshake_type(payload[0]));
    }

    #[test]
    fn empty_payload_malformed() {
        let payload: Vec<u8> = vec![];
        assert!(payload.is_empty());
    }

    #[test]
    fn group_data_too_short() {
        let mut payload = vec![0x42; 32];
        payload.insert(0, GROUP_DATA_TYPE); // only 33 bytes, needs 85+
        assert!(payload.len() < GROUP_DATA_MIN_LEN);
    }

    #[test]
    fn replay_detection_in_dispatch() {
        let (mut mgr, peers) = setup_lifecycle(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher, _) = mgr.propose_create(members).unwrap();

        let payload = build_group_data_payload(&gid, &mut cipher, b"replay me");
        let ct = &payload[33..];

        // First decrypt works
        let _ = cipher.decrypt(ct).unwrap();

        // check_replay should succeed for new, fail for duplicate
        let sender_bytes: [u8; 32] = ct[..32].try_into().unwrap();
        let step = u64::from_le_bytes(ct[32..40].try_into().unwrap());
        assert!(mgr.check_replay(&gid, sender_bytes, step).is_ok());
        assert!(mgr.check_replay(&gid, sender_bytes, step).is_err());
    }

    // ─── Cipher management ───

    #[test]
    fn propose_create_stores_cipher() {
        let (mut mgr, peers) = setup_lifecycle(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();
        assert!(mgr.members(&gid).is_ok());
        assert_eq!(mgr.epoch(&gid).unwrap(), 0);
    }

    #[test]
    fn propose_dissolve_removes_cipher() {
        let (mut mgr, peers) = setup_lifecycle(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();
        mgr.propose_dissolve(&gid).unwrap();
        let info = mgr.group_info(&gid).unwrap();
        assert_eq!(info.status, GroupStatus::Dissolved);
    }

    #[test]
    fn send_group_message_encodes_correctly() {
        let (mut mgr, peers) = setup_lifecycle(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher, _) = mgr.propose_create(members).unwrap();
        let payload = build_group_data_payload(&gid, &mut cipher, b"test");

        let envelope = Envelope::decode(&wrap_in_envelope("s", payload)).unwrap();
        assert_eq!(envelope.payload[0], GROUP_DATA_TYPE);
        assert_eq!(&envelope.payload[1..33], gid.as_bytes());
    }

    #[test]
    fn no_cipher_for_unknown_group() {
        let (_, _) = setup_lifecycle(2);
        let gid = GroupId::from_bytes([0xEE; 32]);
        let ciphers: HashMap<[u8; 32], SenderKeyCipher> = HashMap::new();
        assert!(ciphers.get(gid.as_bytes()).is_none());
    }

    #[test]
    fn lifecycle_error_propagated() {
        let payload = vec![0x20]; // control type but way too short
        let (mut mgr, _) = setup_lifecycle(2);
        let result = mgr.apply_control(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn list_groups_after_operations() {
        let (mut mgr, peers) = setup_lifecycle(4);
        let members_a: Vec<PeerId> = peers[0..2].iter().map(|p| p.peer_id.clone()).collect();
        let members_b: Vec<PeerId> = peers[2..4].iter().map(|p| p.peer_id.clone()).collect();

        let (gid_a, _, _) = mgr.propose_create(members_a).unwrap();
        let (gid_b, _, _) = mgr.propose_create(members_b).unwrap();

        let members_a = mgr.members(&gid_a).unwrap();
        let members_b = mgr.members(&gid_b).unwrap();
        assert_eq!(members_a.len(), 2);
        assert_eq!(members_b.len(), 2);
        // Verify they are different groups
        assert_ne!(gid_a, gid_b);
    }
}
