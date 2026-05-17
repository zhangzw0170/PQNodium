use std::collections::HashMap;

use crate::crypto::backend::pqc::ml_kem::MlKem768Kem;
use crate::crypto::backend::pqc::x25519::X25519Kem;
use crate::crypto::hybrid::hybrid_kem::{HybridKemPublicKey, HybridKemSecretKey};
use crate::group::sender_key::{SenderKeyCipher, SenderKeyDistributionPayload, SenderKeyManager};
use crate::group::traits::GroupSessionManager;
use crate::group::types::GroupId;
use crate::identity::PeerId;

use super::error::GroupLifecycleError;
use super::state::LifecycleGroupState;
use super::types::{
    ApplyResult, GroupControlEnvelope, GroupControlMessageType, GroupInfo, GroupStatus,
};

type PendingAcks = Vec<(u64, Vec<[u8; 32]>)>;

/// Production-ready group lifecycle manager wrapping the Sender Key crypto backend.
///
/// Adds epoch management, propose/apply separation, replay detection,
/// ack tracking, batch mutations, and state queries on top of
/// [`SenderKeyManager`].
pub struct GroupLifecycleManager {
    inner: SenderKeyManager,
    my_peer_id: PeerId,
    lifecycle_states: HashMap<[u8; 32], LifecycleGroupState>,
}

impl GroupLifecycleManager {
    /// Create a new lifecycle manager.
    pub fn new(
        my_peer_id: PeerId,
        my_hybrid_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>,
    ) -> Self {
        Self {
            inner: SenderKeyManager::new(my_peer_id.clone(), my_hybrid_sk),
            my_peer_id,
            lifecycle_states: HashMap::new(),
        }
    }

    /// Register a member's hybrid KEM public key for future group operations.
    pub fn register_member_pk(
        &mut self,
        peer_id: PeerId,
        pk: HybridKemPublicKey<X25519Kem, MlKem768Kem>,
    ) {
        self.inner.register_member_pk(peer_id, pk);
    }

    // ─── Helpers ───

    fn get_state(&self, group_id: &GroupId) -> Result<&LifecycleGroupState, GroupLifecycleError> {
        self.lifecycle_states
            .get(group_id.as_bytes())
            .ok_or(GroupLifecycleError::GroupNotFound)
    }

    fn get_state_mut(
        &mut self,
        group_id: &GroupId,
    ) -> Result<&mut LifecycleGroupState, GroupLifecycleError> {
        self.lifecycle_states
            .get_mut(group_id.as_bytes())
            .ok_or(GroupLifecycleError::GroupNotFound)
    }

    fn build_envelope(
        &self,
        msg_type: GroupControlMessageType,
        epoch: u64,
        group_id: &GroupId,
        distribution: Option<SenderKeyDistributionPayload>,
    ) -> GroupControlEnvelope {
        GroupControlEnvelope {
            msg_type,
            epoch,
            group_id: group_id.clone(),
            proposer_id: self.my_peer_id.clone(),
            distribution,
        }
    }

    // ─── Propose ───

    /// Propose group creation. Returns (group_id, cipher, envelope for broadcast).
    pub fn propose_create(
        &mut self,
        members: Vec<PeerId>,
    ) -> Result<(GroupId, SenderKeyCipher, GroupControlEnvelope), GroupLifecycleError> {
        let (group_id, cipher, payload) = self.inner.create_group(&members)?;

        let state = LifecycleGroupState::new(members);
        let epoch = state.epoch;
        self.lifecycle_states.insert(*group_id.as_bytes(), state);

        let envelope = self.build_envelope(
            GroupControlMessageType::GroupCreate,
            epoch,
            &group_id,
            Some(payload),
        );
        Ok((group_id, cipher, envelope))
    }

    /// Propose adding a member to an existing group.
    pub fn propose_add(
        &mut self,
        group_id: &GroupId,
        member: &PeerId,
    ) -> Result<(SenderKeyCipher, GroupControlEnvelope), GroupLifecycleError> {
        {
            let state = self.get_state(group_id)?;
            state.require_active()?;
            if state.members.contains(member) {
                return Err(GroupLifecycleError::AlreadyMember);
            }
            if state.has_pending() {
                return Err(GroupLifecycleError::ProposalConflict);
            }
        }

        let (cipher, payload) = self.inner.add_member(group_id, member)?;

        let state = self.get_state_mut(group_id)?;
        state.members.push(member.clone());
        let epoch = state.advance_epoch();

        let envelope = self.build_envelope(
            GroupControlMessageType::GroupAdd,
            epoch,
            group_id,
            Some(payload),
        );
        Ok((cipher, envelope))
    }

    /// Propose removing a member from an existing group.
    pub fn propose_remove(
        &mut self,
        group_id: &GroupId,
        member: &PeerId,
    ) -> Result<(SenderKeyCipher, GroupControlEnvelope), GroupLifecycleError> {
        {
            let state = self.get_state(group_id)?;
            state.require_active()?;
            if !state.members.contains(member) {
                return Err(GroupLifecycleError::NotMember);
            }
            if state.has_pending() {
                return Err(GroupLifecycleError::ProposalConflict);
            }
        }

        let (cipher, payload) = self.inner.remove_member(group_id, member)?;

        let state = self.get_state_mut(group_id)?;
        state.members.retain(|m| m != member);
        let epoch = state.advance_epoch();

        let envelope = self.build_envelope(
            GroupControlMessageType::GroupRemove,
            epoch,
            group_id,
            Some(payload),
        );
        Ok((cipher, envelope))
    }

    /// Propose a key rotation for an existing group.
    pub fn propose_rekey(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(SenderKeyCipher, GroupControlEnvelope), GroupLifecycleError> {
        {
            let state = self.get_state(group_id)?;
            state.require_active()?;
            if state.has_pending() {
                return Err(GroupLifecycleError::ProposalConflict);
            }
        }

        let (cipher, payload) = self.inner.rotate_key(group_id)?;

        let state = self.get_state_mut(group_id)?;
        let epoch = state.advance_epoch();

        let envelope = self.build_envelope(
            GroupControlMessageType::GroupRekey,
            epoch,
            group_id,
            Some(payload),
        );
        Ok((cipher, envelope))
    }

    /// Propose dissolving a group.
    pub fn propose_dissolve(
        &mut self,
        group_id: &GroupId,
    ) -> Result<GroupControlEnvelope, GroupLifecycleError> {
        {
            let state = self.get_state(group_id)?;
            state.require_active()?;
        }

        self.inner.dissolve(group_id)?;

        let state = self.get_state_mut(group_id)?;
        state.status = GroupStatus::Dissolved;
        let epoch = state.advance_epoch();

        let envelope = self.build_envelope(
            GroupControlMessageType::GroupDissolve,
            epoch,
            group_id,
            None,
        );
        Ok(envelope)
    }

    // ─── Batch ───

    /// Queue a member addition for later batch flush.
    pub fn queue_add(
        &mut self,
        group_id: &GroupId,
        member: PeerId,
    ) -> Result<(), GroupLifecycleError> {
        self.get_state_mut(group_id)?.queue_add(member)
    }

    /// Queue a member removal for later batch flush.
    pub fn queue_remove(
        &mut self,
        group_id: &GroupId,
        member: PeerId,
    ) -> Result<(), GroupLifecycleError> {
        self.get_state_mut(group_id)?.queue_remove(member)
    }

    /// Flush all pending batch operations. Each add/remove triggers a rekey.
    pub fn flush_pending(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(SenderKeyCipher, GroupControlEnvelope), GroupLifecycleError> {
        let (adds, removes) = {
            let state = self.get_state_mut(group_id)?;
            if !state.has_pending() {
                return Err(GroupLifecycleError::NoPendingChanges);
            }
            state.drain_pending()
        };

        let mut last_cipher = None;
        let mut last_payload = None;

        for member in &adds {
            let (cipher, payload) = self.inner.add_member(group_id, member)?;
            last_cipher = Some(cipher);
            last_payload = Some(payload);
        }
        for member in &removes {
            let (cipher, payload) = self.inner.remove_member(group_id, member)?;
            last_cipher = Some(cipher);
            last_payload = Some(payload);
        }

        let state = self.get_state_mut(group_id)?;
        for member in &adds {
            if !state.members.contains(member) {
                state.members.push(member.clone());
            }
        }
        for member in &removes {
            state.members.retain(|m| m != member);
        }
        let epoch = state.advance_epoch();

        let envelope = self.build_envelope(
            GroupControlMessageType::GroupRekey,
            epoch,
            group_id,
            last_payload,
        );

        Ok((
            last_cipher.expect("at least one pending operation"),
            envelope,
        ))
    }

    /// Propose a batch of adds and removes in a single operation.
    pub fn propose_batch(
        &mut self,
        group_id: &GroupId,
        adds: &[PeerId],
        removes: &[PeerId],
    ) -> Result<(SenderKeyCipher, GroupControlEnvelope), GroupLifecycleError> {
        {
            let state = self.get_state(group_id)?;
            state.require_active()?;
            for member in adds {
                if state.members.contains(member) {
                    return Err(GroupLifecycleError::AlreadyMember);
                }
            }
            for member in removes {
                if !state.members.contains(member) {
                    return Err(GroupLifecycleError::NotMember);
                }
            }
            if adds.is_empty() && removes.is_empty() {
                return Err(GroupLifecycleError::NoPendingChanges);
            }
        }

        let mut last_cipher = None;
        let mut last_payload = None;

        for member in adds {
            let (cipher, payload) = self.inner.add_member(group_id, member)?;
            last_cipher = Some(cipher);
            last_payload = Some(payload);
        }
        for member in removes {
            let (cipher, payload) = self.inner.remove_member(group_id, member)?;
            last_cipher = Some(cipher);
            last_payload = Some(payload);
        }

        let state = self.get_state_mut(group_id)?;
        for member in adds {
            if !state.members.contains(member) {
                state.members.push(member.clone());
            }
        }
        for member in removes {
            state.members.retain(|m| m != member);
        }
        let epoch = state.advance_epoch();

        let envelope = self.build_envelope(
            GroupControlMessageType::GroupRekey,
            epoch,
            group_id,
            last_payload,
        );

        Ok((
            last_cipher.expect("batch must have at least one operation"),
            envelope,
        ))
    }

    // ─── Apply ───

    /// Apply a received control message (from wire bytes).
    pub fn apply_control(
        &mut self,
        envelope_bytes: &[u8],
    ) -> Result<ApplyResult, GroupLifecycleError> {
        let envelope = GroupControlEnvelope::decode(envelope_bytes)?;
        self.apply_envelope(&envelope)
    }

    fn apply_envelope(
        &mut self,
        envelope: &GroupControlEnvelope,
    ) -> Result<ApplyResult, GroupLifecycleError> {
        match envelope.msg_type {
            GroupControlMessageType::GroupCreate | GroupControlMessageType::GroupWelcome => {
                self.apply_create_or_welcome(envelope)
            }
            GroupControlMessageType::GroupAdd
            | GroupControlMessageType::GroupRemove
            | GroupControlMessageType::GroupRekey => match self.apply_mutation(envelope) {
                Ok(r) => Ok(r),
                Err(_)
                    if !self
                        .lifecycle_states
                        .contains_key(envelope.group_id.as_bytes())
                        && envelope.msg_type == GroupControlMessageType::GroupAdd =>
                {
                    self.apply_create_or_welcome(envelope)
                }
                Err(e) => Err(e),
            },
            GroupControlMessageType::GroupDissolve => self.apply_dissolve(envelope),
        }
    }

    fn apply_create_or_welcome(
        &mut self,
        envelope: &GroupControlEnvelope,
    ) -> Result<ApplyResult, GroupLifecycleError> {
        if self
            .lifecycle_states
            .contains_key(envelope.group_id.as_bytes())
        {
            let existing = self
                .lifecycle_states
                .get(envelope.group_id.as_bytes())
                .unwrap();
            return Err(GroupLifecycleError::InvalidTransition {
                from: existing.status,
                to: existing.status,
            });
        }

        let dist = envelope.distribution.as_ref().ok_or_else(|| {
            GroupLifecycleError::Serialization(
                "GroupCreate/Welcome requires distribution payload".into(),
            )
        })?;

        let (group_id, cipher) = self.inner.apply_distribution(dist)?;

        let mut state = LifecycleGroupState::new(dist.members.clone());
        while state.epoch < envelope.epoch {
            state.advance_epoch();
        }
        self.lifecycle_states.insert(*group_id.as_bytes(), state);

        Ok(ApplyResult {
            group_id,
            cipher: Some(cipher),
            epoch: envelope.epoch,
        })
    }

    fn apply_mutation(
        &mut self,
        envelope: &GroupControlEnvelope,
    ) -> Result<ApplyResult, GroupLifecycleError> {
        let dist = envelope.distribution.as_ref().ok_or_else(|| {
            GroupLifecycleError::Serialization(
                "mutation control message requires distribution payload".into(),
            )
        })?;

        {
            let state = self.get_state(&envelope.group_id)?;
            state.require_active()?;
            let expected = state.epoch + 1;
            if envelope.epoch != expected {
                return Err(GroupLifecycleError::EpochMismatch {
                    expected,
                    got: envelope.epoch,
                });
            }
        }

        let (group_id, cipher) = self.inner.apply_distribution(dist)?;

        let state = self.get_state_mut(&group_id)?;
        state.members = dist.members.clone();
        let _ = state.advance_epoch();

        Ok(ApplyResult {
            group_id,
            cipher: Some(cipher),
            epoch: envelope.epoch,
        })
    }

    fn apply_dissolve(
        &mut self,
        envelope: &GroupControlEnvelope,
    ) -> Result<ApplyResult, GroupLifecycleError> {
        {
            let state = self.get_state(&envelope.group_id)?;
            state.require_active()?;
            let expected = state.epoch + 1;
            if envelope.epoch != expected {
                return Err(GroupLifecycleError::EpochMismatch {
                    expected,
                    got: envelope.epoch,
                });
            }
        }

        self.inner.dissolve(&envelope.group_id)?;

        let state = self.get_state_mut(&envelope.group_id)?;
        state.status = GroupStatus::Dissolved;

        Ok(ApplyResult {
            group_id: envelope.group_id.clone(),
            cipher: None,
            epoch: envelope.epoch,
        })
    }

    // ─── Acknowledgment ───

    /// Record an ack from a member for a given epoch.
    pub fn acknowledge(
        &mut self,
        group_id: &GroupId,
        epoch: u64,
        member: &PeerId,
    ) -> Result<(), GroupLifecycleError> {
        let state = self.get_state_mut(group_id)?;
        if !state.members.contains(member) {
            return Err(GroupLifecycleError::MemberNotFound);
        }
        state.record_ack(epoch, *member.as_bytes());
        Ok(())
    }

    /// Return pending acks per epoch.
    pub fn pending_acks(&self, group_id: &GroupId) -> Result<PendingAcks, GroupLifecycleError> {
        let state = self.get_state(group_id)?;
        let mut result = Vec::new();
        for e in 0..=state.epoch {
            let pending = state.pending_acks_for_epoch(e);
            if !pending.is_empty() {
                result.push((e, pending));
            }
        }
        Ok(result)
    }

    // ─── Replay ───

    /// Check and record a replay entry. Returns error if already seen.
    pub fn check_replay(
        &mut self,
        group_id: &GroupId,
        sender_id: [u8; 32],
        chain_step: u64,
    ) -> Result<(), GroupLifecycleError> {
        let state = self.get_state_mut(group_id)?;
        state.record_replay(sender_id, chain_step)
    }

    // ─── Query ───

    /// Return the current member list for a group.
    pub fn members(&self, group_id: &GroupId) -> Result<Vec<PeerId>, GroupLifecycleError> {
        Ok(self.get_state(group_id)?.members.clone())
    }

    /// Check if a peer is a member of the group.
    pub fn is_member(
        &self,
        group_id: &GroupId,
        member: &PeerId,
    ) -> Result<bool, GroupLifecycleError> {
        Ok(self.get_state(group_id)?.members.contains(member))
    }

    /// Return the current epoch for a group.
    pub fn epoch(&self, group_id: &GroupId) -> Result<u64, GroupLifecycleError> {
        Ok(self.get_state(group_id)?.epoch)
    }

    /// Return a snapshot of group state.
    pub fn group_info(&self, group_id: &GroupId) -> Result<GroupInfo, GroupLifecycleError> {
        let state = self.get_state(group_id)?;
        Ok(GroupInfo {
            group_id: group_id.clone(),
            epoch: state.epoch,
            members: state.members.clone(),
            status: state.status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hybrid::hybrid_kem::HybridKem;
    use crate::crypto::traits::kem::KeyEncapsulation;
    use crate::crypto::traits::sign::Signer;
    use crate::group::traits::GroupCipher;

    type PqHybridKem = HybridKem<X25519Kem, MlKem768Kem>;

    struct TestPeer {
        peer_id: PeerId,
        hybrid_pk: HybridKemPublicKey<X25519Kem, MlKem768Kem>,
        hybrid_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>,
    }

    impl TestPeer {
        fn generate() -> Self {
            let (ed_pk, _) =
                crate::crypto::backend::pqc::ed25519::Ed25519Signer::keygen(&mut rand::rngs::OsRng);
            let (ml_pk, _) =
                crate::crypto::backend::pqc::ml_dsa::MlDsa65Signer::keygen(&mut rand::rngs::OsRng);
            let peer_id = PeerId::from_hybrid_pk(&ed_pk, &ml_pk);
            let (hybrid_pk, hybrid_sk) = PqHybridKem::keygen_os();
            Self {
                peer_id,
                hybrid_pk,
                hybrid_sk,
            }
        }
    }

    fn setup_manager(n: usize) -> (GroupLifecycleManager, Vec<TestPeer>) {
        let peers: Vec<TestPeer> = (0..n).map(|_| TestPeer::generate()).collect();
        let first = &peers[0];
        let mut mgr = GroupLifecycleManager::new(first.peer_id.clone(), first.hybrid_sk.clone());
        for p in &peers {
            mgr.register_member_pk(p.peer_id.clone(), p.hybrid_pk.clone());
        }
        (mgr, peers)
    }

    fn make_joiner_mgr(peer: &TestPeer, all_peers: &[TestPeer]) -> GroupLifecycleManager {
        let mut mgr = GroupLifecycleManager::new(peer.peer_id.clone(), peer.hybrid_sk.clone());
        for p in all_peers {
            mgr.register_member_pk(p.peer_id.clone(), p.hybrid_pk.clone());
        }
        mgr
    }

    // ─── propose_create ───

    #[test]
    fn propose_create_basic() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher, envelope) = mgr.propose_create(members.clone()).unwrap();

        assert_eq!(envelope.msg_type, GroupControlMessageType::GroupCreate);
        assert_eq!(envelope.epoch, 0);
        assert!(envelope.distribution.is_some());
        assert_eq!(mgr.epoch(&gid).unwrap(), 0);
        assert_eq!(mgr.members(&gid).unwrap().len(), 3);

        let ct = cipher.encrypt(b"hello").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"hello");
    }

    #[test]
    fn propose_create_envelope_roundtrip() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (_, _, envelope) = mgr.propose_create(members).unwrap();

        let bytes = envelope.encode();
        let decoded = GroupControlEnvelope::decode(&bytes).unwrap();
        assert_eq!(decoded.msg_type, envelope.msg_type);
        assert_eq!(decoded.epoch, envelope.epoch);
        assert_eq!(decoded.group_id, envelope.group_id);
    }

    // ─── apply_control (GroupCreate) ───

    #[test]
    fn apply_create_on_receiver() {
        let (mut mgr_a, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, envelope) = mgr_a.propose_create(members).unwrap();

        // Peer 1 applies
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        let wire = envelope.encode();
        let result = mgr_b.apply_control(&wire).unwrap();

        assert_eq!(result.group_id, gid);
        assert!(result.cipher.is_some());
        assert_eq!(result.epoch, 0);
        assert_eq!(mgr_b.members(&gid).unwrap().len(), 3);
    }

    #[test]
    fn apply_create_cross_encrypt() {
        let (mut mgr_a, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (_, mut cipher_a, envelope) = mgr_a.propose_create(members).unwrap();

        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        let result = mgr_b.apply_control(&envelope.encode()).unwrap();

        let mut cipher_b = result.cipher.unwrap();
        // A encrypts, B decrypts
        let ct = cipher_a.encrypt(b"from A").unwrap();
        assert_eq!(cipher_b.decrypt(&ct).unwrap(), b"from A");
        // B encrypts, A decrypts
        let ct = cipher_b.encrypt(b"from B").unwrap();
        assert_eq!(cipher_a.decrypt(&ct).unwrap(), b"from B");
    }

    // ─── propose_add ───

    #[test]
    fn propose_add_basic() {
        let (mut mgr, peers) = setup_manager(3);
        let new_peer = TestPeer::generate();
        mgr.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());

        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        let (cipher, envelope) = mgr.propose_add(&gid, &new_peer.peer_id).unwrap();
        assert_eq!(envelope.msg_type, GroupControlMessageType::GroupAdd);
        assert_eq!(envelope.epoch, 1);
        assert_eq!(mgr.members(&gid).unwrap().len(), 4);
        assert!(mgr.is_member(&gid, &new_peer.peer_id).unwrap());

        let mut c = cipher;
        let ct = c.encrypt(b"after add").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"after add");
    }

    #[test]
    fn propose_add_already_member_rejected() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        assert!(mgr.propose_add(&gid, &peers[1].peer_id).is_err());
    }

    // ─── propose_remove ───

    #[test]
    fn propose_remove_basic() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        let (cipher, envelope) = mgr.propose_remove(&gid, &peers[2].peer_id).unwrap();
        assert_eq!(envelope.msg_type, GroupControlMessageType::GroupRemove);
        assert_eq!(envelope.epoch, 1);
        assert_eq!(mgr.members(&gid).unwrap().len(), 2);
        assert!(!mgr.is_member(&gid, &peers[2].peer_id).unwrap());

        let mut c = cipher;
        let ct = c.encrypt(b"after remove").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"after remove");
    }

    #[test]
    fn propose_remove_nonmember_rejected() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        let outsider = TestPeer::generate();
        assert!(mgr.propose_remove(&gid, &outsider.peer_id).is_err());
    }

    // ─── propose_rekey ───

    #[test]
    fn propose_rekey_basic() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        let (cipher, envelope) = mgr.propose_rekey(&gid).unwrap();
        assert_eq!(envelope.msg_type, GroupControlMessageType::GroupRekey);
        assert_eq!(envelope.epoch, 1);

        let mut c = cipher;
        let ct = c.encrypt(b"rekeyed").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"rekeyed");
    }

    // ─── propose_dissolve ───

    #[test]
    fn propose_dissolve_basic() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        let envelope = mgr.propose_dissolve(&gid).unwrap();
        assert_eq!(envelope.msg_type, GroupControlMessageType::GroupDissolve);
        assert!(envelope.distribution.is_none());

        let info = mgr.group_info(&gid).unwrap();
        assert_eq!(info.status, GroupStatus::Dissolved);
    }

    #[test]
    fn propose_dissolved_rejects_operations() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();
        mgr.propose_dissolve(&gid).unwrap();

        assert!(mgr.propose_add(&gid, &peers[0].peer_id).is_err());
        assert!(mgr.propose_remove(&gid, &peers[1].peer_id).is_err());
        assert!(mgr.propose_rekey(&gid).is_err());
        assert!(mgr.propose_dissolve(&gid).is_err());
    }

    // ─── apply mutation (cross-node) ───

    #[test]
    fn apply_add_cross_node() {
        let (mut mgr_a, peers) = setup_manager(3);
        let new_peer = TestPeer::generate();
        mgr_a.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());

        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, create_env) = mgr_a.propose_create(members).unwrap();

        // Peer 1 joins
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        mgr_b.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());
        mgr_b.apply_control(&create_env.encode()).unwrap();

        // A adds new member
        let (_, add_env) = mgr_a.propose_add(&gid, &new_peer.peer_id).unwrap();

        // B applies the add
        let result = mgr_b.apply_control(&add_env.encode()).unwrap();
        assert_eq!(result.epoch, 1);
        assert_eq!(mgr_b.members(&gid).unwrap().len(), 4);
    }

    #[test]
    fn apply_dissolve_cross_node() {
        let (mut mgr_a, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, create_env) = mgr_a.propose_create(members).unwrap();

        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        mgr_b.apply_control(&create_env.encode()).unwrap();

        let dissolve_env = mgr_a.propose_dissolve(&gid).unwrap();
        let result = mgr_b.apply_control(&dissolve_env.encode()).unwrap();
        assert_eq!(result.epoch, 1);

        let info = mgr_b.group_info(&gid).unwrap();
        assert_eq!(info.status, GroupStatus::Dissolved);
    }

    #[test]
    fn apply_epoch_mismatch_rejected() {
        let (mut mgr_a, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, create_env) = mgr_a.propose_create(members).unwrap();

        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        mgr_b.apply_control(&create_env.encode()).unwrap();

        // Create a fake envelope with wrong epoch
        let (_, rekey_env) = mgr_a.propose_rekey(&gid).unwrap();
        let mut bad_bytes = rekey_env.encode();
        // Corrupt epoch field (bytes 2-9, LE u64) to wrong value
        bad_bytes[2] = 0xFF;

        assert!(mgr_b.apply_control(&bad_bytes).is_err());
    }

    #[test]
    fn apply_duplicate_create_rejected() {
        let (mut mgr_a, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (_, _, create_env) = mgr_a.propose_create(members).unwrap();

        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        mgr_b.apply_control(&create_env.encode()).unwrap();

        // Applying same create again should fail
        assert!(mgr_b.apply_control(&create_env.encode()).is_err());
    }

    // ─── Batch ───

    #[test]
    fn flush_pending_add() {
        let (mut mgr, peers) = setup_manager(3);
        let new_peer = TestPeer::generate();
        mgr.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());

        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        mgr.queue_add(&gid, new_peer.peer_id.clone()).unwrap();
        let (cipher, envelope) = mgr.flush_pending(&gid).unwrap();

        assert_eq!(envelope.epoch, 1);
        assert_eq!(mgr.members(&gid).unwrap().len(), 4);

        let mut c = cipher;
        let ct = c.encrypt(b"batch add").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"batch add");
    }

    #[test]
    fn flush_pending_remove() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        mgr.queue_remove(&gid, peers[2].peer_id.clone()).unwrap();
        let (cipher, _) = mgr.flush_pending(&gid).unwrap();

        assert_eq!(mgr.members(&gid).unwrap().len(), 2);

        let mut c = cipher;
        let ct = c.encrypt(b"batch remove").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"batch remove");
    }

    #[test]
    fn flush_pending_empty_rejected() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        assert!(mgr.flush_pending(&gid).is_err());
    }

    // ─── Acknowledgment ───

    #[test]
    fn ack_tracking_full() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        let e = mgr.epoch(&gid).unwrap();

        // Initially all pending
        let pending = mgr.pending_acks(&gid).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, e);
        assert_eq!(pending[0].1.len(), 3);

        // Ack two
        mgr.acknowledge(&gid, e, &peers[0].peer_id).unwrap();
        mgr.acknowledge(&gid, e, &peers[1].peer_id).unwrap();

        let pending = mgr.pending_acks(&gid).unwrap();
        assert_eq!(pending[0].1.len(), 1);

        // Ack last
        mgr.acknowledge(&gid, e, &peers[2].peer_id).unwrap();
        let pending = mgr.pending_acks(&gid).unwrap();
        assert!(pending.is_empty());
    }

    // ─── Replay ───

    #[test]
    fn replay_detection() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        assert!(mgr.check_replay(&gid, [0xaa; 32], 0).is_ok());
        assert!(mgr.check_replay(&gid, [0xaa; 32], 1).is_ok());
        assert!(mgr.check_replay(&gid, [0xbb; 32], 0).is_ok());
        // Duplicate rejected
        assert!(mgr.check_replay(&gid, [0xaa; 32], 0).is_err());
    }

    // ─── Query ───

    #[test]
    fn query_nonexistent_group() {
        let (mgr, _) = setup_manager(1);
        let fake = GroupId::from_bytes([0xff; 32]);
        assert!(mgr.members(&fake).is_err());
        assert!(mgr.epoch(&fake).is_err());
        assert!(mgr.group_info(&fake).is_err());
    }

    #[test]
    fn group_info_snapshot() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        let info = mgr.group_info(&gid).unwrap();
        assert_eq!(info.epoch, 0);
        assert_eq!(info.members.len(), 3);
        assert_eq!(info.status, GroupStatus::Active);
    }

    // ─── Full lifecycle ───

    #[test]
    fn full_lifecycle_flow() {
        let (mut mgr_a, peers) = setup_manager(3);
        let new_peer = TestPeer::generate();
        mgr_a.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());

        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();

        // Create
        let (gid, mut cipher_a, create_env) = mgr_a.propose_create(members).unwrap();

        // B joins
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        mgr_b.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());
        let result_b = mgr_b.apply_control(&create_env.encode()).unwrap();
        let cipher_b = result_b.cipher.unwrap();

        // Cross-encrypt
        let ct = cipher_a.encrypt(b"hello B").unwrap();
        assert_eq!(cipher_b.decrypt(&ct).unwrap(), b"hello B");

        // Add member
        let (_, add_env) = mgr_a.propose_add(&gid, &new_peer.peer_id).unwrap();
        mgr_b.apply_control(&add_env.encode()).unwrap();
        assert_eq!(mgr_b.members(&gid).unwrap().len(), 4);

        // Remove member
        let (_, rm_env) = mgr_a.propose_remove(&gid, &peers[2].peer_id).unwrap();
        mgr_b.apply_control(&rm_env.encode()).unwrap();
        assert_eq!(mgr_b.members(&gid).unwrap().len(), 3);

        // Rekey
        let (_, rekey_env) = mgr_a.propose_rekey(&gid).unwrap();
        let result_b = mgr_b.apply_control(&rekey_env.encode()).unwrap();
        let _cipher_b = result_b.cipher.unwrap();
        assert_eq!(mgr_b.epoch(&gid).unwrap(), 3);

        // Dissolve
        let dissolve_env = mgr_a.propose_dissolve(&gid).unwrap();
        mgr_b.apply_control(&dissolve_env.encode()).unwrap();
        assert_eq!(
            mgr_b.group_info(&gid).unwrap().status,
            GroupStatus::Dissolved
        );
    }

    // ─── Stress ───

    #[test]
    fn stress_rapid_propose_apply() {
        let (mut mgr_a, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, create_env) = mgr_a.propose_create(members).unwrap();

        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        mgr_b.apply_control(&create_env.encode()).unwrap();

        for i in 0..20 {
            let (_, rekey_env) = mgr_a.propose_rekey(&gid).unwrap();
            let result = mgr_b.apply_control(&rekey_env.encode()).unwrap();
            assert_eq!(result.epoch, (i + 1) as u64);
        }
        assert_eq!(mgr_a.epoch(&gid).unwrap(), 20);
        assert_eq!(mgr_b.epoch(&gid).unwrap(), 20);
    }

    #[test]
    fn stress_many_members() {
        let n = 15;
        let (mut mgr, peers) = setup_manager(n);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher, _) = mgr.propose_create(members).unwrap();
        assert_eq!(mgr.members(&gid).unwrap().len(), n);

        let ct = cipher.encrypt(b"big group").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"big group");
    }

    #[test]
    fn stress_batch_churn() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        for _ in 0..10 {
            let new_peer = TestPeer::generate();
            mgr.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());
            mgr.queue_add(&gid, new_peer.peer_id.clone()).unwrap();
            let (cipher, _) = mgr.flush_pending(&gid).unwrap();
            let mut c = cipher;
            let ct = c.encrypt(b"after batch add").unwrap();
            assert_eq!(c.decrypt(&ct).unwrap(), b"after batch add");

            mgr.queue_remove(&gid, new_peer.peer_id.clone()).unwrap();
            let (cipher, _) = mgr.flush_pending(&gid).unwrap();
            let mut c = cipher;
            let ct = c.encrypt(b"after batch rm").unwrap();
            assert_eq!(c.decrypt(&ct).unwrap(), b"after batch rm");
        }
    }

    #[test]
    fn stress_replay_under_load() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        for i in 0..100u64 {
            assert!(mgr.check_replay(&gid, [0xaa; 32], i).is_ok());
        }
        assert!(mgr.check_replay(&gid, [0xaa; 32], 50).is_err());
    }

    // ─── Additional edge case tests ───

    #[test]
    fn apply_welcome_type_works_like_create() {
        let (mut mgr_a, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, mut create_env) = mgr_a.propose_create(members).unwrap();

        // Change type to GroupWelcome — should be accepted identically
        create_env.msg_type = GroupControlMessageType::GroupWelcome;
        let wire = create_env.encode();
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        let result = mgr_b.apply_control(&wire).unwrap();
        assert_eq!(result.group_id, gid);
        assert!(result.cipher.is_some());
        assert_eq!(mgr_b.members(&gid).unwrap().len(), 3);
        assert_eq!(mgr_b.epoch(&gid).unwrap(), 0);

        // Verify cipher works
        let mut cipher = result.cipher.unwrap();
        let ct = cipher.encrypt(b"welcome test").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"welcome test");
    }

    #[test]
    fn apply_mutation_missing_distribution_rejected() {
        let (mut mgr_a, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr_a.propose_create(members).unwrap();

        // Build a GroupAdd envelope without distribution payload
        let envelope = GroupControlEnvelope {
            msg_type: GroupControlMessageType::GroupAdd,
            epoch: 1,
            group_id: gid.clone(),
            proposer_id: peers[0].peer_id.clone(),
            distribution: None,
        };
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        let result = mgr_b.apply_envelope(&envelope);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("distribution payload"));
    }

    #[test]
    fn apply_create_missing_distribution_rejected() {
        let (_, peers) = setup_manager(3);
        let gid = GroupId::from_bytes([0x99; 32]);
        let envelope = GroupControlEnvelope {
            msg_type: GroupControlMessageType::GroupCreate,
            epoch: 0,
            group_id: gid,
            proposer_id: peers[0].peer_id.clone(),
            distribution: None,
        };
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        let result = mgr_b.apply_envelope(&envelope);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("distribution payload"));
    }

    #[test]
    fn acknowledge_non_member_rejected() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        let outsider = PeerId::from_bytes([0xFF; 32]);
        let result = mgr.acknowledge(&gid, 0, &outsider);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GroupLifecycleError::MemberNotFound
        ));
    }

    #[test]
    fn check_replay_nonexistent_group() {
        let (_, _) = setup_manager(2);
        let (mut mgr, _) = setup_manager(1);
        let gid = GroupId::from_bytes([0xEE; 32]);
        let result = mgr.check_replay(&gid, [0x01; 32], 1);
        assert!(matches!(
            result.unwrap_err(),
            GroupLifecycleError::GroupNotFound
        ));
    }

    #[test]
    fn propose_batch_mixed_add_remove() {
        let (mut mgr, peers) = setup_manager(5);
        let members: Vec<PeerId> = peers[0..4].iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        let new_peer = &peers[4];
        let remove_peer = &peers[3];
        let result = mgr.propose_batch(
            &gid,
            &[new_peer.peer_id.clone()],
            &[remove_peer.peer_id.clone()],
        );
        assert!(result.is_ok());

        let (mut cipher, envelope) = result.unwrap();
        assert_eq!(envelope.msg_type, GroupControlMessageType::GroupRekey);
        assert_eq!(envelope.epoch, 1);

        // Members should now be [0,1,2,4] — 3 removed, 4 added
        let current_members = mgr.members(&gid).unwrap();
        assert_eq!(current_members.len(), 4);
        assert!(current_members.contains(&peers[0].peer_id));
        assert!(!current_members.contains(&peers[3].peer_id));
        assert!(current_members.contains(&peers[4].peer_id));

        // Cipher should work
        let ct = cipher.encrypt(b"batch test").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"batch test");
    }

    #[test]
    fn propose_batch_applied_cross_node() {
        let (mut mgr_a, peers) = setup_manager(4);
        let members: Vec<PeerId> = peers[0..3].iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, create_env) = mgr_a.propose_create(members).unwrap();

        let new_peer = &peers[3];
        let (mut cipher_a, batch_env) = mgr_a
            .propose_batch(&gid, &[new_peer.peer_id.clone()], &[])
            .unwrap();

        // B applies create then batch
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        let _ = mgr_b.apply_control(&create_env.encode()).unwrap();
        let result_b = mgr_b.apply_control(&batch_env.encode()).unwrap();
        assert!(result_b.cipher.is_some());
        assert_eq!(mgr_b.members(&gid).unwrap().len(), 4);

        // Cross-encrypt
        let ct = cipher_a.encrypt(b"batch cross").unwrap();
        let cipher_b = result_b.cipher.unwrap();
        assert_eq!(cipher_b.decrypt(&ct).unwrap(), b"batch cross");
    }

    #[test]
    fn flush_pending_mixed_adds_and_removes() {
        let (mut mgr, peers) = setup_manager(5);
        let members: Vec<PeerId> = peers[0..4].iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        mgr.queue_add(&gid, peers[4].peer_id.clone()).unwrap();
        mgr.queue_remove(&gid, peers[3].peer_id.clone()).unwrap();

        let (mut cipher, envelope) = mgr.flush_pending(&gid).unwrap();
        assert_eq!(envelope.epoch, 1);
        let current = mgr.members(&gid).unwrap();
        assert_eq!(current.len(), 4);
        assert!(current.contains(&peers[4].peer_id));
        assert!(!current.contains(&peers[3].peer_id));

        let ct = cipher.encrypt(b"mixed flush").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"mixed flush");
    }

    #[test]
    fn dissolved_group_query_returns_dissolved() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();
        mgr.propose_dissolve(&gid).unwrap();

        let info = mgr.group_info(&gid).unwrap();
        assert_eq!(info.status, GroupStatus::Dissolved);
        assert_eq!(info.epoch, 1);
    }

    #[test]
    fn propose_on_pending_conflicts() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        // Queue a pending add
        mgr.queue_add(&gid, PeerId::from_bytes([0xBB; 32])).unwrap();

        // Propose add should conflict
        let result = mgr.propose_add(&gid, &PeerId::from_bytes([0xCC; 32]));
        assert!(matches!(
            result.unwrap_err(),
            GroupLifecycleError::ProposalConflict
        ));

        // Propose remove should also conflict
        let result = mgr.propose_remove(&gid, &peers[1].peer_id);
        assert!(matches!(
            result.unwrap_err(),
            GroupLifecycleError::ProposalConflict
        ));

        // Propose rekey should also conflict
        let result = mgr.propose_rekey(&gid);
        assert!(matches!(
            result.unwrap_err(),
            GroupLifecycleError::ProposalConflict
        ));
    }

    #[test]
    fn apply_mutation_on_dissolved_rejected() {
        let (mut mgr_a, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, create_env) = mgr_a.propose_create(members).unwrap();

        // Dissolve at epoch 1
        let dissolve_env = mgr_a.propose_dissolve(&gid).unwrap();

        // B applies create (epoch 0) then dissolve (epoch 1)
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        let _ = mgr_b.apply_control(&create_env.encode()).unwrap();
        mgr_b.apply_control(&dissolve_env.encode()).unwrap();

        // B tries to apply create again — should fail (group already exists, dissolved)
        let result = mgr_b.apply_control(&create_env.encode());
        assert!(result.is_err());
    }

    #[test]
    fn register_member_pk_delegation_works() {
        let (mut mgr, _) = setup_manager(1);
        let peer = TestPeer::generate();
        mgr.register_member_pk(peer.peer_id.clone(), peer.hybrid_pk.clone());

        // Should be able to add this peer to a group
        let (gid, _, _) = mgr.propose_create(vec![mgr.my_peer_id.clone()]).unwrap();
        let result = mgr.propose_add(&gid, &peer.peer_id);
        assert!(result.is_ok());
    }

    #[test]
    fn pending_acks_returns_all_epochs() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        // All 3 members are pending at epoch 0
        let acks = mgr.pending_acks(&gid).unwrap();
        assert_eq!(acks.len(), 1);
        assert_eq!(acks[0].0, 0);
        assert_eq!(acks[0].1.len(), 3); // all 3 unacked

        // Ack epoch 0 with member 1 — now 2 pending
        mgr.acknowledge(&gid, 0, &peers[1].peer_id).unwrap();
        let acks = mgr.pending_acks(&gid).unwrap();
        assert_eq!(acks[0].1.len(), 2); // member 0 and 2 still pending
        assert!(!acks[0].1.iter().any(|m| m == peers[1].peer_id.as_bytes()));
    }

    #[test]
    fn stress_1000_epochs() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.propose_create(members).unwrap();

        for i in 0..1000 {
            let (_, env) = mgr.propose_rekey(&gid).unwrap();
            assert_eq!(env.epoch, i as u64 + 1);
        }
        assert_eq!(mgr.epoch(&gid).unwrap(), 1000);
    }

    #[test]
    fn large_group_lifecycle_50_members() {
        let (mut mgr, peers) = setup_manager(50);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher, create_env) = mgr.propose_create(members.clone()).unwrap();

        // Apply on receiver
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        let _result = mgr_b.apply_control(&create_env.encode()).unwrap();
        assert_eq!(mgr_b.members(&gid).unwrap().len(), 50);

        // Remove 10 members
        for i in 10..20 {
            let (_, env) = mgr.propose_remove(&gid, &peers[i].peer_id).unwrap();
            mgr_b.apply_control(&env.encode()).unwrap();
        }
        assert_eq!(mgr.members(&gid).unwrap().len(), 40);
        assert_eq!(mgr_b.members(&gid).unwrap().len(), 40);

        // Cross-encrypt still works
        let ct = cipher.encrypt(b"large group msg").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"large group msg");
    }

    #[test]
    fn apply_wrong_epoch_stale_rejected() {
        let (mut mgr_a, peers) = setup_manager(4);
        let members: Vec<PeerId> = peers[0..3].iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, create_env) = mgr_a.propose_create(members).unwrap();

        // Create an add at epoch 1
        let (_, add_env) = mgr_a.propose_add(&gid, &peers[3].peer_id).unwrap();

        // B applies create then add — now at epoch 1
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        mgr_b.apply_control(&create_env.encode()).unwrap();
        mgr_b.apply_control(&add_env.encode()).unwrap();

        // Replay the same epoch 1 message — should fail (now expects epoch 2)
        let result = mgr_b.apply_control(&add_env.encode());
        assert!(matches!(
            result.unwrap_err(),
            GroupLifecycleError::EpochMismatch { .. }
        ));
    }

    #[test]
    fn apply_create_wrong_version_rejected() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (_, _, envelope) = mgr.propose_create(members).unwrap();
        let mut bytes = envelope.encode();
        // Corrupt version byte
        bytes[0] = 0x99;
        let mut mgr_b = make_joiner_mgr(&peers[1], &peers);
        assert!(mgr_b.apply_control(&bytes).is_err());
    }
}
