use std::collections::{HashMap, HashSet};

use crate::identity::PeerId;

use super::error::GroupLifecycleError;
use super::types::GroupStatus;

/// Internal lifecycle state tracked per group.
pub(crate) struct LifecycleGroupState {
    pub epoch: u64,
    pub status: GroupStatus,
    pub members: Vec<PeerId>,
    pub seen_replay: HashSet<([u8; 32], u64)>,
    pub ack_tracker: HashMap<u64, HashSet<[u8; 32]>>,
    pub pending_adds: Vec<PeerId>,
    pub pending_removes: Vec<PeerId>,
}

impl LifecycleGroupState {
    /// Create a new lifecycle state for a freshly created group.
    pub fn new(members: Vec<PeerId>) -> Self {
        Self {
            epoch: 0,
            status: GroupStatus::Active,
            members,
            seen_replay: HashSet::new(),
            ack_tracker: HashMap::new(),
            pending_adds: Vec::new(),
            pending_removes: Vec::new(),
        }
    }

    /// Increment epoch and return the new value.
    pub fn advance_epoch(&mut self) -> u64 {
        self.epoch += 1;
        self.epoch
    }

    /// Record a replay entry. Returns error if already seen.
    pub fn record_replay(
        &mut self,
        sender_id: [u8; 32],
        chain_step: u64,
    ) -> Result<(), GroupLifecycleError> {
        if self.seen_replay.contains(&(sender_id, chain_step)) {
            return Err(GroupLifecycleError::ReplayDetected { chain_step });
        }
        self.seen_replay.insert((sender_id, chain_step));
        Ok(())
    }

    /// Record an ack from a member for a given epoch.
    pub fn record_ack(&mut self, epoch: u64, member: [u8; 32]) {
        self.ack_tracker.entry(epoch).or_default().insert(member);
    }

    /// Return member IDs that have not yet acked for the given epoch.
    pub fn pending_acks_for_epoch(&self, epoch: u64) -> Vec<[u8; 32]> {
        let acked = self.ack_tracker.get(&epoch);
        self.members
            .iter()
            .filter(|m| acked.is_none_or(|set| !set.contains(m.as_bytes())))
            .map(|m| *m.as_bytes())
            .collect()
    }

    /// Whether the group is still active.
    pub fn is_active(&self) -> bool {
        self.status == GroupStatus::Active
    }

    /// Require the group to be active, returning error otherwise.
    pub fn require_active(&self) -> Result<(), GroupLifecycleError> {
        if !self.is_active() {
            return Err(GroupLifecycleError::GroupDissolved);
        }
        Ok(())
    }

    /// Queue a member for batch addition.
    pub fn queue_add(&mut self, member: PeerId) -> Result<(), GroupLifecycleError> {
        self.require_active()?;
        if self.members.contains(&member) || self.pending_adds.contains(&member) {
            return Err(GroupLifecycleError::AlreadyMember);
        }
        self.pending_adds.push(member);
        Ok(())
    }

    /// Queue a member for batch removal.
    pub fn queue_remove(&mut self, member: PeerId) -> Result<(), GroupLifecycleError> {
        self.require_active()?;
        if !self.members.contains(&member) || self.pending_removes.contains(&member) {
            return Err(GroupLifecycleError::NotMember);
        }
        self.pending_removes.push(member);
        Ok(())
    }

    /// Drain all pending adds and removes.
    pub fn drain_pending(&mut self) -> (Vec<PeerId>, Vec<PeerId>) {
        let adds = std::mem::take(&mut self.pending_adds);
        let removes = std::mem::take(&mut self.pending_removes);
        (adds, removes)
    }

    /// Whether there are pending batch operations.
    pub fn has_pending(&self) -> bool {
        !self.pending_adds.is_empty() || !self.pending_removes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    fn test_state(n_members: usize) -> LifecycleGroupState {
        let members: Vec<PeerId> = (0..n_members).map(|i| test_peer(i as u8)).collect();
        LifecycleGroupState::new(members)
    }

    #[test]
    fn new_state_has_epoch_zero() {
        let state = test_state(3);
        assert_eq!(state.epoch, 0);
        assert!(state.is_active());
        assert_eq!(state.members.len(), 3);
    }

    #[test]
    fn advance_epoch_increments() {
        let mut state = test_state(1);
        assert_eq!(state.advance_epoch(), 1);
        assert_eq!(state.advance_epoch(), 2);
        assert_eq!(state.epoch, 2);
    }

    // ─── Replay ───

    #[test]
    fn replay_new_entry_accepted() {
        let mut state = test_state(1);
        assert!(state.record_replay([0xaa; 32], 0).is_ok());
        assert!(state.record_replay([0xaa; 32], 1).is_ok());
        assert!(state.record_replay([0xbb; 32], 0).is_ok());
    }

    #[test]
    fn replay_duplicate_rejected() {
        let mut state = test_state(1);
        state.record_replay([0xaa; 32], 5).unwrap();
        assert!(state.record_replay([0xaa; 32], 5).is_err());
    }

    // ─── Ack ───

    #[test]
    fn ack_tracking() {
        let mut state = test_state(3);
        let epoch = state.advance_epoch();

        // Initially all 3 members have pending acks
        let pending = state.pending_acks_for_epoch(epoch);
        assert_eq!(pending.len(), 3);

        // Ack member 0
        state.record_ack(epoch, *test_peer(0).as_bytes());
        let pending = state.pending_acks_for_epoch(epoch);
        assert_eq!(pending.len(), 2);

        // Ack remaining
        state.record_ack(epoch, *test_peer(1).as_bytes());
        state.record_ack(epoch, *test_peer(2).as_bytes());
        let pending = state.pending_acks_for_epoch(epoch);
        assert!(pending.is_empty());
    }

    #[test]
    fn ack_per_epoch_independent() {
        let mut state = test_state(2);
        let e1 = state.advance_epoch();
        let e2 = state.advance_epoch();

        state.record_ack(e1, *test_peer(0).as_bytes());
        assert_eq!(state.pending_acks_for_epoch(e1).len(), 1);
        assert_eq!(state.pending_acks_for_epoch(e2).len(), 2);
    }

    // ─── Status ───

    #[test]
    fn dissolved_state_rejects_operations() {
        let mut state = test_state(1);
        state.status = GroupStatus::Dissolved;
        assert!(state.require_active().is_err());
        assert!(state.queue_add(test_peer(99)).is_err());
        assert!(state.queue_remove(test_peer(0)).is_err());
    }

    // ─── Pending batch ───

    #[test]
    fn queue_add_valid() {
        let mut state = test_state(2);
        assert!(state.queue_add(test_peer(99)).is_ok());
        assert!(state.has_pending());
        assert_eq!(state.pending_adds.len(), 1);
    }

    #[test]
    fn queue_add_duplicate_rejected() {
        let mut state = test_state(2);
        assert!(state.queue_add(test_peer(99)).is_ok());
        assert!(state.queue_add(test_peer(99)).is_err());
    }

    #[test]
    fn queue_add_existing_member_rejected() {
        let mut state = test_state(2);
        assert!(state.queue_add(test_peer(0)).is_err());
    }

    #[test]
    fn queue_remove_valid() {
        let mut state = test_state(2);
        assert!(state.queue_remove(test_peer(0)).is_ok());
        assert!(state.has_pending());
    }

    #[test]
    fn queue_remove_nonmember_rejected() {
        let mut state = test_state(2);
        assert!(state.queue_remove(test_peer(99)).is_err());
    }

    #[test]
    fn queue_remove_duplicate_rejected() {
        let mut state = test_state(2);
        assert!(state.queue_remove(test_peer(0)).is_ok());
        assert!(state.queue_remove(test_peer(0)).is_err());
    }

    #[test]
    fn drain_pending_clears() {
        let mut state = test_state(3);
        state.queue_add(test_peer(10)).unwrap();
        state.queue_remove(test_peer(0)).unwrap();
        let (adds, removes) = state.drain_pending();
        assert_eq!(adds.len(), 1);
        assert_eq!(removes.len(), 1);
        assert!(!state.has_pending());
    }

    #[test]
    fn drain_pending_empty() {
        let mut state = test_state(1);
        let (adds, removes) = state.drain_pending();
        assert!(adds.is_empty());
        assert!(removes.is_empty());
    }

    #[test]
    fn has_pending_false_initially() {
        let state = test_state(1);
        assert!(!state.has_pending());
    }
}
