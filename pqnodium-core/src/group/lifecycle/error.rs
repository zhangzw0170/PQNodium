use crate::group::sender_key::error::SenderKeyError;

/// Errors from group lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum GroupLifecycleError {
    #[error("group not found")]
    GroupNotFound,

    #[error("group already dissolved")]
    GroupDissolved,

    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidTransition {
        from: super::types::GroupStatus,
        to: super::types::GroupStatus,
    },

    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    #[error("replay detected: sender at chain step {chain_step}")]
    ReplayDetected { chain_step: u64 },

    #[error("member not found")]
    MemberNotFound,

    #[error("already a member")]
    AlreadyMember,

    #[error("not a member")]
    NotMember,

    #[error("proposal conflicts with pending changes")]
    ProposalConflict,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("payload too short: expected {expected}, got {got}")]
    PayloadTooShort { expected: usize, got: usize },

    #[error("unknown control message type: 0x{0:02x}")]
    UnknownControlType(u8),

    #[error("trailing data: {actual} bytes, consumed {consumed}")]
    TrailingData { actual: usize, consumed: usize },

    #[error("unknown payload version: {0}")]
    UnknownPayloadVersion(u8),

    #[error("no pending changes to flush")]
    NoPendingChanges,

    #[error("sender key error: {0}")]
    SenderKey(#[from] SenderKeyError),
}

#[cfg(test)]
mod tests {
    use super::super::types::GroupStatus;
    use super::*;
    use crate::group::sender_key::error::SenderKeyError;

    #[test]
    fn display_group_not_found() {
        assert_eq!(
            GroupLifecycleError::GroupNotFound.to_string(),
            "group not found"
        );
    }

    #[test]
    fn display_group_dissolved() {
        assert_eq!(
            GroupLifecycleError::GroupDissolved.to_string(),
            "group already dissolved"
        );
    }

    #[test]
    fn display_invalid_transition() {
        let err = GroupLifecycleError::InvalidTransition {
            from: GroupStatus::Active,
            to: GroupStatus::Dissolved,
        };
        let msg = err.to_string();
        assert!(msg.contains("Active"));
        assert!(msg.contains("Dissolved"));
    }

    #[test]
    fn display_epoch_mismatch() {
        let err = GroupLifecycleError::EpochMismatch {
            expected: 5,
            got: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn display_replay_detected() {
        let err = GroupLifecycleError::ReplayDetected { chain_step: 42 };
        let msg = err.to_string();
        assert!(msg.contains("42"));
    }

    #[test]
    fn display_payload_too_short() {
        let err = GroupLifecycleError::PayloadTooShort {
            expected: 75,
            got: 10,
        };
        let msg = err.to_string();
        assert!(msg.contains("75"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn display_trailing_data() {
        let err = GroupLifecycleError::TrailingData {
            actual: 100,
            consumed: 75,
        };
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("75"));
    }

    #[test]
    fn display_unknown_control_type() {
        let err = GroupLifecycleError::UnknownControlType(0x99);
        let msg = err.to_string();
        assert!(msg.contains("0x99"));
    }

    #[test]
    fn display_unknown_payload_version() {
        let err = GroupLifecycleError::UnknownPayloadVersion(0x05);
        assert_eq!(err.to_string(), "unknown payload version: 5");
    }

    #[test]
    fn display_member_errors() {
        assert_eq!(
            GroupLifecycleError::MemberNotFound.to_string(),
            "member not found"
        );
        assert_eq!(
            GroupLifecycleError::AlreadyMember.to_string(),
            "already a member"
        );
        assert_eq!(GroupLifecycleError::NotMember.to_string(), "not a member");
    }

    #[test]
    fn display_proposal_conflict() {
        assert_eq!(
            GroupLifecycleError::ProposalConflict.to_string(),
            "proposal conflicts with pending changes"
        );
    }

    #[test]
    fn display_no_pending_changes() {
        assert_eq!(
            GroupLifecycleError::NoPendingChanges.to_string(),
            "no pending changes to flush"
        );
    }

    #[test]
    fn display_serialization() {
        let err = GroupLifecycleError::Serialization("bad data".into());
        let msg = err.to_string();
        assert!(msg.contains("bad data"));
    }

    #[test]
    fn from_sender_key_group_not_found() {
        let sk_err = SenderKeyError::GroupNotFound;
        let lc_err: GroupLifecycleError = sk_err.into();
        let msg = lc_err.to_string();
        assert!(msg.contains("sender key error"));
        assert!(msg.contains("group not found"));
    }

    #[test]
    fn from_sender_key_decryption_failed() {
        let sk_err = SenderKeyError::DecryptionFailed;
        let lc_err: GroupLifecycleError = sk_err.into();
        assert!(matches!(lc_err, GroupLifecycleError::SenderKey(_)));
    }

    #[test]
    fn from_sender_key_chain_step_exceeded() {
        let sk_err = SenderKeyError::ChainStepExceeded {
            step: 999999,
            max: 100,
        };
        let lc_err: GroupLifecycleError = sk_err.into();
        let msg = lc_err.to_string();
        assert!(msg.contains("999999"));
    }
}
