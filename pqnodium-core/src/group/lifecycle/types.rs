use crate::group::sender_key::SenderKeyDistributionPayload;
use crate::group::types::GroupId;
use crate::identity::PeerId;

use super::error::GroupLifecycleError;

/// Control message type byte range 0x20-0x2F (following `MessageType` in message.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupControlMessageType {
    GroupCreate = 0x20,
    GroupWelcome = 0x21,
    GroupAdd = 0x22,
    GroupRemove = 0x23,
    GroupRekey = 0x24,
    GroupDissolve = 0x25,
}

impl GroupControlMessageType {
    /// Convert to the wire byte value.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for GroupControlMessageType {
    type Error = GroupLifecycleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x20 => Ok(Self::GroupCreate),
            0x21 => Ok(Self::GroupWelcome),
            0x22 => Ok(Self::GroupAdd),
            0x23 => Ok(Self::GroupRemove),
            0x24 => Ok(Self::GroupRekey),
            0x25 => Ok(Self::GroupDissolve),
            _ => Err(GroupLifecycleError::UnknownControlType(value)),
        }
    }
}

/// Lifecycle status of a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupStatus {
    Active,
    Dissolved,
}

/// Outer wire format for all group control messages.
///
/// ```text
/// [version:1][msg_type:1][epoch:8 LE][group_id:32][proposer_id:32]
/// [has_distribution:1]
///   if 0x01: [distribution_len:4 BE][distribution_bytes:N]
/// ```
#[derive(Debug, Clone)]
pub struct GroupControlEnvelope {
    pub msg_type: GroupControlMessageType,
    pub epoch: u64,
    pub group_id: GroupId,
    pub proposer_id: PeerId,
    pub distribution: Option<SenderKeyDistributionPayload>,
}

/// Snapshot of group state returned by query API.
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub group_id: GroupId,
    pub epoch: u64,
    pub members: Vec<PeerId>,
    pub status: GroupStatus,
}

/// Result of applying a control message.
#[derive(Debug)]
pub struct ApplyResult {
    pub group_id: GroupId,
    pub cipher: Option<crate::group::sender_key::SenderKeyCipher>,
    pub epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_type_to_byte() {
        assert_eq!(GroupControlMessageType::GroupCreate.to_byte(), 0x20);
        assert_eq!(GroupControlMessageType::GroupWelcome.to_byte(), 0x21);
        assert_eq!(GroupControlMessageType::GroupAdd.to_byte(), 0x22);
        assert_eq!(GroupControlMessageType::GroupRemove.to_byte(), 0x23);
        assert_eq!(GroupControlMessageType::GroupRekey.to_byte(), 0x24);
        assert_eq!(GroupControlMessageType::GroupDissolve.to_byte(), 0x25);
    }

    #[test]
    fn control_type_try_from_valid() {
        assert_eq!(
            GroupControlMessageType::try_from(0x20).unwrap(),
            GroupControlMessageType::GroupCreate
        );
        assert_eq!(
            GroupControlMessageType::try_from(0x25).unwrap(),
            GroupControlMessageType::GroupDissolve
        );
    }

    #[test]
    fn control_type_try_from_invalid() {
        assert!(GroupControlMessageType::try_from(0x00).is_err());
        assert!(GroupControlMessageType::try_from(0x19).is_err());
        assert!(GroupControlMessageType::try_from(0x26).is_err());
        assert!(GroupControlMessageType::try_from(0xFF).is_err());
    }

    #[test]
    fn group_status_equality() {
        assert_eq!(GroupStatus::Active, GroupStatus::Active);
        assert_ne!(GroupStatus::Active, GroupStatus::Dissolved);
    }

    #[test]
    fn control_type_roundtrip_all() {
        for byte in 0x20u8..=0x25 {
            let ct = GroupControlMessageType::try_from(byte).unwrap();
            assert_eq!(ct.to_byte(), byte);
        }
    }

    #[test]
    fn group_info_fields() {
        let gid = GroupId::from_bytes([0x42; 32]);
        let info = GroupInfo {
            group_id: gid.clone(),
            epoch: 5,
            members: vec![PeerId::from_bytes([0x01; 32])],
            status: GroupStatus::Active,
        };
        assert_eq!(info.group_id, gid);
        assert_eq!(info.epoch, 5);
        assert_eq!(info.members.len(), 1);
        assert_eq!(info.members[0], PeerId::from_bytes([0x01; 32]));
        assert_eq!(info.status, GroupStatus::Active);
    }

    #[test]
    fn group_info_dissolved_status() {
        let info = GroupInfo {
            group_id: GroupId::from_bytes([0x42; 32]),
            epoch: 0,
            members: vec![],
            status: GroupStatus::Dissolved,
        };
        assert_eq!(info.status, GroupStatus::Dissolved);
    }

    #[test]
    fn apply_result_without_cipher() {
        let gid = GroupId::from_bytes([0x42; 32]);
        let result = ApplyResult {
            group_id: gid.clone(),
            cipher: None,
            epoch: 3,
        };
        assert_eq!(result.group_id, gid);
        assert!(result.cipher.is_none());
        assert_eq!(result.epoch, 3);
    }

    #[test]
    fn apply_result_with_cipher() {
        let gid = GroupId::from_bytes([0x42; 32]);
        let result = ApplyResult {
            group_id: gid.clone(),
            cipher: None,
            epoch: 3,
        };
        assert!(result.cipher.is_none());
    }

    #[test]
    fn group_status_debug() {
        assert_eq!(format!("{:?}", GroupStatus::Active), "Active");
        assert_eq!(format!("{:?}", GroupStatus::Dissolved), "Dissolved");
    }

    #[test]
    fn group_status_copy() {
        let s = GroupStatus::Active;
        let _s2 = s;
        assert_eq!(s, GroupStatus::Active);
    }

    #[test]
    fn group_control_message_type_boundary() {
        assert!(GroupControlMessageType::try_from(0x1F).is_err());
        assert!(GroupControlMessageType::try_from(0x30).is_err());
    }
}
