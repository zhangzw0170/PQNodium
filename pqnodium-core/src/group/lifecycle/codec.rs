use crate::group::sender_key::SenderKeyDistributionPayload;
use crate::group::types::GroupId;
use crate::identity::PeerId;

use super::error::GroupLifecycleError;
use super::types::GroupControlEnvelope;

const ENVELOPE_VERSION: u8 = 0x01;
const PAYLOAD_VERSION: u8 = 0x01;

// Min sizes for validation
const ENVELOPE_MIN_SIZE: usize = 1 + 1 + 8 + 32 + 32 + 1; // 75
const PAYLOAD_MIN_SIZE: usize = 1 + 32 + 4 + 4; // 41

impl GroupControlEnvelope {
    /// Encode to binary wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.push(ENVELOPE_VERSION);
        buf.push(self.msg_type.to_byte());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(self.group_id.as_bytes());
        buf.extend_from_slice(self.proposer_id.as_bytes());

        if let Some(ref dist) = self.distribution {
            buf.push(0x01);
            let dist_bytes = dist.encode();
            buf.extend_from_slice(&(dist_bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(&dist_bytes);
        } else {
            buf.push(0x00);
        }

        buf
    }

    /// Decode from binary wire format.
    pub fn decode(data: &[u8]) -> Result<Self, GroupLifecycleError> {
        if data.len() < ENVELOPE_MIN_SIZE {
            return Err(GroupLifecycleError::PayloadTooShort {
                expected: ENVELOPE_MIN_SIZE,
                got: data.len(),
            });
        }

        let version = data[0];
        if version != ENVELOPE_VERSION {
            return Err(GroupLifecycleError::UnknownPayloadVersion(version));
        }

        let msg_type = super::types::GroupControlMessageType::try_from(data[1])?;
        let epoch = u64::from_le_bytes(data[2..10].try_into().unwrap());
        let group_id = GroupId::from_bytes(data[10..42].try_into().unwrap());
        let proposer_id = PeerId::from_bytes(data[42..74].try_into().unwrap());

        let has_distribution = data[74];
        let (distribution, consumed) = if has_distribution == 0x01 {
            if data.len() < 75 + 4 {
                return Err(GroupLifecycleError::PayloadTooShort {
                    expected: 75 + 4,
                    got: data.len(),
                });
            }
            let dist_len = u32::from_be_bytes(data[75..79].try_into().unwrap()) as usize;
            if data.len() < 79 + dist_len {
                return Err(GroupLifecycleError::PayloadTooShort {
                    expected: 79 + dist_len,
                    got: data.len(),
                });
            }
            let dist = SenderKeyDistributionPayload::decode(&data[79..79 + dist_len])?;
            (Some(dist), 79 + dist_len)
        } else {
            (None, 75)
        };

        if data.len() != consumed {
            return Err(GroupLifecycleError::TrailingData {
                actual: data.len(),
                consumed,
            });
        }

        Ok(Self {
            msg_type,
            epoch,
            group_id,
            proposer_id,
            distribution,
        })
    }
}

impl SenderKeyDistributionPayload {
    /// Encode to binary wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.push(PAYLOAD_VERSION);
        buf.extend_from_slice(self.group_id.as_bytes());
        buf.extend_from_slice(&(self.members.len() as u32).to_be_bytes());
        for m in &self.members {
            buf.extend_from_slice(m.as_bytes());
        }
        buf.extend_from_slice(&(self.encrypted_keys.len() as u32).to_be_bytes());
        for b in &self.encrypted_keys {
            buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
            buf.extend_from_slice(b);
        }
        buf
    }

    /// Decode from binary wire format.
    pub fn decode(data: &[u8]) -> Result<Self, GroupLifecycleError> {
        if data.len() < PAYLOAD_MIN_SIZE {
            return Err(GroupLifecycleError::PayloadTooShort {
                expected: PAYLOAD_MIN_SIZE,
                got: data.len(),
            });
        }

        let version = data[0];
        if version != PAYLOAD_VERSION {
            return Err(GroupLifecycleError::UnknownPayloadVersion(version));
        }

        let group_id = GroupId::from_bytes(data[1..33].try_into().unwrap());
        let mut pos = 33;

        let member_count = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if data.len() < pos + member_count * 32 {
            return Err(GroupLifecycleError::PayloadTooShort {
                expected: pos + member_count * 32,
                got: data.len(),
            });
        }
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(PeerId::from_bytes(data[pos..pos + 32].try_into().unwrap()));
            pos += 32;
        }

        if data.len() < pos + 4 {
            return Err(GroupLifecycleError::PayloadTooShort {
                expected: pos + 4,
                got: data.len(),
            });
        }
        let bundle_count = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        let mut encrypted_keys = Vec::with_capacity(bundle_count);
        for _ in 0..bundle_count {
            if data.len() < pos + 4 {
                return Err(GroupLifecycleError::PayloadTooShort {
                    expected: pos + 4,
                    got: data.len(),
                });
            }
            let b_len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if data.len() < pos + b_len {
                return Err(GroupLifecycleError::PayloadTooShort {
                    expected: pos + b_len,
                    got: data.len(),
                });
            }
            encrypted_keys.push(data[pos..pos + b_len].to_vec());
            pos += b_len;
        }

        if data.len() != pos {
            return Err(GroupLifecycleError::TrailingData {
                actual: data.len(),
                consumed: pos,
            });
        }

        Ok(Self {
            group_id,
            members,
            encrypted_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::sender_key::SenderKeyDistributionPayload;

    fn test_group_id() -> GroupId {
        GroupId::from_bytes([0x42; 32])
    }

    fn test_peer_id(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    fn test_payload() -> SenderKeyDistributionPayload {
        SenderKeyDistributionPayload {
            group_id: test_group_id(),
            members: vec![test_peer_id(0x01), test_peer_id(0x02)],
            encrypted_keys: vec![vec![0xaa; 100], vec![0xbb; 100]],
        }
    }

    // ─── SenderKeyDistributionPayload codec ───

    #[test]
    fn payload_roundtrip() {
        let p = test_payload();
        let bytes = p.encode();
        let decoded = SenderKeyDistributionPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.group_id, p.group_id);
        assert_eq!(decoded.members.len(), 2);
        assert_eq!(decoded.members[0], p.members[0]);
        assert_eq!(decoded.members[1], p.members[1]);
        assert_eq!(decoded.encrypted_keys.len(), 2);
        assert_eq!(decoded.encrypted_keys[0], p.encrypted_keys[0]);
        assert_eq!(decoded.encrypted_keys[1], p.encrypted_keys[1]);
    }

    #[test]
    fn payload_empty_members() {
        let p = SenderKeyDistributionPayload {
            group_id: test_group_id(),
            members: vec![],
            encrypted_keys: vec![],
        };
        let bytes = p.encode();
        let decoded = SenderKeyDistributionPayload::decode(&bytes).unwrap();
        assert!(decoded.members.is_empty());
        assert!(decoded.encrypted_keys.is_empty());
    }

    #[test]
    fn payload_too_short() {
        assert!(SenderKeyDistributionPayload::decode(&[]).is_err());
        assert!(SenderKeyDistributionPayload::decode(&[0x01]).is_err());
        assert!(SenderKeyDistributionPayload::decode(&[0x01; 40]).is_err());
    }

    #[test]
    fn payload_wrong_version() {
        let p = test_payload();
        let mut bytes = p.encode();
        bytes[0] = 0x02;
        assert!(SenderKeyDistributionPayload::decode(&bytes).is_err());
    }

    #[test]
    fn payload_trailing_data_rejected() {
        let p = test_payload();
        let mut bytes = p.encode();
        bytes.push(0xFF);
        assert!(SenderKeyDistributionPayload::decode(&bytes).is_err());
    }

    #[test]
    fn payload_large_group() {
        let members: Vec<PeerId> = (0..50).map(test_peer_id).collect();
        let encrypted_keys: Vec<Vec<u8>> = (0..50).map(|i| vec![i; 200]).collect();
        let p = SenderKeyDistributionPayload {
            group_id: test_group_id(),
            members,
            encrypted_keys,
        };
        let bytes = p.encode();
        let decoded = SenderKeyDistributionPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.members.len(), 50);
        assert_eq!(decoded.encrypted_keys.len(), 50);
    }

    // ─── GroupControlEnvelope codec ───

    fn make_envelope(
        msg_type: super::super::types::GroupControlMessageType,
        distribution: Option<SenderKeyDistributionPayload>,
    ) -> GroupControlEnvelope {
        GroupControlEnvelope {
            msg_type,
            epoch: 1,
            group_id: test_group_id(),
            proposer_id: test_peer_id(0xAA),
            distribution,
        }
    }

    #[test]
    fn envelope_roundtrip_with_distribution() {
        let env = make_envelope(
            super::super::types::GroupControlMessageType::GroupCreate,
            Some(test_payload()),
        );
        let bytes = env.encode();
        let decoded = GroupControlEnvelope::decode(&bytes).unwrap();
        assert_eq!(decoded.msg_type, env.msg_type);
        assert_eq!(decoded.epoch, env.epoch);
        assert_eq!(decoded.group_id, env.group_id);
        assert!(decoded.distribution.is_some());
    }

    #[test]
    fn envelope_roundtrip_without_distribution() {
        let env = make_envelope(
            super::super::types::GroupControlMessageType::GroupDissolve,
            None,
        );
        let bytes = env.encode();
        assert_eq!(bytes.len(), 75);
        let decoded = GroupControlEnvelope::decode(&bytes).unwrap();
        assert_eq!(decoded.msg_type, env.msg_type);
        assert!(decoded.distribution.is_none());
    }

    #[test]
    fn envelope_too_short() {
        assert!(GroupControlEnvelope::decode(&[0u8; 74]).is_err());
        assert!(GroupControlEnvelope::decode(&[]).is_err());
    }

    #[test]
    fn envelope_wrong_version() {
        let env = make_envelope(
            super::super::types::GroupControlMessageType::GroupDissolve,
            None,
        );
        let mut bytes = env.encode();
        bytes[0] = 0x02;
        assert!(GroupControlEnvelope::decode(&bytes).is_err());
    }

    #[test]
    fn envelope_trailing_data_rejected() {
        let env = make_envelope(
            super::super::types::GroupControlMessageType::GroupDissolve,
            None,
        );
        let mut bytes = env.encode();
        bytes.push(0xFF);
        assert!(GroupControlEnvelope::decode(&bytes).is_err());
    }

    #[test]
    fn envelope_invalid_msg_type() {
        let mut bytes = vec![0x01, 0xFF];
        bytes.extend_from_slice(&[0u8; 73]); // pad to 75
        assert!(GroupControlEnvelope::decode(&bytes).is_err());
    }

    #[test]
    fn envelope_distribution_too_short() {
        let mut bytes = vec![0x01, 0x20];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&[0x42; 32]); // group_id
        bytes.extend_from_slice(&[0xAA; 32]); // proposer_id
        bytes.push(0x01); // has_distribution = true
        bytes.extend_from_slice(&100u32.to_be_bytes()); // claims 100 bytes
                                                        // but we provide none
        assert!(GroupControlEnvelope::decode(&bytes).is_err());
    }

    #[test]
    fn envelope_all_types_roundtrip() {
        use super::super::types::GroupControlMessageType;
        let types = [
            GroupControlMessageType::GroupCreate,
            GroupControlMessageType::GroupWelcome,
            GroupControlMessageType::GroupAdd,
            GroupControlMessageType::GroupRemove,
            GroupControlMessageType::GroupRekey,
            GroupControlMessageType::GroupDissolve,
        ];
        for mt in types {
            let has_dist = mt != GroupControlMessageType::GroupDissolve;
            let env = make_envelope(mt, has_dist.then(test_payload));
            let bytes = env.encode();
            let decoded = GroupControlEnvelope::decode(&bytes).unwrap();
            assert_eq!(decoded.msg_type, mt);
        }
    }

    // ─── Additional edge case tests ───

    #[test]
    fn payload_truncated_after_member_count() {
        let mut data = vec![0x01; 37];
        data[33..37].copy_from_slice(&5u32.to_be_bytes());
        assert!(SenderKeyDistributionPayload::decode(&data).is_err());
    }

    #[test]
    fn payload_truncated_mid_member() {
        let p = test_payload();
        let bytes = p.encode();
        assert!(SenderKeyDistributionPayload::decode(&bytes[..41]).is_err());
    }

    #[test]
    fn payload_truncated_after_members_no_bundles() {
        let p = SenderKeyDistributionPayload {
            group_id: test_group_id(),
            members: vec![test_peer_id(0x01)],
            encrypted_keys: vec![],
        };
        let bytes = p.encode();
        assert!(SenderKeyDistributionPayload::decode(&bytes[..69]).is_err());
    }

    #[test]
    fn payload_members_with_zero_keys() {
        let p = SenderKeyDistributionPayload {
            group_id: test_group_id(),
            members: vec![test_peer_id(0x01), test_peer_id(0x02)],
            encrypted_keys: vec![],
        };
        let bytes = p.encode();
        let decoded = SenderKeyDistributionPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.members.len(), 2);
        assert!(decoded.encrypted_keys.is_empty());
    }

    #[test]
    fn payload_zero_length_bundle() {
        let p = SenderKeyDistributionPayload {
            group_id: test_group_id(),
            members: vec![test_peer_id(0x01)],
            encrypted_keys: vec![vec![]],
        };
        let bytes = p.encode();
        let decoded = SenderKeyDistributionPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.encrypted_keys.len(), 1);
        assert!(decoded.encrypted_keys[0].is_empty());
    }

    #[test]
    fn payload_error_content_too_short() {
        let result = SenderKeyDistributionPayload::decode(&[0x01; 10]);
        match result.unwrap_err() {
            GroupLifecycleError::PayloadTooShort { expected, got } => {
                assert_eq!(expected, PAYLOAD_MIN_SIZE);
                assert_eq!(got, 10);
            }
            other => panic!("expected PayloadTooShort, got {other}"),
        }
    }

    #[test]
    fn payload_error_content_trailing() {
        let p = test_payload();
        let mut bytes = p.encode();
        bytes.push(0xFF);
        match SenderKeyDistributionPayload::decode(&bytes).unwrap_err() {
            GroupLifecycleError::TrailingData { actual, consumed } => {
                assert_eq!(actual, bytes.len());
                assert_eq!(consumed, bytes.len() - 1);
            }
            other => panic!("expected TrailingData, got {other:?}"),
        }
    }

    #[test]
    fn envelope_invalid_distribution_flag_accepted_as_none() {
        let mut bytes = vec![0x01, 0x20];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&[0x42; 32]);
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.push(0x02);
        let decoded = GroupControlEnvelope::decode(&bytes).unwrap();
        assert!(decoded.distribution.is_none());
    }

    #[test]
    fn envelope_corrupted_distribution_fails() {
        let mut bytes = vec![0x01, 0x20];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&[0x42; 32]);
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.push(0x01);
        bytes.extend_from_slice(&5u32.to_be_bytes());
        bytes.extend_from_slice(&[0xFF; 5]);
        assert!(GroupControlEnvelope::decode(&bytes).is_err());
    }

    #[test]
    fn envelope_truncated_at_distribution_len() {
        let mut bytes = vec![0x01, 0x20];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&[0x42; 32]);
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.push(0x01);
        assert!(GroupControlEnvelope::decode(&bytes).is_err());
    }

    #[test]
    fn envelope_error_content_epoch_field() {
        let mut bytes = vec![0x01, 0x20];
        bytes.extend_from_slice(&5u64.to_le_bytes());
        bytes.extend_from_slice(&[0x42; 32]);
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.push(0x00);
        let decoded = GroupControlEnvelope::decode(&bytes).unwrap();
        assert_eq!(decoded.epoch, 5);
    }

    #[test]
    fn envelope_error_content_wrong_version() {
        let mut bytes = vec![0x99, 0x20];
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&[0x42; 32]);
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.push(0x00);
        match GroupControlEnvelope::decode(&bytes).unwrap_err() {
            GroupLifecycleError::UnknownPayloadVersion(v) => assert_eq!(v, 0x99),
            other => panic!("expected UnknownPayloadVersion, got {other:?}"),
        }
    }
}
