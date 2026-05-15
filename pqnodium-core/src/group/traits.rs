use crate::group::types::GroupId;

/// Encrypts and decrypts messages within a group session.
///
/// Each instance is bound to a specific group. Implementations manage
/// their own key state (chain keys, nonce counters, sender chains, etc.)
/// internally — callers only interact via [`encrypt`](GroupCipher::encrypt)
/// and [`decrypt`](GroupCipher::decrypt).
pub trait GroupCipher: Send + Sync {
    type Error: std::error::Error + Send + Sync;

    /// Encrypt a plaintext message for the group.
    ///
    /// The returned bytes are backend-specific and include any metadata
    /// required for decryption (e.g., sender identifier, chain step index).
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Decrypt a ciphertext received from a group member.
    ///
    /// The ciphertext format is backend-specific and produced by a
    /// corresponding [`encrypt`](GroupCipher::encrypt) call on the sender's
    /// side.
    ///
    /// Implementations that track per-sender chain state for out-of-order
    /// message detection will need interior mutability (e.g., `RefCell`,
    /// `Mutex`) here.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// Distributes group keys to members via key encapsulation.
///
/// Backends differ in encapsulation strategy (N-way HybridKem,
/// multi-recipient KEM, TreeKEM, etc.) but all expose the same
/// distribute/recover interface.
pub trait GroupKeyDistributor: Send + Sync {
    type Error: std::error::Error + Send + Sync;
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;

    /// Encapsulate a group key for each recipient.
    ///
    /// Returns one encrypted bundle per recipient, in the same order as
    /// `recipient_pks`.
    fn distribute(
        &self,
        group_key: &[u8],
        recipient_pks: &[Self::PublicKey],
    ) -> Result<Vec<Vec<u8>>, Self::Error>;

    /// Decapsulate a group key from an encrypted bundle addressed to this
    /// node.
    fn recover(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// Manages the lifecycle of encrypted group sessions.
///
/// Covers group creation, membership changes, and key rotation. Each
/// mutation returns a [`DistributionPayload`](Self::DistributionPayload)
/// that must be delivered to the affected members (typically via Gossipsub
/// or direct P2P message).
pub trait GroupSessionManager: Send + Sync {
    type Error: std::error::Error + Send + Sync;
    type MemberId: Clone + Eq + std::hash::Hash + Send + Sync;
    type Cipher: GroupCipher;
    type DistributionPayload: Send + Sync;

    /// Create a new encrypted group with the given initial members.
    ///
    /// `members` **must** include the creator. Returns the group ID, a
    /// [`Cipher`](Self::Cipher) for the creator, and a distribution payload
    /// to send to all initial members.
    fn create_group(
        &mut self,
        members: &[Self::MemberId],
    ) -> Result<(GroupId, Self::Cipher, Self::DistributionPayload), Self::Error>;

    /// Process a received distribution payload and initialize a cipher.
    ///
    /// Used by non-creator members to join a group or apply a re-key.
    fn apply_distribution(
        &mut self,
        payload: &Self::DistributionPayload,
    ) -> Result<(GroupId, Self::Cipher), Self::Error>;

    /// Add a member to an existing group, triggering a re-key.
    ///
    /// Returns an updated cipher for the caller and a distribution payload
    /// to send to all current and new members.
    fn add_member(
        &mut self,
        group_id: &GroupId,
        member: &Self::MemberId,
    ) -> Result<(Self::Cipher, Self::DistributionPayload), Self::Error>;

    /// Remove a member from a group, triggering a re-key.
    ///
    /// Returns an updated cipher for the caller and a distribution payload
    /// to send to remaining members.
    fn remove_member(
        &mut self,
        group_id: &GroupId,
        member: &Self::MemberId,
    ) -> Result<(Self::Cipher, Self::DistributionPayload), Self::Error>;

    /// Manually rotate the group key.
    ///
    /// Returns an updated cipher for the caller and a distribution payload
    /// to send to all current members.
    fn rotate_key(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(Self::Cipher, Self::DistributionPayload), Self::Error>;

    /// Dissolve a group, releasing all associated state.
    ///
    /// After dissolution the group ID is no longer valid. Members will not
    /// be notified — the caller is responsible for sending a dissolution
    /// message if desired.
    fn dissolve(&mut self, group_id: &GroupId) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    // ── Mock infrastructure ──

    #[derive(Debug, thiserror::Error)]
    enum MockError {
        #[error("mock error")]
        Fail,
    }

    struct MockCipher {
        key: [u8; 32],
        step: u64,
    }

    impl GroupCipher for MockCipher {
        type Error = MockError;

        fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
            let mut out = Vec::with_capacity(8 + plaintext.len());
            out.extend_from_slice(&self.step.to_le_bytes());
            for (i, &b) in plaintext.iter().enumerate() {
                out.push(b ^ self.key[i % 32]);
            }
            self.step += 1;
            Ok(out)
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
            if ciphertext.len() < 8 {
                return Err(MockError::Fail);
            }
            let plaintext = ciphertext[8..]
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ self.key[i % 32])
                .collect();
            Ok(plaintext)
        }
    }

    struct MockDistributor;

    impl GroupKeyDistributor for MockDistributor {
        type Error = MockError;
        type PublicKey = Vec<u8>;

        fn distribute(
            &self,
            group_key: &[u8],
            recipient_pks: &[Self::PublicKey],
        ) -> Result<Vec<Vec<u8>>, Self::Error> {
            Ok(recipient_pks
                .iter()
                .map(|pk| {
                    let mut bundle = Vec::with_capacity(pk.len() + group_key.len());
                    bundle.extend_from_slice(pk);
                    bundle.extend_from_slice(group_key);
                    bundle
                })
                .collect())
        }

        fn recover(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, Self::Error> {
            if encrypted_key.len() < 32 {
                return Err(MockError::Fail);
            }
            Ok(encrypted_key[encrypted_key.len() - 32..].to_vec())
        }
    }

    type MemberId = Vec<u8>;

    #[allow(dead_code)]
    struct MockDistributionPayload {
        group_id: GroupId,
        members: Vec<MemberId>,
        encrypted_keys: Vec<Vec<u8>>,
    }

    struct MockManager {
        groups: HashMap<[u8; 32], Vec<MemberId>>,
    }

    impl MockManager {
        fn new() -> Self {
            Self {
                groups: HashMap::new(),
            }
        }
    }

    impl GroupSessionManager for MockManager {
        type Error = MockError;
        type MemberId = MemberId;
        type Cipher = MockCipher;
        type DistributionPayload = MockDistributionPayload;

        fn create_group(
            &mut self,
            members: &[Self::MemberId],
        ) -> Result<(GroupId, Self::Cipher, Self::DistributionPayload), Self::Error> {
            let gid = GroupId::random();
            let key = [0x42u8; 32];
            let dist = MockDistributor;
            let pks: Vec<Vec<u8>> = members.iter().cloned().collect();
            let encrypted_keys = dist.distribute(&key, &pks).unwrap();
            self.groups.insert(*gid.as_bytes(), members.to_vec());
            let payload = MockDistributionPayload {
                group_id: gid.clone(),
                members: members.to_vec(),
                encrypted_keys,
            };
            Ok((gid, MockCipher { key, step: 0 }, payload))
        }

        fn apply_distribution(
            &mut self,
            payload: &Self::DistributionPayload,
        ) -> Result<(GroupId, Self::Cipher), Self::Error> {
            let gid = payload.group_id.clone();
            let key = [0x42u8; 32];
            self.groups.insert(*gid.as_bytes(), payload.members.clone());
            Ok((gid, MockCipher { key, step: 0 }))
        }

        fn add_member(
            &mut self,
            group_id: &GroupId,
            member: &Self::MemberId,
        ) -> Result<(Self::Cipher, Self::DistributionPayload), Self::Error> {
            let members = self
                .groups
                .get_mut(group_id.as_bytes())
                .ok_or(MockError::Fail)?;
            members.push(member.clone());
            let key = [0x43u8; 32];
            let payload = MockDistributionPayload {
                group_id: group_id.clone(),
                members: members.clone(),
                encrypted_keys: vec![],
            };
            Ok((MockCipher { key, step: 0 }, payload))
        }

        fn remove_member(
            &mut self,
            group_id: &GroupId,
            member: &Self::MemberId,
        ) -> Result<(Self::Cipher, Self::DistributionPayload), Self::Error> {
            let members = self
                .groups
                .get_mut(group_id.as_bytes())
                .ok_or(MockError::Fail)?;
            members.retain(|m| m != member);
            let key = [0x44u8; 32];
            let payload = MockDistributionPayload {
                group_id: group_id.clone(),
                members: members.clone(),
                encrypted_keys: vec![],
            };
            Ok((MockCipher { key, step: 0 }, payload))
        }

        fn rotate_key(
            &mut self,
            group_id: &GroupId,
        ) -> Result<(Self::Cipher, Self::DistributionPayload), Self::Error> {
            let members = self
                .groups
                .get(group_id.as_bytes())
                .ok_or(MockError::Fail)?;
            let key = [0x45u8; 32];
            let payload = MockDistributionPayload {
                group_id: group_id.clone(),
                members: members.clone(),
                encrypted_keys: vec![],
            };
            Ok((MockCipher { key, step: 0 }, payload))
        }

        fn dissolve(&mut self, group_id: &GroupId) -> Result<(), Self::Error> {
            self.groups
                .remove(group_id.as_bytes())
                .ok_or(MockError::Fail)?;
            Ok(())
        }
    }

    // ════════════════════════════════════════════
    //  GroupCipher functional tests
    // ════════════════════════════════════════════

    #[test]
    fn cipher_encrypt_decrypt_roundtrip() {
        let mut cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        let ct = cipher.encrypt(b"hello").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn cipher_empty_plaintext() {
        let mut cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        let ct = cipher.encrypt(b"").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn cipher_single_byte() {
        let mut cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        let ct = cipher.encrypt(b"\x00").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, b"\x00");
    }

    #[test]
    fn cipher_binary_data() {
        let mut cipher = MockCipher {
            key: [0xaa; 32],
            step: 0,
        };
        let data: Vec<u8> = (0u8..=255).collect();
        let ct = cipher.encrypt(&data).unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn cipher_unicode_plaintext() {
        let mut cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        let msg = "你好世界 🌍 PQNodium";
        let ct = cipher.encrypt(msg.as_bytes()).unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    #[test]
    fn cipher_sequential_encrypts_advance_step() {
        let mut cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        // Each encrypt should produce different ciphertext (step counter changes)
        let ct1 = cipher.encrypt(b"same").unwrap();
        let ct2 = cipher.encrypt(b"same").unwrap();
        assert_ne!(ct1, ct2, "sequential encrypts must differ (step advances)");
        // Both should still decrypt correctly
        assert_eq!(cipher.decrypt(&ct1).unwrap(), b"same");
        assert_eq!(cipher.decrypt(&ct2).unwrap(), b"same");
    }

    #[test]
    fn cipher_decrypt_wrong_key_fails() {
        let enc_cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        let dec_cipher = MockCipher {
            key: [0x99; 32],
            step: 0,
        };
        let mut enc = enc_cipher;
        let ct = enc.encrypt(b"secret").unwrap();
        let pt = dec_cipher.decrypt(&ct).unwrap();
        assert_ne!(pt, b"secret", "wrong key should produce wrong plaintext");
    }

    #[test]
    fn cipher_decrypt_truncated_fails() {
        let cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        assert!(cipher.decrypt(&[0u8; 7]).is_err());
        assert!(cipher.decrypt(&[0u8; 0]).is_err());
        assert!(cipher.decrypt(&[0u8; 3]).is_err());
    }

    #[test]
    fn cipher_large_plaintext() {
        let mut cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        let data = vec![0xabu8; 1024 * 1024]; // 1 MiB
        let ct = cipher.encrypt(&data).unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn cipher_cross_instance_compatibility() {
        // Two ciphers with the same key should be compatible
        let mut sender = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        let receiver = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        let ct = sender.encrypt(b"cross-instance").unwrap();
        let pt = receiver.decrypt(&ct).unwrap();
        assert_eq!(pt, b"cross-instance");
    }

    // ════════════════════════════════════════════
    //  GroupKeyDistributor functional tests
    // ════════════════════════════════════════════

    #[test]
    fn distributor_distribute_zero_recipients() {
        let dist = MockDistributor;
        let bundles = dist.distribute(&[0x42; 32], &[]).unwrap();
        assert!(bundles.is_empty());
    }

    #[test]
    fn distributor_distribute_single_recipient() {
        let dist = MockDistributor;
        let key = [0x42; 32];
        let bundles = dist.distribute(&key, &[b"pk1".to_vec()]).unwrap();
        assert_eq!(bundles.len(), 1);
        let recovered = dist.recover(&bundles[0]).unwrap();
        assert_eq!(recovered.as_slice(), key);
    }

    #[test]
    fn distributor_distribute_many_recipients() {
        let dist = MockDistributor;
        let key = [0x42; 32];
        let pks: Vec<Vec<u8>> = (0..10).map(|i| vec![i; 32]).collect();
        let bundles = dist.distribute(&key, &pks).unwrap();
        assert_eq!(bundles.len(), 10);
        for bundle in &bundles {
            let recovered = dist.recover(bundle).unwrap();
            assert_eq!(recovered.as_slice(), key);
        }
    }

    #[test]
    fn distributor_distribute_order_preserved() {
        let dist = MockDistributor;
        let key = [0x42; 32];
        let pks: Vec<Vec<u8>> = vec![b"alice".to_vec(), b"bob".to_vec()];
        let bundles = dist.distribute(&key, &pks).unwrap();
        // Each bundle should contain its recipient's pk as prefix
        assert!(bundles[0].starts_with(b"alice"));
        assert!(bundles[1].starts_with(b"bob"));
    }

    #[test]
    fn distributor_recover_truncated_fails() {
        let dist = MockDistributor;
        assert!(dist.recover(&[0u8; 31]).is_err());
        assert!(dist.recover(&[0u8; 0]).is_err());
    }

    #[test]
    fn distributor_recover_exactly_32_bytes() {
        let dist = MockDistributor;
        let data = [0x42u8; 32];
        let recovered = dist.recover(&data).unwrap();
        assert_eq!(recovered.as_slice(), data);
    }

    // ════════════════════════════════════════════
    //  GroupSessionManager functional tests
    // ════════════════════════════════════════════

    #[test]
    fn manager_create_group_returns_valid_id_and_cipher() {
        let mut mgr = MockManager::new();
        let members: Vec<Vec<u8>> = vec![b"alice".to_vec(), b"bob".to_vec()];
        let (gid, mut cipher, payload) = mgr.create_group(&members).unwrap();
        assert_ne!(gid.as_bytes(), &[0u8; 32]);
        let ct = cipher.encrypt(b"hello").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello");
        assert_eq!(payload.group_id, gid);
        assert_eq!(payload.members.len(), 2);
    }

    #[test]
    fn manager_create_group_unique_ids() {
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec()];
        let (id1, _, _) = mgr.create_group(&members).unwrap();
        let (id2, _, _) = mgr.create_group(&members).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn manager_apply_distribution_joins_group() {
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec()];
        let (_, _, payload) = mgr.create_group(&members).unwrap();
        let (gid, mut cipher) = mgr.apply_distribution(&payload).unwrap();
        let ct = cipher.encrypt(b"world").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, b"world");
        assert_eq!(gid, payload.group_id);
    }

    #[test]
    fn manager_cross_member_encrypt_decrypt() {
        // Creator encrypts, joiner decrypts (same key → compatible)
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec(), b"bob".to_vec()];
        let (_, mut creator_cipher, payload) = mgr.create_group(&members).unwrap();
        let (_, joiner_cipher) = mgr.apply_distribution(&payload).unwrap();

        let ct = creator_cipher.encrypt(b"from creator").unwrap();
        let pt = joiner_cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, b"from creator");
    }

    #[test]
    fn manager_add_member_rekeys() {
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec(), b"bob".to_vec()];
        let (gid, _, _) = mgr.create_group(&members).unwrap();
        let (cipher, payload) = mgr.add_member(&gid, &b"charlie".to_vec()).unwrap();
        assert_eq!(payload.members.len(), 3);
        assert!(payload.members.contains(&b"charlie".to_vec()));
        // New cipher works
        let mut c = cipher;
        let ct = c.encrypt(b"after add").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"after add");
    }

    #[test]
    fn manager_remove_member_rekeys() {
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec(), b"bob".to_vec(), b"charlie".to_vec()];
        let (gid, _, _) = mgr.create_group(&members).unwrap();
        let (cipher, payload) = mgr.remove_member(&gid, &b"bob".to_vec()).unwrap();
        assert_eq!(payload.members.len(), 2);
        assert!(!payload.members.contains(&b"bob".to_vec()));
        let mut c = cipher;
        let ct = c.encrypt(b"after remove").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"after remove");
    }

    #[test]
    fn manager_rotate_key() {
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec()];
        let (gid, _, _) = mgr.create_group(&members).unwrap();
        let (cipher, _) = mgr.rotate_key(&gid).unwrap();
        let mut c = cipher;
        let ct = c.encrypt(b"rotated").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"rotated");
    }

    #[test]
    fn manager_dissolve_removes_group() {
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec()];
        let (gid, _, _) = mgr.create_group(&members).unwrap();
        mgr.dissolve(&gid).unwrap();
        assert!(mgr.dissolve(&gid).is_err(), "dissolve twice should fail");
    }

    #[test]
    fn manager_operations_on_dissolved_group_fail() {
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec()];
        let (gid, _, _) = mgr.create_group(&members).unwrap();
        mgr.dissolve(&gid).unwrap();
        assert!(mgr.add_member(&gid, &b"bob".to_vec()).is_err());
        assert!(mgr.remove_member(&gid, &b"alice".to_vec()).is_err());
        assert!(mgr.rotate_key(&gid).is_err());
    }

    #[test]
    fn manager_operations_on_nonexistent_group_fail() {
        let mut mgr = MockManager::new();
        let fake_gid = GroupId::from_bytes([0xff; 32]);
        assert!(mgr.add_member(&fake_gid, &b"bob".to_vec()).is_err());
        assert!(mgr.remove_member(&fake_gid, &b"alice".to_vec()).is_err());
        assert!(mgr.rotate_key(&fake_gid).is_err());
        assert!(mgr.dissolve(&fake_gid).is_err());
    }

    #[test]
    fn manager_full_lifecycle() {
        let mut mgr = MockManager::new();

        // 1. Create
        let members = vec![b"alice".to_vec(), b"bob".to_vec()];
        let (gid, mut cipher, payload) = mgr.create_group(&members).unwrap();

        // 2. Encrypt with initial key
        let ct = cipher.encrypt(b"msg1").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"msg1");

        // 3. Joiner applies distribution
        let (_, mut joiner) = mgr.apply_distribution(&payload).unwrap();
        let ct2 = joiner.encrypt(b"msg2").unwrap();
        assert_eq!(joiner.decrypt(&ct2).unwrap(), b"msg2");

        // 4. Add member → re-key
        let (cipher, _) = mgr.add_member(&gid, &b"charlie".to_vec()).unwrap();
        let mut c = cipher;
        let ct3 = c.encrypt(b"msg3").unwrap();
        assert_eq!(c.decrypt(&ct3).unwrap(), b"msg3");

        // 5. Remove member → re-key
        let (cipher, _) = mgr.remove_member(&gid, &b"bob".to_vec()).unwrap();
        let mut c = cipher;
        let ct4 = c.encrypt(b"msg4").unwrap();
        assert_eq!(c.decrypt(&ct4).unwrap(), b"msg4");

        // 6. Manual rotation
        let (cipher, _) = mgr.rotate_key(&gid).unwrap();
        let mut c = cipher;
        let ct5 = c.encrypt(b"msg5").unwrap();
        assert_eq!(c.decrypt(&ct5).unwrap(), b"msg5");

        // 7. Dissolve
        mgr.dissolve(&gid).unwrap();
        assert!(mgr.rotate_key(&gid).is_err());
    }

    #[test]
    fn manager_multiple_groups_independent() {
        let mut mgr = MockManager::new();

        let (gid_a, mut cipher_a, _) = mgr.create_group(&[b"alice".to_vec()]).unwrap();
        let (gid_b, mut cipher_b, _) = mgr.create_group(&[b"bob".to_vec()]).unwrap();

        assert_ne!(gid_a, gid_b);

        // Each group has independent cipher state (same mock key but independent step counters)
        let ct_a = cipher_a.encrypt(b"group A").unwrap();
        let ct_b = cipher_b.encrypt(b"group B").unwrap();
        assert_eq!(cipher_a.decrypt(&ct_a).unwrap(), b"group A");
        assert_eq!(cipher_b.decrypt(&ct_b).unwrap(), b"group B");

        // Dissolve one group doesn't affect the other
        mgr.dissolve(&gid_a).unwrap();
        assert!(mgr.dissolve(&gid_a).is_err());
        // Group B still works
        let (cipher_b2, _) = mgr.rotate_key(&gid_b).unwrap();
        let mut c = cipher_b2;
        let ct = c.encrypt(b"still alive").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"still alive");
    }

    #[test]
    fn manager_add_then_remove_same_member() {
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec(), b"bob".to_vec()];
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        let (_, payload) = mgr.add_member(&gid, &b"charlie".to_vec()).unwrap();
        assert_eq!(payload.members.len(), 3);

        let (_, payload) = mgr.remove_member(&gid, &b"charlie".to_vec()).unwrap();
        assert_eq!(payload.members.len(), 2);
        assert!(!payload.members.contains(&b"charlie".to_vec()));
    }

    // ════════════════════════════════════════════
    //  Stress tests
    // ════════════════════════════════════════════

    #[test]
    fn stress_cipher_many_sequential_encrypts() {
        let mut cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        for i in 0..10_000u64 {
            let msg = format!("message {i}");
            let ct = cipher.encrypt(msg.as_bytes()).unwrap();
            let pt = cipher.decrypt(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes(), "failed at iteration {i}");
        }
    }

    #[test]
    fn stress_cipher_many_encrypts_collect_then_decrypt() {
        let mut cipher = MockCipher {
            key: [0x42; 32],
            step: 0,
        };
        let ciphertexts: Vec<Vec<u8>> = (0..1000)
            .map(|i| {
                let msg = format!("msg-{i}");
                cipher.encrypt(msg.as_bytes()).unwrap()
            })
            .collect();
        // Decrypt in reverse order to verify stateless decrypt
        for i in (0..1000).rev() {
            let expected = format!("msg-{i}");
            let pt = cipher.decrypt(&ciphertexts[i]).unwrap();
            assert_eq!(pt, expected.as_bytes(), "failed at reverse decrypt {i}");
        }
    }

    #[test]
    fn stress_distributor_many_recipients() {
        let dist = MockDistributor;
        let key = [0x42; 32];
        let pks: Vec<Vec<u8>> = (0..100).map(|i| vec![i; 32]).collect();
        let bundles = dist.distribute(&key, &pks).unwrap();
        assert_eq!(bundles.len(), 100);
        for bundle in &bundles {
            let recovered = dist.recover(bundle).unwrap();
            assert_eq!(recovered.as_slice(), key);
        }
    }

    #[test]
    fn stress_manager_many_groups() {
        let mut mgr = MockManager::new();
        let mut gids = Vec::new();
        for i in 0u8..200 {
            let member = vec![i];
            let (gid, mut cipher, _) = mgr.create_group(&[member.clone()]).unwrap();
            let ct = cipher.encrypt(&[i]).unwrap();
            assert_eq!(cipher.decrypt(&ct).unwrap(), vec![i]);
            gids.push(gid);
        }
        assert_eq!(gids.len(), 200);
        // All groups are distinct
        let set: HashSet<[u8; 32]> = gids.iter().map(|g| *g.as_bytes()).collect();
        assert_eq!(set.len(), 200);
    }

    #[test]
    fn stress_manager_large_group() {
        let mut mgr = MockManager::new();
        let members: Vec<Vec<u8>> = (0..100).map(|i| vec![i]).collect();
        let (gid, mut cipher, payload) = mgr.create_group(&members).unwrap();
        assert_eq!(payload.members.len(), 100);
        assert_eq!(payload.encrypted_keys.len(), 100);

        // Encrypt/decrypt in a large group
        let ct = cipher.encrypt(b"big group").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"big group");

        // Add one more
        let (cipher, payload) = mgr.add_member(&gid, &b"new_member".to_vec()).unwrap();
        assert_eq!(payload.members.len(), 101);

        // Remove half
        let mut c = cipher;
        for i in 0..50 {
            let (_, payload) = mgr.remove_member(&gid, &vec![i]).unwrap();
            assert_eq!(payload.members.len(), 100 - i as usize);
        }
        // Still works
        let ct = c.encrypt(b"still works").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"still works");
    }

    #[test]
    fn stress_manager_rapid_rotation() {
        let mut mgr = MockManager::new();
        let members = vec![b"alice".to_vec(), b"bob".to_vec()];
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        for _ in 0..100 {
            let (cipher, _) = mgr.rotate_key(&gid).unwrap();
            let mut c = cipher;
            let ct = c.encrypt(b"rotated").unwrap();
            assert_eq!(c.decrypt(&ct).unwrap(), b"rotated");
        }
    }

    #[test]
    fn stress_manager_create_dissolve_cycle() {
        let mut mgr = MockManager::new();
        for i in 0..100 {
            let member = format!("member-{i}").into_bytes();
            let (gid, mut cipher, _) = mgr.create_group(&[member]).unwrap();
            let ct = cipher.encrypt(b"temp").unwrap();
            assert_eq!(cipher.decrypt(&ct).unwrap(), b"temp");
            mgr.dissolve(&gid).unwrap();
        }
    }

    #[test]
    fn stress_manager_churn_add_remove() {
        let mut mgr = MockManager::new();
        let members: Vec<Vec<u8>> = (0..10).map(|i| vec![i]).collect();
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        // Add and remove members in rapid succession
        for i in 100u8..200 {
            let member = vec![i];
            let (cipher, _) = mgr.add_member(&gid, &member).unwrap();
            let mut c = cipher;
            let ct = c.encrypt(&[i]).unwrap();
            assert_eq!(c.decrypt(&ct).unwrap(), vec![i]);

            let (cipher, _) = mgr.remove_member(&gid, &member).unwrap();
            let mut c = cipher;
            let ct = c.encrypt(b"after remove").unwrap();
            assert_eq!(c.decrypt(&ct).unwrap(), b"after remove");
        }
    }
}
