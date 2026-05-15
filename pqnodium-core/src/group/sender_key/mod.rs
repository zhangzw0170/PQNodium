pub mod chain;
pub mod error;

use std::collections::HashMap;

use rand::RngCore;

use crate::crypto::backend::pqc::chacha20::ChaCha20Poly1305Cipher;
use crate::crypto::backend::pqc::ml_kem::MlKem768Kem;
use crate::crypto::backend::pqc::x25519::X25519Kem;
use crate::crypto::hybrid::hybrid_kem::{HybridKem, HybridKemPublicKey, HybridKemSecretKey};
use crate::crypto::traits::aead::AeadCipher;
use crate::crypto::traits::kem::KeyEncapsulation;
use crate::group::traits::{GroupCipher, GroupKeyDistributor, GroupSessionManager};
use crate::group::types::GroupId;
use crate::identity::PeerId;

use chain::ChainKey;
use error::SenderKeyError;

/// Wire format header size: `[sender_id:32][chain_step:8][nonce:12]` = 52 bytes.
const HEADER_LEN: usize = 32 + 8 + 12;

/// KEM bundle size: `[HybridKem ct:1122][AEAD nonce:12][encrypted_group_key:48]` = 1182 bytes.
const KEM_BUNDLE_LEN: usize = 1122 + 12 + 48;

// ─── SenderKeyCipher ────────────────────────────────────────────────

/// Sender Key group cipher implementing the chain-key ratchet.
///
/// Each instance is bound to one group and one sender identity. Encryption
/// advances the sender's chain step; decryption is stateless (derives any
/// sender's chain key from the shared group key on demand).
pub struct SenderKeyCipher {
    group_key: [u8; 32],
    my_sender_id: [u8; 32],
    chain_step: u64,
}

impl SenderKeyCipher {
    /// Create a new cipher bound to the given group key and sender identity.
    pub fn new(group_key: [u8; 32], sender_id: [u8; 32]) -> Self {
        Self {
            group_key,
            my_sender_id: sender_id,
            chain_step: 0,
        }
    }
}

impl GroupCipher for SenderKeyCipher {
    type Error = SenderKeyError;

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let (mk, _) =
            ChainKey::derive_at_step(&self.group_key, &self.my_sender_id, self.chain_step)?;

        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let aad = &self.my_sender_id[..];
        let ct = ChaCha20Poly1305Cipher::encrypt(mk.as_bytes(), &nonce, aad, plaintext)
            .map_err(|e| SenderKeyError::Aead(e.to_string()))?;

        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(&self.my_sender_id);
        out.extend_from_slice(&self.chain_step.to_le_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);

        self.chain_step += 1;
        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.len() < HEADER_LEN {
            return Err(SenderKeyError::CiphertextTooShort {
                min: HEADER_LEN,
                got: ciphertext.len(),
            });
        }

        let sender_id: [u8; 32] = ciphertext[..32].try_into().unwrap();
        let chain_step = u64::from_le_bytes(ciphertext[32..40].try_into().unwrap());
        let nonce = &ciphertext[40..52];
        let ct = &ciphertext[52..];

        let (mk, _) = ChainKey::derive_at_step(&self.group_key, &sender_id, chain_step)?;

        ChaCha20Poly1305Cipher::decrypt(mk.as_bytes(), nonce, &sender_id[..], ct)
            .map_err(|_| SenderKeyError::DecryptionFailed)
    }
}

// ─── SenderKeyDistributor ───────────────────────────────────────────

/// Distributes group keys to members via HybridKem key encapsulation.
///
/// Each recipient gets a KEM bundle: the group key is encrypted with a
/// fresh ephemeral shared secret encapsulated to the recipient's public key,
/// then wrapped in a second AEAD layer.
pub struct SenderKeyDistributor {
    my_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>,
}

type PqHybridKem = HybridKem<X25519Kem, MlKem768Kem>;

impl SenderKeyDistributor {
    /// Create a distributor that can recover keys addressed to `my_sk`.
    pub fn new(my_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>) -> Self {
        Self { my_sk }
    }
}

impl GroupKeyDistributor for SenderKeyDistributor {
    type Error = SenderKeyError;
    type PublicKey = HybridKemPublicKey<X25519Kem, MlKem768Kem>;

    fn distribute(
        &self,
        group_key: &[u8],
        recipient_pks: &[Self::PublicKey],
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        let mut bundles = Vec::with_capacity(recipient_pks.len());
        for pk in recipient_pks {
            let (kem_ct, ss) = PqHybridKem::encapsulate(pk, &mut rand::rngs::OsRng)
                .map_err(|e| SenderKeyError::KemEncapsulation(e.to_string()))?;

            let mut nonce = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut nonce);

            let encrypted_gk =
                ChaCha20Poly1305Cipher::encrypt(ss.as_bytes(), &nonce, &[], group_key)
                    .map_err(|e| SenderKeyError::Aead(e.to_string()))?;

            let mut bundle = Vec::with_capacity(KEM_BUNDLE_LEN);
            bundle.extend_from_slice(&kem_ct);
            bundle.extend_from_slice(&nonce);
            bundle.extend_from_slice(&encrypted_gk);
            bundles.push(bundle);
        }
        Ok(bundles)
    }

    fn recover(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, Self::Error> {
        if encrypted_key.len() < 1122 + 12 {
            return Err(SenderKeyError::CiphertextTooShort {
                min: 1122 + 12,
                got: encrypted_key.len(),
            });
        }

        let kem_ct = &encrypted_key[..1122];
        let nonce = &encrypted_key[1122..1134];
        let enc_gk = &encrypted_key[1134..];

        let ss = PqHybridKem::decapsulate(&self.my_sk, kem_ct)
            .map_err(|e| SenderKeyError::KemDecapsulation(e.to_string()))?;

        ChaCha20Poly1305Cipher::decrypt(ss.as_bytes(), nonce, &[], enc_gk)
            .map_err(|_| SenderKeyError::DecryptionFailed)
    }
}

// ─── SenderKeyManager ───────────────────────────────────────────────

/// Internal state tracked per group.
struct GroupState {
    members: Vec<PeerId>,
    group_key: [u8; 32],
}

/// Distribution payload delivered to members on group creation or re-key.
pub struct SenderKeyDistributionPayload {
    /// The group this payload belongs to.
    pub group_id: GroupId,
    /// Current member list after the operation.
    pub members: Vec<PeerId>,
    /// One encrypted key bundle per member (same order as `members`).
    pub encrypted_keys: Vec<Vec<u8>>,
}

/// Manages Sender Key group sessions: creation, membership, re-keying.
///
/// Callers must register each member's hybrid KEM public key via
/// [`register_member_pk`](SenderKeyManager::register_member_pk) before
/// creating a group or adding a member.
pub struct SenderKeyManager {
    my_peer_id: PeerId,
    my_hybrid_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>,
    groups: HashMap<[u8; 32], GroupState>,
    known_pks: HashMap<[u8; 32], HybridKemPublicKey<X25519Kem, MlKem768Kem>>,
}

impl SenderKeyManager {
    /// Create a new manager for the given local peer identity.
    pub fn new(
        my_peer_id: PeerId,
        my_hybrid_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>,
    ) -> Self {
        Self {
            my_peer_id,
            my_hybrid_sk,
            groups: HashMap::new(),
            known_pks: HashMap::new(),
        }
    }

    /// Register a member's hybrid KEM public key for future group operations.
    pub fn register_member_pk(
        &mut self,
        peer_id: PeerId,
        pk: HybridKemPublicKey<X25519Kem, MlKem768Kem>,
    ) {
        self.known_pks.insert(*peer_id.as_bytes(), pk);
    }

    /// Generate a fresh random 32-byte group key.
    fn random_group_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    /// Distribute the current group key to all members using known public keys.
    fn distribute_group_key(
        sk: &HybridKemSecretKey<X25519Kem, MlKem768Kem>,
        known_pks: &HashMap<[u8; 32], HybridKemPublicKey<X25519Kem, MlKem768Kem>>,
        group_key: &[u8; 32],
        members: &[PeerId],
    ) -> Result<Vec<Vec<u8>>, SenderKeyError> {
        let dist = SenderKeyDistributor::new(sk.clone());
        let pks: Vec<_> = members
            .iter()
            .map(|m| {
                known_pks
                    .get(m.as_bytes())
                    .cloned()
                    .ok_or(SenderKeyError::MemberPublicKeyNotFound)
            })
            .collect::<Result<_, _>>()?;
        dist.distribute(group_key, &pks)
    }
}

impl GroupSessionManager for SenderKeyManager {
    type Error = SenderKeyError;
    type MemberId = PeerId;
    type Cipher = SenderKeyCipher;
    type DistributionPayload = SenderKeyDistributionPayload;

    fn create_group(
        &mut self,
        members: &[Self::MemberId],
    ) -> Result<(GroupId, Self::Cipher, Self::DistributionPayload), Self::Error> {
        let group_id = GroupId::random();
        let group_key = Self::random_group_key();

        let encrypted_keys =
            Self::distribute_group_key(&self.my_hybrid_sk, &self.known_pks, &group_key, members)?;

        self.groups.insert(
            *group_id.as_bytes(),
            GroupState {
                members: members.to_vec(),
                group_key,
            },
        );

        let cipher = SenderKeyCipher::new(group_key, *self.my_peer_id.as_bytes());
        let payload = SenderKeyDistributionPayload {
            group_id: group_id.clone(),
            members: members.to_vec(),
            encrypted_keys,
        };
        Ok((group_id, cipher, payload))
    }

    fn apply_distribution(
        &mut self,
        payload: &Self::DistributionPayload,
    ) -> Result<(GroupId, Self::Cipher), Self::Error> {
        // Find the bundle addressed to us
        let my_idx = payload
            .members
            .iter()
            .position(|m| m == &self.my_peer_id)
            .ok_or(SenderKeyError::MemberPublicKeyNotFound)?;

        let my_bundle = &payload.encrypted_keys[my_idx];
        let dist = SenderKeyDistributor::new(self.my_hybrid_sk.clone());
        let group_key_bytes = dist.recover(my_bundle)?;

        let group_key: [u8; 32] = group_key_bytes
            .try_into()
            .map_err(|_| SenderKeyError::DecryptionFailed)?;

        self.groups.insert(
            *payload.group_id.as_bytes(),
            GroupState {
                members: payload.members.clone(),
                group_key,
            },
        );

        let cipher = SenderKeyCipher::new(group_key, *self.my_peer_id.as_bytes());
        Ok((payload.group_id.clone(), cipher))
    }

    fn add_member(
        &mut self,
        group_id: &GroupId,
        member: &Self::MemberId,
    ) -> Result<(Self::Cipher, Self::DistributionPayload), Self::Error> {
        let state = self
            .groups
            .get_mut(group_id.as_bytes())
            .ok_or(SenderKeyError::GroupNotFound)?;

        state.group_key = Self::random_group_key();
        state.members.push(member.clone());

        let encrypted_keys = Self::distribute_group_key(
            &self.my_hybrid_sk,
            &self.known_pks,
            &state.group_key,
            &state.members,
        )?;
        let cipher = SenderKeyCipher::new(state.group_key, *self.my_peer_id.as_bytes());
        let payload = SenderKeyDistributionPayload {
            group_id: group_id.clone(),
            members: state.members.clone(),
            encrypted_keys,
        };
        Ok((cipher, payload))
    }

    fn remove_member(
        &mut self,
        group_id: &GroupId,
        member: &Self::MemberId,
    ) -> Result<(Self::Cipher, Self::DistributionPayload), Self::Error> {
        let state = self
            .groups
            .get_mut(group_id.as_bytes())
            .ok_or(SenderKeyError::GroupNotFound)?;

        state.group_key = Self::random_group_key();
        state.members.retain(|m| m != member);

        let encrypted_keys = Self::distribute_group_key(
            &self.my_hybrid_sk,
            &self.known_pks,
            &state.group_key,
            &state.members,
        )?;
        let cipher = SenderKeyCipher::new(state.group_key, *self.my_peer_id.as_bytes());
        let payload = SenderKeyDistributionPayload {
            group_id: group_id.clone(),
            members: state.members.clone(),
            encrypted_keys,
        };
        Ok((cipher, payload))
    }

    fn rotate_key(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(Self::Cipher, Self::DistributionPayload), Self::Error> {
        let state = self
            .groups
            .get_mut(group_id.as_bytes())
            .ok_or(SenderKeyError::GroupNotFound)?;

        state.group_key = Self::random_group_key();

        let encrypted_keys = Self::distribute_group_key(
            &self.my_hybrid_sk,
            &self.known_pks,
            &state.group_key,
            &state.members,
        )?;
        let cipher = SenderKeyCipher::new(state.group_key, *self.my_peer_id.as_bytes());
        let payload = SenderKeyDistributionPayload {
            group_id: group_id.clone(),
            members: state.members.clone(),
            encrypted_keys,
        };
        Ok((cipher, payload))
    }

    fn dissolve(&mut self, group_id: &GroupId) -> Result<(), Self::Error> {
        self.groups
            .remove(group_id.as_bytes())
            .ok_or(SenderKeyError::GroupNotFound)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::traits::sign::Signer;

    /// Generate a test PeerId (unused byte param is intentional for distinctness).
    fn test_peer_id(_byte: u8) -> PeerId {
        PeerId::from_hybrid_pk(
            &crate::crypto::backend::pqc::ed25519::Ed25519Signer::keygen(&mut rand::rngs::OsRng).0,
            &crate::crypto::backend::pqc::ml_dsa::MlDsa65Signer::keygen(&mut rand::rngs::OsRng).0,
        )
    }

    /// Set up a test peer with keys and register them with the manager.
    struct TestPeer {
        peer_id: PeerId,
        hybrid_pk: HybridKemPublicKey<X25519Kem, MlKem768Kem>,
        hybrid_sk: HybridKemSecretKey<X25519Kem, MlKem768Kem>,
    }

    impl TestPeer {
        fn generate() -> Self {
            let (ed_pk, _ed_sk) =
                crate::crypto::backend::pqc::ed25519::Ed25519Signer::keygen(&mut rand::rngs::OsRng);
            let (ml_pk, _ml_sk) =
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

    /// Create a manager with `n` registered peers, returning (manager, peers).
    fn setup_manager(n: usize) -> (SenderKeyManager, Vec<TestPeer>) {
        let peers: Vec<TestPeer> = (0..n).map(|_| TestPeer::generate()).collect();
        let first = &peers[0];
        let mut mgr = SenderKeyManager::new(first.peer_id.clone(), first.hybrid_sk.clone());
        for p in &peers {
            mgr.register_member_pk(p.peer_id.clone(), p.hybrid_pk.clone());
        }
        (mgr, peers)
    }

    // ─── SenderKeyCipher ───

    #[test]
    fn cipher_encrypt_decrypt_roundtrip() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let ct = cipher.encrypt(b"hello sender key").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello sender key");
    }

    #[test]
    fn cipher_empty_plaintext() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let ct = cipher.encrypt(b"").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn cipher_large_plaintext() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let data = vec![0xabu8; 1024 * 100]; // 100 KiB
        let ct = cipher.encrypt(&data).unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn cipher_sequential_encrypts_differ() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let ct1 = cipher.encrypt(b"same").unwrap();
        let ct2 = cipher.encrypt(b"same").unwrap();
        assert_ne!(ct1, ct2);
        assert_eq!(cipher.decrypt(&ct1).unwrap(), b"same");
        assert_eq!(cipher.decrypt(&ct2).unwrap(), b"same");
    }

    #[test]
    fn cipher_stateless_decrypt_from_other_sender() {
        let key = [0x42; 32];
        let sender_a = [0xaa; 32];
        let sender_b = [0xbb; 32];

        // Sender A encrypts
        let mut cipher_a = SenderKeyCipher::new(key, sender_a);
        let ct = cipher_a.encrypt(b"from A").unwrap();

        // Sender B decrypts (different cipher instance, same group key)
        let cipher_b = SenderKeyCipher::new(key, sender_b);
        let pt = cipher_b.decrypt(&ct).unwrap();
        assert_eq!(pt, b"from A");
    }

    #[test]
    fn cipher_tampered_ciphertext_fails() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let mut ct = cipher.encrypt(b"tamper me").unwrap();
        // Flip a byte in the AEAD ciphertext portion
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(cipher.decrypt(&ct).is_err());
    }

    #[test]
    fn cipher_truncated_ciphertext_fails() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let cipher = SenderKeyCipher::new(key, sender);
        assert!(cipher.decrypt(&[0u8; 51]).is_err());
        assert!(cipher.decrypt(&[0u8; 0]).is_err());
        assert!(cipher.decrypt(&[0u8; HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn cipher_wrong_group_key_fails() {
        let key_a = [0x42; 32];
        let key_b = [0x99; 32];
        let sender = [0xaa; 32];
        let mut cipher_a = SenderKeyCipher::new(key_a, sender);
        let ct = cipher_a.encrypt(b"wrong key").unwrap();
        let cipher_b = SenderKeyCipher::new(key_b, sender);
        assert!(cipher_b.decrypt(&ct).is_err());
    }

    #[test]
    fn cipher_unicode_plaintext() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let msg = "你好世界 PQNodium 加密组播";
        let ct = cipher.encrypt(msg.as_bytes()).unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    #[test]
    fn cipher_out_of_order_decrypt() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let ct0 = cipher.encrypt(b"msg0").unwrap();
        let ct1 = cipher.encrypt(b"msg1").unwrap();
        let ct2 = cipher.encrypt(b"msg2").unwrap();

        // Decrypt in reverse order — stateless so this works
        let reader = SenderKeyCipher::new(key, [0xbb; 32]);
        assert_eq!(reader.decrypt(&ct2).unwrap(), b"msg2");
        assert_eq!(reader.decrypt(&ct0).unwrap(), b"msg0");
        assert_eq!(reader.decrypt(&ct1).unwrap(), b"msg1");
    }

    // ─── SenderKeyDistributor ───

    #[test]
    fn distributor_roundtrip_single() {
        let (pk, sk) = PqHybridKem::keygen_os();
        let dist = SenderKeyDistributor::new(sk);
        let group_key = [0x42; 32];
        let bundles = dist.distribute(&group_key, &[pk]).unwrap();
        assert_eq!(bundles.len(), 1);
        let recovered = dist.recover(&bundles[0]).unwrap();
        assert_eq!(recovered.as_slice(), group_key);
    }

    #[test]
    fn distributor_roundtrip_multiple() {
        let keys: Vec<_> = (0..5).map(|_| PqHybridKem::keygen_os()).collect();
        let pks: Vec<_> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let sk0 = keys[0].1.clone();
        let dist = SenderKeyDistributor::new(sk0);
        let group_key = [0xab; 32];
        let bundles = dist.distribute(&group_key, &pks).unwrap();
        assert_eq!(bundles.len(), 5);

        // Each recipient can recover
        for (i, (_, sk)) in keys.iter().enumerate() {
            let d = SenderKeyDistributor::new(sk.clone());
            let recovered = d.recover(&bundles[i]).unwrap();
            assert_eq!(recovered.as_slice(), group_key);
        }
    }

    #[test]
    fn distributor_zero_recipients() {
        let (_, sk) = PqHybridKem::keygen_os();
        let dist = SenderKeyDistributor::new(sk);
        let bundles = dist.distribute(&[0x42; 32], &[]).unwrap();
        assert!(bundles.is_empty());
    }

    #[test]
    fn distributor_wrong_key_fails() {
        let (pk1, sk1) = PqHybridKem::keygen_os();
        let (_, sk2) = PqHybridKem::keygen_os();
        let dist1 = SenderKeyDistributor::new(sk1);
        let group_key = [0x42; 32];
        let bundles = dist1.distribute(&group_key, &[pk1]).unwrap();
        let dist2 = SenderKeyDistributor::new(sk2);
        assert!(dist2.recover(&bundles[0]).is_err());
    }

    #[test]
    fn distributor_truncated_fails() {
        let (_, sk) = PqHybridKem::keygen_os();
        let dist = SenderKeyDistributor::new(sk);
        assert!(dist.recover(&[0u8; 100]).is_err());
        assert!(dist.recover(&[0u8; 0]).is_err());
    }

    #[test]
    fn distributor_bundle_size() {
        let (pk, sk) = PqHybridKem::keygen_os();
        let dist = SenderKeyDistributor::new(sk);
        let bundles = dist.distribute(&[0x42; 32], &[pk]).unwrap();
        // 1122 (KEM ct) + 12 (nonce) + 32 (encrypted key) + 16 (tag) = 1182
        assert_eq!(bundles[0].len(), KEM_BUNDLE_LEN);
    }

    // ─── SenderKeyManager ───

    #[test]
    fn manager_create_group() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher, payload) = mgr.create_group(&members).unwrap();
        assert_ne!(gid.as_bytes(), &[0u8; 32]);
        assert_eq!(payload.members.len(), 3);
        assert_eq!(payload.encrypted_keys.len(), 3);

        let ct = cipher.encrypt(b"hello group").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"hello group");
    }

    #[test]
    fn manager_apply_distribution() {
        let (mut mgr_creator, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (_, _, payload) = mgr_creator.create_group(&members).unwrap();

        // Peer 1 applies distribution
        let mut mgr_joiner =
            SenderKeyManager::new(peers[1].peer_id.clone(), peers[1].hybrid_sk.clone());
        for p in &peers {
            mgr_joiner.register_member_pk(p.peer_id.clone(), p.hybrid_pk.clone());
        }
        let (gid, mut cipher) = mgr_joiner.apply_distribution(&payload).unwrap();
        assert_eq!(gid, payload.group_id);
        let ct = cipher.encrypt(b"from joiner").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"from joiner");
    }

    #[test]
    fn manager_cross_member_encrypt_decrypt() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (_, mut creator_cipher, payload) = mgr.create_group(&members).unwrap();

        // Joiner
        let mut mgr_joiner =
            SenderKeyManager::new(peers[1].peer_id.clone(), peers[1].hybrid_sk.clone());
        for p in &peers {
            mgr_joiner.register_member_pk(p.peer_id.clone(), p.hybrid_pk.clone());
        }
        let (_, joiner_cipher) = mgr_joiner.apply_distribution(&payload).unwrap();

        // Creator encrypts, joiner decrypts
        let ct = creator_cipher.encrypt(b"from creator").unwrap();
        assert_eq!(joiner_cipher.decrypt(&ct).unwrap(), b"from creator");

        // Joiner encrypts, creator decrypts
        let joiner_gk = mgr_joiner
            .groups
            .get(payload.group_id.as_bytes())
            .unwrap()
            .group_key;
        let mut j = SenderKeyCipher::new(joiner_gk, *peers[1].peer_id.as_bytes());
        let ct2 = j.encrypt(b"from joiner").unwrap();
        assert_eq!(creator_cipher.decrypt(&ct2).unwrap(), b"from joiner");
    }

    #[test]
    fn manager_add_member_rekeys() {
        let (mut mgr, peers) = setup_manager(3);
        let new_peer = TestPeer::generate();
        mgr.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());

        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        let (cipher, payload) = mgr.add_member(&gid, &new_peer.peer_id).unwrap();
        assert_eq!(payload.members.len(), 4);
        assert!(payload.members.contains(&new_peer.peer_id));

        let mut c = cipher;
        let ct = c.encrypt(b"after add").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"after add");
    }

    #[test]
    fn manager_remove_member_rekeys() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        let (cipher, payload) = mgr.remove_member(&gid, &peers[1].peer_id).unwrap();
        assert_eq!(payload.members.len(), 2);
        assert!(!payload.members.contains(&peers[1].peer_id));

        let mut c = cipher;
        let ct = c.encrypt(b"after remove").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"after remove");
    }

    #[test]
    fn manager_rotate_key() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        let (cipher, _) = mgr.rotate_key(&gid).unwrap();
        let mut c = cipher;
        let ct = c.encrypt(b"rotated").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"rotated");
    }

    #[test]
    fn manager_dissolve() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        mgr.dissolve(&gid).unwrap();
        assert!(mgr.dissolve(&gid).is_err());
    }

    #[test]
    fn manager_operations_on_dissolved_fail() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.create_group(&members).unwrap();
        mgr.dissolve(&gid).unwrap();

        assert!(mgr.add_member(&gid, &peers[0].peer_id).is_err());
        assert!(mgr.remove_member(&gid, &peers[0].peer_id).is_err());
        assert!(mgr.rotate_key(&gid).is_err());
        assert!(mgr.dissolve(&gid).is_err());
    }

    #[test]
    fn manager_operations_on_nonexistent_fail() {
        let (mut mgr, _) = setup_manager(1);
        let fake = GroupId::from_bytes([0xff; 32]);
        let fake_member = test_peer_id(0);

        assert!(mgr.add_member(&fake, &fake_member).is_err());
        assert!(mgr.remove_member(&fake, &fake_member).is_err());
        assert!(mgr.rotate_key(&fake).is_err());
        assert!(mgr.dissolve(&fake).is_err());
    }

    #[test]
    fn manager_full_lifecycle() {
        let (mut mgr, peers) = setup_manager(3);
        let new_peer = TestPeer::generate();
        mgr.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());

        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();

        // Create
        let (gid, mut cipher, _payload) = mgr.create_group(&members).unwrap();
        let ct = cipher.encrypt(b"msg1").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"msg1");

        // Add
        let (cipher, _) = mgr.add_member(&gid, &new_peer.peer_id).unwrap();
        let mut c = cipher;
        let ct = c.encrypt(b"msg2").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"msg2");

        // Remove
        let (cipher, _) = mgr.remove_member(&gid, &peers[2].peer_id).unwrap();
        let mut c = cipher;
        let ct = c.encrypt(b"msg3").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"msg3");

        // Rotate
        let (cipher, _) = mgr.rotate_key(&gid).unwrap();
        let mut c = cipher;
        let ct = c.encrypt(b"msg4").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"msg4");

        // Dissolve
        mgr.dissolve(&gid).unwrap();
        assert!(mgr.rotate_key(&gid).is_err());
    }

    #[test]
    fn manager_rekey_produces_different_ciphertext() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher1, _) = mgr.create_group(&members).unwrap();
        let ct1 = cipher1.encrypt(b"test").unwrap();

        let (mut cipher2, _) = mgr.rotate_key(&gid).unwrap();
        let ct2 = cipher2.encrypt(b"test").unwrap();

        // Different group key → different ciphertext (even for same plaintext)
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn manager_multiple_groups_independent() {
        let (mut mgr, peers) = setup_manager(2);
        let members_a: Vec<PeerId> = vec![peers[0].peer_id.clone()];
        let members_b: Vec<PeerId> = vec![peers[1].peer_id.clone()];

        let (gid_a, mut cipher_a, _) = mgr.create_group(&members_a).unwrap();
        let (gid_b, mut cipher_b, _) = mgr.create_group(&members_b).unwrap();
        assert_ne!(gid_a, gid_b);

        let ct_a = cipher_a.encrypt(b"A").unwrap();
        let ct_b = cipher_b.encrypt(b"B").unwrap();

        // Each cipher can only decrypt its own messages
        assert_eq!(cipher_a.decrypt(&ct_a).unwrap(), b"A");
        assert_eq!(cipher_b.decrypt(&ct_b).unwrap(), b"B");
        assert!(cipher_a.decrypt(&ct_b).is_err());
        assert!(cipher_b.decrypt(&ct_a).is_err());

        // Dissolve one doesn't affect the other
        mgr.dissolve(&gid_a).unwrap();
        let (cipher_b2, _) = mgr.rotate_key(&gid_b).unwrap();
        let mut c = cipher_b2;
        let ct = c.encrypt(b"still alive").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"still alive");
    }

    // ─── Stress tests ───

    #[test]
    fn stress_cipher_10k_sequential_encrypts() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        for i in 0..10_000u64 {
            let msg = format!("message {i}");
            let ct = cipher.encrypt(msg.as_bytes()).unwrap();
            assert_eq!(
                cipher.decrypt(&ct).unwrap(),
                msg.as_bytes(),
                "failed at {i}"
            );
        }
    }

    #[test]
    fn stress_cipher_reverse_order_decrypt() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let ciphertexts: Vec<Vec<u8>> = (0..1000)
            .map(|i| {
                let msg = format!("msg-{i}");
                cipher.encrypt(msg.as_bytes()).unwrap()
            })
            .collect();

        // Decrypt in reverse — stateless so no step tracking needed
        let reader = SenderKeyCipher::new(key, [0xbb; 32]);
        for i in (0..1000).rev() {
            let expected = format!("msg-{i}");
            let pt = reader.decrypt(&ciphertexts[i]).unwrap();
            assert_eq!(pt, expected.as_bytes(), "failed at reverse decrypt {i}");
        }
    }

    #[test]
    fn stress_distributor_many_recipients() {
        let keys: Vec<_> = (0..50).map(|_| PqHybridKem::keygen_os()).collect();
        let pks: Vec<_> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let sk0 = keys[0].1.clone();
        let dist = SenderKeyDistributor::new(sk0);
        let group_key = [0x42; 32];
        let bundles = dist.distribute(&group_key, &pks).unwrap();
        assert_eq!(bundles.len(), 50);
        for (i, (_, sk)) in keys.iter().enumerate() {
            let d = SenderKeyDistributor::new(sk.clone());
            let recovered = d.recover(&bundles[i]).unwrap();
            assert_eq!(recovered.as_slice(), group_key);
        }
    }

    #[test]
    fn stress_manager_rapid_rotation() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        for _ in 0..50 {
            let (cipher, _) = mgr.rotate_key(&gid).unwrap();
            let mut c = cipher;
            let ct = c.encrypt(b"rotated").unwrap();
            assert_eq!(c.decrypt(&ct).unwrap(), b"rotated");
        }
    }

    // ─── Additional coverage tests ───

    #[test]
    fn cipher_single_byte() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let ct = cipher.encrypt(b"\x00").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, b"\x00");
    }

    #[test]
    fn cipher_binary_data_all_bytes() {
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let mut cipher = SenderKeyCipher::new(key, sender);
        let data: Vec<u8> = (0u8..=255).collect();
        let ct = cipher.encrypt(&data).unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn cipher_multi_sender_cross_decrypt() {
        let key = [0x42; 32];
        let sender_a = [0xaa; 32];
        let sender_b = [0xbb; 32];
        let sender_c = [0xcc; 32];

        let mut cipher_a = SenderKeyCipher::new(key, sender_a);
        let mut cipher_b = SenderKeyCipher::new(key, sender_b);
        let mut cipher_c = SenderKeyCipher::new(key, sender_c);

        let ct_a = cipher_a.encrypt(b"from A").unwrap();
        let ct_b = cipher_b.encrypt(b"from B").unwrap();
        let ct_c = cipher_c.encrypt(b"from C").unwrap();

        // Any cipher can decrypt messages from any sender (same group key)
        assert_eq!(cipher_c.decrypt(&ct_a).unwrap(), b"from A");
        assert_eq!(cipher_c.decrypt(&ct_b).unwrap(), b"from B");
        assert_eq!(cipher_b.decrypt(&ct_a).unwrap(), b"from A");
        assert_eq!(cipher_b.decrypt(&ct_c).unwrap(), b"from C");
        assert_eq!(cipher_a.decrypt(&ct_b).unwrap(), b"from B");
        assert_eq!(cipher_a.decrypt(&ct_c).unwrap(), b"from C");
    }

    #[test]
    fn distributor_independent_recovery() {
        let keys: Vec<_> = (0..5).map(|_| PqHybridKem::keygen_os()).collect();
        let pks: Vec<_> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        let sk0 = keys[0].1.clone();
        let dist = SenderKeyDistributor::new(sk0);
        let group_key = [0xab; 32];
        let bundles = dist.distribute(&group_key, &pks).unwrap();

        // Each recipient recovers independently with their own distributor
        for (i, (_, sk)) in keys.iter().enumerate() {
            let own_dist = SenderKeyDistributor::new(sk.clone());
            let recovered = own_dist.recover(&bundles[i]).unwrap();
            assert_eq!(recovered.as_slice(), group_key);
        }
    }

    #[test]
    fn manager_create_group_unique_ids() {
        let (mut mgr, peers) = setup_manager(2);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (id1, _, _) = mgr.create_group(&members).unwrap();
        let (id2, _, _) = mgr.create_group(&members).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn manager_single_member_group() {
        let (mut mgr, peers) = setup_manager(1);
        let members = vec![peers[0].peer_id.clone()];
        let (_, mut cipher, _) = mgr.create_group(&members).unwrap();
        let ct = cipher.encrypt(b"solo").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"solo");
    }

    #[test]
    fn manager_add_then_remove_same_member() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        let new_peer = TestPeer::generate();
        mgr.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());

        let (_, payload) = mgr.add_member(&gid, &new_peer.peer_id).unwrap();
        assert_eq!(payload.members.len(), 4);

        let (_, payload) = mgr.remove_member(&gid, &new_peer.peer_id).unwrap();
        assert_eq!(payload.members.len(), 3);
        assert!(!payload.members.contains(&new_peer.peer_id));
    }

    #[test]
    fn manager_multi_member_concurrent_encrypt() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (_, _, payload) = mgr.create_group(&members).unwrap();

        // Each peer independently builds a cipher from the distribution payload
        let mut ciphers: Vec<SenderKeyCipher> = Vec::new();
        for peer in &peers {
            let mut peer_mgr = SenderKeyManager::new(peer.peer_id.clone(), peer.hybrid_sk.clone());
            for p in &peers {
                peer_mgr.register_member_pk(p.peer_id.clone(), p.hybrid_pk.clone());
            }
            let (_, cipher) = peer_mgr.apply_distribution(&payload).unwrap();
            ciphers.push(cipher);
        }

        // Each peer encrypts a message
        let mut ciphertexts: Vec<Vec<u8>> = Vec::new();
        for (i, cipher) in ciphers.iter_mut().enumerate() {
            let msg = format!("peer {i}");
            let ct = cipher.encrypt(msg.as_bytes()).unwrap();
            ciphertexts.push(ct);
        }

        // Every peer can decrypt every other peer's messages
        for cipher in &ciphers {
            for (i, ct) in ciphertexts.iter().enumerate() {
                let expected = format!("peer {i}");
                assert_eq!(cipher.decrypt(ct).unwrap(), expected.as_bytes());
            }
        }
    }

    // ─── Additional stress tests ───

    #[test]
    fn stress_manager_create_dissolve_cycle() {
        for _ in 0..20 {
            let (mut mgr, peers) = setup_manager(2);
            let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
            let (gid, mut cipher, _) = mgr.create_group(&members).unwrap();
            let ct = cipher.encrypt(b"temp").unwrap();
            assert_eq!(cipher.decrypt(&ct).unwrap(), b"temp");
            mgr.dissolve(&gid).unwrap();
        }
    }

    #[test]
    fn stress_manager_churn_add_remove() {
        let (mut mgr, peers) = setup_manager(3);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, _, _) = mgr.create_group(&members).unwrap();

        for i in 0..20u8 {
            let p = TestPeer::generate();
            mgr.register_member_pk(p.peer_id.clone(), p.hybrid_pk.clone());

            let (cipher, _) = mgr.add_member(&gid, &p.peer_id).unwrap();
            let mut c = cipher;
            let msg = format!("after add {i}");
            let ct = c.encrypt(msg.as_bytes()).unwrap();
            assert_eq!(c.decrypt(&ct).unwrap(), msg.as_bytes());

            let (cipher, _) = mgr.remove_member(&gid, &p.peer_id).unwrap();
            let mut c = cipher;
            let ct = c.encrypt(b"after remove").unwrap();
            assert_eq!(c.decrypt(&ct).unwrap(), b"after remove");
        }
    }

    #[test]
    fn stress_manager_large_group() {
        let n = 30;
        let (mut mgr, peers) = setup_manager(n);
        let members: Vec<PeerId> = peers.iter().map(|p| p.peer_id.clone()).collect();
        let (gid, mut cipher, payload) = mgr.create_group(&members).unwrap();
        assert_eq!(payload.members.len(), n);
        assert_eq!(payload.encrypted_keys.len(), n);

        let ct = cipher.encrypt(b"big group").unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"big group");

        // Add one more
        let new_peer = TestPeer::generate();
        mgr.register_member_pk(new_peer.peer_id.clone(), new_peer.hybrid_pk.clone());
        let (cipher, payload) = mgr.add_member(&gid, &new_peer.peer_id).unwrap();
        assert_eq!(payload.members.len(), n + 1);
        let mut c = cipher;
        let ct = c.encrypt(b"bigger").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"bigger");
    }

    #[test]
    fn stress_chain_large_step() {
        // Derive at a moderately large step to verify it doesn't blow up
        let key = [0x42; 32];
        let sender = [0xaa; 32];
        let (mk, _) = ChainKey::derive_at_step(&key, &sender, 1000).unwrap();
        assert_eq!(mk.as_bytes().len(), 32);

        // Step 1000 and 1001 must differ
        let (mk2, _) = ChainKey::derive_at_step(&key, &sender, 1001).unwrap();
        assert_ne!(mk.as_bytes(), mk2.as_bytes());
    }
}
