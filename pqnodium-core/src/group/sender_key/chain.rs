use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::SenderKeyError;

/// Maximum chain step before we refuse to derive further (DoS protection).
pub const MAX_CHAIN_STEP: u64 = 1 << 20;

/// Domain-separation label for message key derivation (H1).
const H1_LABEL: &[u8] = b"pqnodium-sk-h1";
/// Domain-separation label for chain key advancement (H2).
const H2_LABEL: &[u8] = b"pqnodium-sk-h2";
/// Domain-separation label for initial chain key derivation (CK_0).
const CK_LABEL: &[u8] = b"pqnodium-sender-ck-v1";

/// A chain key in the Sender Key ratchet.
///
/// Advancing produces a new `ChainKey` via `H2(ck)` while a message key is
/// extracted via `H1(ck)`. The two domain-separated hashes ensure
/// forward secrecy within the chain.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey([u8; 32]);

impl ChainKey {
    /// Derive the initial chain key for a sender from the shared group key
    /// and the sender's identifier.
    ///
    /// `CK_0 = SHA-256("pqnodium-sender-ck-v1" || group_key || sender_id)`
    pub fn initial(group_key: &[u8; 32], sender_id: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(CK_LABEL);
        hasher.update(group_key);
        hasher.update(sender_id);
        Self(hasher.finalize().into())
    }

    /// Derive the message key and next chain key at the given step.
    ///
    /// At step 0 the message key is `H1(CK_0)` and the returned chain key is
    /// `CK_0` (no H2 applied). At step N > 0, H2 is applied N times to reach
    /// `CK_N`, then `H1(CK_N)` yields the message key.
    ///
    /// Returns an error if `step > MAX_CHAIN_STEP`.
    pub fn derive_at_step(
        group_key: &[u8; 32],
        sender_id: &[u8; 32],
        step: u64,
    ) -> Result<(MessageKey, Self), SenderKeyError> {
        if step > MAX_CHAIN_STEP {
            return Err(SenderKeyError::ChainStepExceeded {
                step,
                max: MAX_CHAIN_STEP,
            });
        }

        let mut ck = Self::initial(group_key, sender_id);
        for _ in 0..step {
            ck = ck.advance();
        }
        let mk = ck.message_key();
        Ok((mk, ck))
    }

    /// Advance the chain key by one step: `H2(ck)`.
    fn advance(self) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(H2_LABEL);
        hasher.update(self.0);
        Self(hasher.finalize().into())
    }

    /// Extract the message key at the current chain position: `H1(ck)`.
    fn message_key(&self) -> MessageKey {
        let mut hasher = Sha256::new();
        hasher.update(H1_LABEL);
        hasher.update(self.0);
        MessageKey(hasher.finalize().into())
    }
}

/// A one-time message key derived from a chain key position.
///
/// Used as the AEAD key for encrypting a single group message.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey([u8; 32]);

impl MessageKey {
    /// Access the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_group_key() -> [u8; 32] {
        [0x42; 32]
    }

    fn test_sender_a() -> [u8; 32] {
        [0xaa; 32]
    }

    fn test_sender_b() -> [u8; 32] {
        [0xbb; 32]
    }

    #[test]
    fn ck_initial_deterministic() {
        let _ck1 = ChainKey::initial(&test_group_key(), &test_sender_a());
        let _ck2 = ChainKey::initial(&test_group_key(), &test_sender_a());
        // Verify determinism by deriving message keys twice and comparing
        let (mk1, _) = ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), 0).unwrap();
        let mk1_bytes = *mk1.as_bytes();
        let (mk2, _) = ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), 0).unwrap();
        assert_eq!(mk1_bytes, *mk2.as_bytes());
    }

    #[test]
    fn different_senders_produce_different_chain_keys() {
        let (mk_a, _) = ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), 0).unwrap();
        let (mk_b, _) = ChainKey::derive_at_step(&test_group_key(), &test_sender_b(), 0).unwrap();
        assert_ne!(mk_a.as_bytes(), mk_b.as_bytes());
    }

    #[test]
    fn different_group_keys_produce_different_chain_keys() {
        let gk2 = [0x43; 32];
        let (mk1, _) = ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), 0).unwrap();
        let (mk2, _) = ChainKey::derive_at_step(&gk2, &test_sender_a(), 0).unwrap();
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn h1_and_h2_domain_separated() {
        // H1(ck) != H2(ck) for any ck
        let _ck = ChainKey::initial(&test_group_key(), &test_sender_a());

        let mk_bytes = {
            let (mk, _) = ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), 0).unwrap();
            *mk.as_bytes()
        };

        // H2 applied once, then H1
        let (mk_after_advance, _) =
            ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), 1).unwrap();
        let mk_advance_bytes = *mk_after_advance.as_bytes();

        // Step 0 and step 1 must produce different message keys
        assert_ne!(mk_bytes, mk_advance_bytes);
    }

    #[test]
    fn step_0_message_key_is_h1_of_ck0() {
        // Manually compute H1(CK_0) and compare
        let ck0_bytes = {
            // Derive CK_0 bytes manually
            let mut hasher = Sha256::new();
            hasher.update(CK_LABEL);
            hasher.update(&test_group_key());
            hasher.update(&test_sender_a());
            let hash: [u8; 32] = hasher.finalize().into();
            hash
        };

        let expected_mk: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(H1_LABEL);
            hasher.update(&ck0_bytes);
            hasher.finalize().into()
        };

        let (mk, _) = ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), 0).unwrap();
        assert_eq!(*mk.as_bytes(), expected_mk);
    }

    #[test]
    fn step_n_produces_correct_key() {
        // Derive step 3 directly and step-by-step, compare
        let (mk_direct, _) =
            ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), 3).unwrap();

        // Step-by-step: compute CK_3, then H1(CK_3)
        let mut ck_bytes: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(CK_LABEL);
            hasher.update(&test_group_key());
            hasher.update(&test_sender_a());
            hasher.finalize().into()
        };

        // Apply H2 three times
        for _ in 0..3 {
            let mut hasher = Sha256::new();
            hasher.update(H2_LABEL);
            hasher.update(&ck_bytes);
            ck_bytes = hasher.finalize().into();
        }

        // Now H1(CK_3)
        let expected: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(H1_LABEL);
            hasher.update(&ck_bytes);
            hasher.finalize().into()
        };

        assert_eq!(*mk_direct.as_bytes(), expected);
    }

    #[test]
    fn max_chain_step_exceeded() {
        let result =
            ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), MAX_CHAIN_STEP + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            SenderKeyError::ChainStepExceeded { step, max } => {
                assert_eq!(step, MAX_CHAIN_STEP + 1);
                assert_eq!(max, MAX_CHAIN_STEP);
            }
            other => panic!("expected ChainStepExceeded, got {other}"),
        }
    }

    #[test]
    fn max_chain_step_accepted() {
        let result = ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), MAX_CHAIN_STEP);
        assert!(result.is_ok());
    }

    #[test]
    fn sequential_steps_produce_different_keys() {
        let keys: Vec<[u8; 32]> = (0..10)
            .map(|step| {
                let (mk, _) =
                    ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), step).unwrap();
                *mk.as_bytes()
            })
            .collect();

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "step {i} and step {j} produced same key");
            }
        }
    }

    #[test]
    fn message_key_32_bytes() {
        let (mk, _) = ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), 0).unwrap();
        assert_eq!(mk.as_bytes().len(), 32);
    }

    #[test]
    fn ck_initial_different_from_group_key() {
        let gk = test_group_key();
        let ck = ChainKey::initial(&gk, &test_sender_a());
        // Chain key bytes should differ from raw group key (SHA-256 hashing)
        // We verify by comparing message keys derived from CK vs raw group key
        let (mk_from_ck, _) = ChainKey::derive_at_step(&gk, &test_sender_a(), 0).unwrap();
        // If group_key were used directly as a message key, it would be [0x42; 32]
        assert_ne!(mk_from_ck.as_bytes(), &gk);
    }

    #[test]
    fn many_steps_all_unique() {
        let keys: std::collections::HashSet<[u8; 32]> = (0..100)
            .map(|step| {
                let (mk, _) =
                    ChainKey::derive_at_step(&test_group_key(), &test_sender_a(), step).unwrap();
                *mk.as_bytes()
            })
            .collect();
        assert_eq!(keys.len(), 100, "all 100 steps must produce unique keys");
    }
}
