use crate::crypto::backend::pqc::ed25519::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signer};
use crate::crypto::backend::pqc::ml_dsa::{MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signer};
use crate::crypto::hybrid::hybrid_sig::HybridSignature;
use crate::crypto::traits::sign::Signer;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

/// A unique peer identifier derived from the hash of both Ed25519 and ML-DSA-65 public keys.
///
/// This binds the classical and PQ identity together: changing either key pair
/// produces a different PeerId, preventing identity substitution attacks.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Derive a PeerId from Ed25519 + ML-DSA-65 public keys.
    pub fn from_hybrid_pk(ed_pk: &Ed25519PublicKey, ml_pk: &MlDsa65PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"pqnodium-peerid-v1");
        hasher.update(ed_pk.as_ref());
        hasher.update(ml_pk.as_ref());
        Self(hasher.finalize().into())
    }

    /// Return the raw 32-byte PeerId.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerId({self})")
    }
}

/// A complete identity with hybrid signing keys.
pub struct Identity {
    ed25519_pk: Ed25519PublicKey,
    ed25519_sk: Ed25519SecretKey,
    mldsa65_pk: MlDsa65PublicKey,
    mldsa65_sk: MlDsa65SecretKey,
    peer_id: PeerId,
}

impl Identity {
    /// Generate a new identity with fresh keypairs.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (ed25519_pk, ed25519_sk) = Ed25519Signer::keygen(rng);
        let (mldsa65_pk, mldsa65_sk) = MlDsa65Signer::keygen(rng);
        let peer_id = PeerId::from_hybrid_pk(&ed25519_pk, &mldsa65_pk);
        Self {
            ed25519_pk,
            ed25519_sk,
            mldsa65_pk,
            mldsa65_sk,
            peer_id,
        }
    }

    /// Reconstruct an identity from existing key material.
    pub fn from_keys(
        ed25519_pk: Ed25519PublicKey,
        ed25519_sk: Ed25519SecretKey,
        mldsa65_pk: MlDsa65PublicKey,
        mldsa65_sk: MlDsa65SecretKey,
    ) -> Self {
        let peer_id = PeerId::from_hybrid_pk(&ed25519_pk, &mldsa65_pk);
        Self {
            ed25519_pk,
            ed25519_sk,
            mldsa65_pk,
            mldsa65_sk,
            peer_id,
        }
    }

    /// Return the derived PeerId.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Return the Ed25519 public key.
    pub fn ed25519_public_key(&self) -> &Ed25519PublicKey {
        &self.ed25519_pk
    }

    /// Return the ML-DSA-65 public key.
    pub fn mldsa65_public_key(&self) -> &MlDsa65PublicKey {
        &self.mldsa65_pk
    }

    /// Return the Ed25519 secret key.
    pub fn ed25519_secret_key(&self) -> &Ed25519SecretKey {
        &self.ed25519_sk
    }

    /// Return the ML-DSA-65 secret key.
    pub fn mldsa65_secret_key(&self) -> &MlDsa65SecretKey {
        &self.mldsa65_sk
    }

    /// Hybrid sign a message (both Ed25519 and ML-DSA-65).
    pub fn sign(&self, msg: &[u8]) -> HybridSignature<Ed25519Signer, MlDsa65Signer> {
        let classic_sig = Ed25519Signer::sign(&self.ed25519_sk, msg);
        let pqc_sig = MlDsa65Signer::sign(&self.mldsa65_sk, msg);
        let encoded = crate::crypto::hybrid::hybrid_sig::encode_hybrid_sig::<
            Ed25519Signer,
            MlDsa65Signer,
        >(&classic_sig, &pqc_sig);
        HybridSignature {
            classic: classic_sig,
            pqc: pqc_sig,
            encoded,
        }
    }

    /// Export public components for sharing.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            peer_id: self.peer_id.clone(),
            ed25519_pk: self.ed25519_pk.clone(),
            mldsa65_pk: self.mldsa65_pk.clone(),
        }
    }
}

/// Public portion of an identity for verification.
#[derive(Clone)]
pub struct PublicIdentity {
    peer_id: PeerId,
    ed25519_pk: Ed25519PublicKey,
    mldsa65_pk: MlDsa65PublicKey,
}

impl PublicIdentity {
    /// Return the derived PeerId.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Return the Ed25519 public key.
    pub fn ed25519_public_key(&self) -> &Ed25519PublicKey {
        &self.ed25519_pk
    }

    /// Return the ML-DSA-65 public key.
    pub fn mldsa65_public_key(&self) -> &MlDsa65PublicKey {
        &self.mldsa65_pk
    }

    /// Verify a hybrid signature.
    pub fn verify(&self, msg: &[u8], sig: &HybridSignature<Ed25519Signer, MlDsa65Signer>) -> bool {
        Ed25519Signer::verify(&self.ed25519_pk, msg, &sig.classic)
            && MlDsa65Signer::verify(&self.mldsa65_pk, msg, &sig.pqc)
    }

    /// Reconstruct from individual public keys.
    pub fn from_parts(ed25519_pk: Ed25519PublicKey, mldsa65_pk: MlDsa65PublicKey) -> Self {
        let peer_id = PeerId::from_hybrid_pk(&ed25519_pk, &mldsa65_pk);
        Self {
            peer_id,
            ed25519_pk,
            mldsa65_pk,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn generate_identity() {
        let identity = Identity::generate(&mut OsRng);
        assert!(!identity.peer_id().as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn peer_id_deterministic() {
        let identity = Identity::generate(&mut OsRng);
        let ed_pk = identity.ed25519_public_key();
        let ml_pk = identity.mldsa65_public_key();
        let peer_id2 = PeerId::from_hybrid_pk(ed_pk, ml_pk);
        assert_eq!(identity.peer_id(), &peer_id2);
    }

    #[test]
    fn hybrid_sign_verify() {
        let identity = Identity::generate(&mut OsRng);
        let msg = b"hello pqnodium";
        let sig = identity.sign(msg);
        assert!(identity.public().verify(msg, &sig));
    }

    #[test]
    fn verify_wrong_message_fails() {
        let identity = Identity::generate(&mut OsRng);
        let sig = identity.sign(b"correct message");
        assert!(!identity.public().verify(b"wrong message", &sig));
    }

    #[test]
    fn verify_wrong_identity_fails() {
        let identity1 = Identity::generate(&mut OsRng);
        let identity2 = Identity::generate(&mut OsRng);
        let sig = identity1.sign(b"hello");
        assert!(!identity2.public().verify(b"hello", &sig));
    }

    #[test]
    fn public_identity_from_parts() {
        let identity = Identity::generate(&mut OsRng);
        let pub_id = PublicIdentity::from_parts(
            identity.ed25519_public_key().clone(),
            identity.mldsa65_public_key().clone(),
        );
        assert_eq!(identity.peer_id(), pub_id.peer_id());

        let msg = b"test message";
        let sig = identity.sign(msg);
        assert!(pub_id.verify(msg, &sig));
    }

    #[test]
    fn peer_id_display() {
        let identity = Identity::generate(&mut OsRng);
        let display = format!("{}", identity.peer_id());
        assert_eq!(display.len(), 16); // 8 bytes hex = 16 chars
    }
}
