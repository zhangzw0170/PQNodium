use crate::crypto::traits::sign::Signer;
use ed25519_dalek::{Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct Ed25519PublicKey {
    bytes: [u8; 32],
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519SecretKey {
    bytes: [u8; 32],
}

#[derive(Clone)]
pub struct Ed25519Signature([u8; 64]);

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct Ed25519Signer;

impl Signer for Ed25519Signer {
    type PublicKey = Ed25519PublicKey;
    type SecretKey = Ed25519SecretKey;
    type Signature = Ed25519Signature;

    fn keygen<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let sk = SigningKey::generate(rng);
        let pk_bytes = sk.verifying_key().to_bytes();
        let sk_bytes = sk.to_bytes();
        (
            Ed25519PublicKey { bytes: pk_bytes },
            Ed25519SecretKey { bytes: sk_bytes },
        )
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        let sk = SigningKey::from_bytes(&sk.bytes);
        let sig = sk.sign(msg);
        Ed25519Signature(sig.to_bytes())
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&pk.bytes) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        vk.verify(msg, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = Ed25519Signer::keygen(&mut OsRng);
        let msg = b"hello pqnodium";
        let sig = Ed25519Signer::sign(&sk, msg);
        assert!(Ed25519Signer::verify(&pk, msg, &sig));
    }

    #[test]
    fn verify_wrong_message_fails() {
        let (pk, sk) = Ed25519Signer::keygen(&mut OsRng);
        let sig = Ed25519Signer::sign(&sk, b"correct message");
        assert!(!Ed25519Signer::verify(&pk, b"wrong message", &sig));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (_pk1, sk1) = Ed25519Signer::keygen(&mut OsRng);
        let (pk2, _) = Ed25519Signer::keygen(&mut OsRng);
        let sig = Ed25519Signer::sign(&sk1, b"hello");
        assert!(!Ed25519Signer::verify(&pk2, b"hello", &sig));
    }

    #[test]
    fn key_sizes() {
        let (pk, sk) = Ed25519Signer::keygen(&mut OsRng);
        assert_eq!(pk.as_ref().len(), 32);
        let sig = Ed25519Signer::sign(&sk, b"test");
        assert_eq!(sig.as_ref().len(), 64);
    }
}
