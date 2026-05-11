use crate::crypto::traits::sign::Signer;
use crystals_dilithium::ml_dsa_65::{Keypair, PublicKey, SecretKey};
use crystals_dilithium::RandomMode;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct MlDsa65PublicKey(Vec<u8>);

impl MlDsa65PublicKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        Some(Self(bytes.to_vec()))
    }
}

impl AsRef<[u8]> for MlDsa65PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA-65 secret key. Internally stores both secret and public key bytes
/// because `crystals-dilithium` requires a `Keypair` (not just `SecretKey`) for signing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65SecretKey {
    secret: Vec<u8>,
    public: Vec<u8>,
}

impl MlDsa65SecretKey {
    pub fn from_bytes(secret: Vec<u8>, public: Vec<u8>) -> Self {
        Self { secret, public }
    }

    pub fn try_from_slice(secret: &[u8], public: &[u8]) -> Option<Self> {
        if secret.is_empty() || public.is_empty() {
            return None;
        }
        Some(Self {
            secret: secret.to_vec(),
            public: public.to_vec(),
        })
    }

    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }

    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }
}

#[derive(Clone)]
pub struct MlDsa65Signature(Vec<u8>);

impl AsRef<[u8]> for MlDsa65Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct MlDsa65Signer;

impl Signer for MlDsa65Signer {
    type PublicKey = MlDsa65PublicKey;
    type SecretKey = MlDsa65SecretKey;
    type Signature = MlDsa65Signature;

    fn keygen<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let kp = Keypair::generate(Some(&seed)).expect("seed length is always 32");
        let pk_bytes = kp.public.to_bytes().to_vec();
        let sk_bytes = kp.secret.to_bytes().to_vec();
        (
            MlDsa65PublicKey(pk_bytes.clone()),
            MlDsa65SecretKey::from_bytes(sk_bytes, pk_bytes),
        )
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        let secret = SecretKey::from_bytes(sk.secret_bytes()).expect("secret key bytes valid");
        let public = PublicKey::from_bytes(sk.public_bytes()).expect("public key bytes valid");
        let kp = Keypair { secret, public };
        let sig = kp
            .sign(msg, None, RandomMode::Deterministic)
            .expect("signing should succeed");
        MlDsa65Signature(sig.to_vec())
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        let Ok(pk) = PublicKey::from_bytes(&pk.0) else {
            return false;
        };
        pk.verify(msg, &sig.0, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = MlDsa65Signer::keygen(&mut OsRng);
        let msg = b"hello pqnodium";
        let sig = MlDsa65Signer::sign(&sk, msg);
        assert!(MlDsa65Signer::verify(&pk, msg, &sig));
    }

    #[test]
    fn verify_wrong_message_fails() {
        let (pk, sk) = MlDsa65Signer::keygen(&mut OsRng);
        let sig = MlDsa65Signer::sign(&sk, b"correct message");
        assert!(!MlDsa65Signer::verify(&pk, b"wrong message", &sig));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (_pk1, sk1) = MlDsa65Signer::keygen(&mut OsRng);
        let (pk2, _) = MlDsa65Signer::keygen(&mut OsRng);
        let sig = MlDsa65Signer::sign(&sk1, b"hello");
        assert!(!MlDsa65Signer::verify(&pk2, b"hello", &sig));
    }

    #[test]
    fn key_sizes() {
        let (pk, sk) = MlDsa65Signer::keygen(&mut OsRng);
        assert_eq!(pk.as_ref().len(), 1952);
        let sig = MlDsa65Signer::sign(&sk, b"test");
        assert_eq!(sig.as_ref().len(), 3309);
    }
}
