use crate::crypto::traits::sign::Signer;
use crystals_dilithium::ml_dsa_65::{Keypair, PublicKey, SecretKey};
use crystals_dilithium::RandomMode;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct MlDsa65PublicKey(Vec<u8>);

impl AsRef<[u8]> for MlDsa65PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65SecretKey(Vec<u8>);

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
        (
            MlDsa65PublicKey(kp.public.to_bytes().to_vec()),
            MlDsa65SecretKey(kp.secret.to_bytes().to_vec()),
        )
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        let sk = SecretKey::from_bytes(&sk.0).expect("secret key bytes valid");
        let kp = Keypair {
            secret: sk,
            public: PublicKey::from_bytes(&[0u8; 1952]).unwrap(),
        };
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
