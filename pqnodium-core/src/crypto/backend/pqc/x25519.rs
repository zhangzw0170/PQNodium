use crate::crypto::traits::kem::{KemError, KeyEncapsulation, SharedSecret};
use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct X25519PublicKey([u8; 32]);

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey(pub [u8; 32]);

pub struct X25519Kem;

impl KeyEncapsulation for X25519Kem {
    type PublicKey = X25519PublicKey;
    type SecretKey = X25519SecretKey;

    fn keygen<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let secret = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        (
            X25519PublicKey(*public.as_bytes()),
            X25519SecretKey(secret.to_bytes()),
        )
    }

    fn encapsulate<R: CryptoRngCore>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret), KemError> {
        let ephemeral_secret = StaticSecret::random_from_rng(rng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let pk_dalek = PublicKey::from(pk.0);
        let shared = ephemeral_secret.diffie_hellman(&pk_dalek);
        Ok((
            ephemeral_public.as_bytes().to_vec(),
            SharedSecret::new(shared.as_bytes().to_vec()),
        ))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<SharedSecret, KemError> {
        let ct_arr: [u8; 32] = ct.try_into().map_err(|_| KemError::InvalidCiphertext {
            expected: 32,
            got: ct.len(),
        })?;
        let ephemeral_public = PublicKey::from(ct_arr);
        let secret = StaticSecret::from(sk.0);
        let shared = secret.diffie_hellman(&ephemeral_public);
        Ok(SharedSecret::new(shared.as_bytes().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn roundtrip() {
        let (pk_alice, sk_alice) = X25519Kem::keygen(&mut OsRng);
        let (ct, ss_bob) = X25519Kem::encapsulate(&pk_alice, &mut OsRng).unwrap();
        let ss_alice = X25519Kem::decapsulate(&sk_alice, &ct).unwrap();
        assert_eq!(ss_bob.as_bytes(), ss_alice.as_bytes());
    }

    #[test]
    fn key_sizes() {
        let (pk, _) = X25519Kem::keygen(&mut OsRng);
        assert_eq!(pk.as_ref().len(), 32);
    }

    #[test]
    fn ciphertext_size() {
        let (pk, _) = X25519Kem::keygen(&mut OsRng);
        let (ct, _) = X25519Kem::encapsulate(&pk, &mut OsRng).unwrap();
        assert_eq!(ct.len(), 32);
    }
}
