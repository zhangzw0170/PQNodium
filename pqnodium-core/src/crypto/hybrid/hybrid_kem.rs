use crate::crypto::traits::kem::{KemError, KeyEncapsulation, SharedSecret};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Combined public key from two KEM schemes.
pub struct HybridKemPublicKey<K1: KeyEncapsulation, K2: KeyEncapsulation> {
    pub classic: K1::PublicKey,
    pub pqc: K2::PublicKey,
}

impl<K1: KeyEncapsulation, K2: KeyEncapsulation> Clone for HybridKemPublicKey<K1, K2> {
    fn clone(&self) -> Self {
        Self {
            classic: self.classic.clone(),
            pqc: self.pqc.clone(),
        }
    }
}

impl<K1: KeyEncapsulation, K2: KeyEncapsulation> AsRef<[u8]> for HybridKemPublicKey<K1, K2> {
    fn as_ref(&self) -> &[u8] {
        // Hybrid keys are serialized separately; this returns empty as
        // the hybrid key is not a single byte array
        &[]
    }
}

/// Combined secret key from two KEM schemes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridKemSecretKey<K1: KeyEncapsulation, K2: KeyEncapsulation> {
    pub classic: K1::SecretKey,
    pub pqc: K2::SecretKey,
}

impl<K1: KeyEncapsulation, K2: KeyEncapsulation> Clone for HybridKemSecretKey<K1, K2>
where
    K1::SecretKey: Clone,
    K2::SecretKey: Clone,
{
    fn clone(&self) -> Self {
        Self {
            classic: self.classic.clone(),
            pqc: self.pqc.clone(),
        }
    }
}

/// Hybrid KEM combining a classical KEM with a PQC KEM.
///
/// SharedSecret = KDF(classic_ss || pqc_ss) where KDF is SHA-256.
pub struct HybridKem<K1, K2>(std::marker::PhantomData<(K1, K2)>);

impl<K1: KeyEncapsulation, K2: KeyEncapsulation> KeyEncapsulation for HybridKem<K1, K2> {
    type PublicKey = HybridKemPublicKey<K1, K2>;
    type SecretKey = HybridKemSecretKey<K1, K2>;

    fn keygen<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let (pk1, sk1) = K1::keygen(rng);
        let (pk2, sk2) = K2::keygen(rng);
        (
            HybridKemPublicKey {
                classic: pk1,
                pqc: pk2,
            },
            HybridKemSecretKey {
                classic: sk1,
                pqc: sk2,
            },
        )
    }

    fn encapsulate<R: CryptoRngCore>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret), KemError> {
        let (classic_ct, classic_ss) = K1::encapsulate(&pk.classic, rng)?;
        let (pqc_ct, pqc_ss) = K2::encapsulate(&pk.pqc, rng)?;

        let mut hasher = Sha256::new();
        hasher.update(classic_ss.as_bytes());
        hasher.update(pqc_ss.as_bytes());
        let combined_ss = hasher.finalize().to_vec();

        let classic_len = classic_ct.len() as u16;
        let mut ct = Vec::with_capacity(2 + classic_ct.len() + pqc_ct.len());
        ct.extend_from_slice(&classic_len.to_le_bytes());
        ct.extend_from_slice(&classic_ct);
        ct.extend_from_slice(&pqc_ct);

        Ok((ct, SharedSecret::new(combined_ss)))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<SharedSecret, KemError> {
        if ct.len() < 2 {
            return Err(KemError::InvalidCiphertext {
                expected: 2,
                got: ct.len(),
            });
        }

        let classic_len = u16::from_le_bytes([ct[0], ct[1]]) as usize;
        if ct.len() < 2 + classic_len {
            return Err(KemError::InvalidCiphertext {
                expected: 2 + classic_len,
                got: ct.len(),
            });
        }

        let classic_ct = &ct[2..2 + classic_len];
        let pqc_ct = &ct[2 + classic_len..];

        let classic_ss = K1::decapsulate(&sk.classic, classic_ct)?;
        let pqc_ss = K2::decapsulate(&sk.pqc, pqc_ct)?;

        let mut hasher = Sha256::new();
        hasher.update(classic_ss.as_bytes());
        hasher.update(pqc_ss.as_bytes());
        let combined_ss = hasher.finalize().to_vec();

        Ok(SharedSecret::new(combined_ss))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::backend::pqc::ml_kem::MlKem768Kem;
    use crate::crypto::backend::pqc::x25519::X25519Kem;
    use rand::rngs::OsRng;

    type X25519MlKem768 = HybridKem<X25519Kem, MlKem768Kem>;

    #[test]
    fn hybrid_kem_roundtrip() {
        let (pk, sk) = X25519MlKem768::keygen(&mut OsRng);
        let (ct, ss_sender) = X25519MlKem768::encapsulate(&pk, &mut OsRng).unwrap();
        let ss_receiver = X25519MlKem768::decapsulate(&sk, &ct).unwrap();
        assert!(ss_sender.ct_eq(&ss_receiver));
    }

    #[test]
    fn hybrid_shared_secret_is_32_bytes() {
        let (pk, sk) = X25519MlKem768::keygen(&mut OsRng);
        let (ct, ss) = X25519MlKem768::encapsulate(&pk, &mut OsRng).unwrap();
        let ss2 = X25519MlKem768::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss.as_bytes().len(), 32);
        assert!(ss.ct_eq(&ss2));
    }

    #[test]
    fn hybrid_ciphertext_contains_both() {
        let (pk, _) = X25519MlKem768::keygen(&mut OsRng);
        let (ct, _) = X25519MlKem768::encapsulate(&pk, &mut OsRng).unwrap();
        assert_eq!(ct.len(), 1122);
    }

    #[test]
    fn different_sessions_produce_different_secrets() {
        let (pk, sk) = X25519MlKem768::keygen(&mut OsRng);
        let (ct1, ss1) = X25519MlKem768::encapsulate(&pk, &mut OsRng).unwrap();
        let (ct2, ss2) = X25519MlKem768::encapsulate(&pk, &mut OsRng).unwrap();
        assert_ne!(ct1, ct2);
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());

        let dec1 = X25519MlKem768::decapsulate(&sk, &ct1).unwrap();
        let dec2 = X25519MlKem768::decapsulate(&sk, &ct2).unwrap();
        assert!(ss1.ct_eq(&dec1));
        assert!(ss2.ct_eq(&dec2));
    }
}
