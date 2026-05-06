use crate::crypto::traits::kem::{KemError, KeyEncapsulation, SharedSecret};
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type MlKem768EncKey = EncapsulationKey<ml_kem::MlKem768Params>;
pub type MlKem768DecKey = DecapsulationKey<ml_kem::MlKem768Params>;

#[derive(Clone)]
pub struct MlKem768PublicKey {
    encoded: Vec<u8>,
}

impl AsRef<[u8]> for MlKem768PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.encoded
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SecretKey {
    decapsulation_key: Vec<u8>,
}

pub struct MlKem768Kem;

impl KeyEncapsulation for MlKem768Kem {
    type PublicKey = MlKem768PublicKey;
    type SecretKey = MlKem768SecretKey;

    fn keygen<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let (dk, ek) = MlKem768::generate(rng);
        (
            MlKem768PublicKey {
                encoded: ek.as_bytes().to_vec(),
            },
            MlKem768SecretKey {
                decapsulation_key: dk.as_bytes().to_vec(),
            },
        )
    }

    fn encapsulate<R: CryptoRngCore>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret), KemError> {
        if pk.encoded.len() != 1184 {
            return Err(KemError::InvalidPublicKey {
                expected: 1184,
                got: pk.encoded.len(),
            });
        }
        let ek_bytes: ml_kem::Encoded<MlKem768EncKey> =
            pk.encoded
                .as_slice()
                .try_into()
                .map_err(|_| KemError::InvalidPublicKey {
                    expected: 1184,
                    got: pk.encoded.len(),
                })?;
        let ek = MlKem768EncKey::from_bytes(&ek_bytes);
        let (ct, ss) = ek
            .encapsulate(rng)
            .map_err(|_| KemError::DecapsulationFailed)?;
        Ok((ct.to_vec(), SharedSecret::new(ss.to_vec())))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<SharedSecret, KemError> {
        if ct.len() != 1088 {
            return Err(KemError::InvalidCiphertext {
                expected: 1088,
                got: ct.len(),
            });
        }
        if sk.decapsulation_key.len() != 2400 {
            return Err(KemError::InvalidPublicKey {
                expected: 2400,
                got: sk.decapsulation_key.len(),
            });
        }
        let dk_bytes: ml_kem::Encoded<MlKem768DecKey> = sk
            .decapsulation_key
            .as_slice()
            .try_into()
            .map_err(|_| KemError::InvalidPublicKey {
                expected: 2400,
                got: sk.decapsulation_key.len(),
            })?;
        let dk = MlKem768DecKey::from_bytes(&dk_bytes);
        let ct_encoded: ml_kem::Ciphertext<MlKem768> =
            ct.try_into().map_err(|_| KemError::InvalidCiphertext {
                expected: 1088,
                got: ct.len(),
            })?;
        let ss = dk
            .decapsulate(&ct_encoded)
            .map_err(|_| KemError::DecapsulationFailed)?;
        Ok(SharedSecret::new(ss.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn roundtrip() {
        let (pk, sk) = MlKem768Kem::keygen(&mut OsRng);
        let (ct, ss_sender) = MlKem768Kem::encapsulate(&pk, &mut OsRng).unwrap();
        let ss_receiver = MlKem768Kem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    }

    #[test]
    fn key_sizes() {
        let (pk, _) = MlKem768Kem::keygen(&mut OsRng);
        assert_eq!(pk.as_ref().len(), 1184);
    }

    #[test]
    fn ciphertext_size() {
        let (pk, _) = MlKem768Kem::keygen(&mut OsRng);
        let (ct, _) = MlKem768Kem::encapsulate(&pk, &mut OsRng).unwrap();
        assert_eq!(ct.len(), 1088);
    }

    #[test]
    fn shared_secret_32_bytes() {
        let (pk, sk) = MlKem768Kem::keygen(&mut OsRng);
        let (ct, ss) = MlKem768Kem::encapsulate(&pk, &mut OsRng).unwrap();
        let ss2 = MlKem768Kem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss.as_bytes().len(), 32);
        assert_eq!(ss2.as_bytes().len(), 32);
    }
}
