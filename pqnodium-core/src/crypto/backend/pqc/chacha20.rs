use crate::crypto::traits::aead::{AeadCipher, AeadError};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

pub struct ChaCha20Poly1305Cipher;

impl AeadCipher for ChaCha20Poly1305Cipher {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;

    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if key.len() != Self::KEY_LEN {
            return Err(AeadError::InvalidKeyLength {
                expected: Self::KEY_LEN,
                got: key.len(),
            });
        }
        if nonce.len() != Self::NONCE_LEN {
            return Err(AeadError::InvalidNonceLength {
                expected: Self::NONCE_LEN,
                got: nonce.len(),
            });
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength {
                expected: Self::KEY_LEN,
                got: key.len(),
            })?;
        let nonce = Nonce::from_slice(nonce);
        cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| AeadError::AuthenticationFailed)
    }

    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if key.len() != Self::KEY_LEN {
            return Err(AeadError::InvalidKeyLength {
                expected: Self::KEY_LEN,
                got: key.len(),
            });
        }
        if nonce.len() != Self::NONCE_LEN {
            return Err(AeadError::InvalidNonceLength {
                expected: Self::NONCE_LEN,
                got: nonce.len(),
            });
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength {
                expected: Self::KEY_LEN,
                got: key.len(),
            })?;
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| AeadError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello pqnodium";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, aad, plaintext).unwrap();
        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello pqnodium";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert!(ChaCha20Poly1305Cipher::decrypt(&wrong_key, &nonce, aad, &ct).is_err());
    }

    #[test]
    fn decrypt_wrong_nonce_fails() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let wrong_nonce = [1u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello pqnodium";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert!(ChaCha20Poly1305Cipher::decrypt(&key, &wrong_nonce, aad, &ct).is_err());
    }

    #[test]
    fn decrypt_wrong_aad_fails() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";
        let plaintext = b"hello pqnodium";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert!(ChaCha20Poly1305Cipher::decrypt(&key, &nonce, wrong_aad, &ct).is_err());
    }

    #[test]
    fn invalid_key_length() {
        let key = [42u8; 16];
        let nonce = [0u8; 12];
        let result = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, b"", b"test");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_nonce_length() {
        let key = [42u8; 32];
        let nonce = [0u8; 8];
        let result = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, b"", b"test");
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"hello pqnodium";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, b"", plaintext).unwrap();
        assert_ne!(ct, plaintext.to_vec());
    }
}
