/// Error type for AEAD operations.
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("decryption failed: authentication tag mismatch")]
    AuthenticationFailed,
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },
}

/// Authenticated Encryption with Associated Data trait.
///
/// Implementors: ChaCha20-Poly1305, SM4-GCM (future).
pub trait AeadCipher: Send + Sync {
    /// The key length in bytes.
    const KEY_LEN: usize;
    /// The nonce length in bytes.
    const NONCE_LEN: usize;

    /// Encrypt plaintext with associated data.
    /// Returns ciphertext || tag.
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError>;

    /// Decrypt ciphertext with associated data.
    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError>;
}
