/// Errors produced by the Sender Key group encryption backend.
#[derive(Debug, thiserror::Error)]
pub enum SenderKeyError {
    #[error("chain step {step} exceeds maximum {max}")]
    ChainStepExceeded { step: u64, max: u64 },

    #[error("ciphertext too short: expected at least {min}, got {got}")]
    CiphertextTooShort { min: usize, got: usize },

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("group not found")]
    GroupNotFound,

    #[error("no public key registered for member")]
    MemberPublicKeyNotFound,

    #[error("KEM encapsulation failed: {0}")]
    KemEncapsulation(String),

    #[error("KEM decapsulation failed: {0}")]
    KemDecapsulation(String),

    #[error("AEAD error: {0}")]
    Aead(String),
}
