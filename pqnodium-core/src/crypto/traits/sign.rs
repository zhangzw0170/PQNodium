use rand_core::CryptoRngCore;
use zeroize::Zeroize;

/// Error type for signing operations.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("invalid signature length: expected {expected}, got {got}")]
    InvalidSignature { expected: usize, got: usize },
    #[error("invalid public key length: expected {expected}, got {got}")]
    InvalidPublicKey { expected: usize, got: usize },
}

/// Digital signature trait.
pub trait Signer: Send + Sync {
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    type SecretKey: Zeroize + Send + Sync;
    type Signature: AsRef<[u8]> + Clone + Send + Sync;

    fn keygen<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature;

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;
}
