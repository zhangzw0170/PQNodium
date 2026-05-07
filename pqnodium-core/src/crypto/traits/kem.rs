use rand::rngs::OsRng;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A shared secret produced by a KEM operation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub(crate) Vec<u8>);

impl SharedSecret {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Constant-time equality comparison to prevent timing side-channels.
    pub fn ct_eq(&self, other: &SharedSecret) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// Error type for KEM operations.
#[derive(Debug, thiserror::Error)]
pub enum KemError {
    #[error("decapsulation failed")]
    DecapsulationFailed,
    #[error("ciphertext length invalid: expected {expected}, got {got}")]
    InvalidCiphertext { expected: usize, got: usize },
    #[error("public key length invalid: expected {expected}, got {got}")]
    InvalidPublicKey { expected: usize, got: usize },
}

/// Key encapsulation mechanism trait.
pub trait KeyEncapsulation: Send + Sync {
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    type SecretKey: Zeroize + Send + Sync;

    fn keygen<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    fn encapsulate<R: CryptoRngCore>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret), KemError>;

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<SharedSecret, KemError>;

    fn keygen_os() -> (Self::PublicKey, Self::SecretKey) {
        Self::keygen(&mut OsRng)
    }
}
