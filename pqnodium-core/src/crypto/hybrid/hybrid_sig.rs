use crate::crypto::traits::sign::Signer;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Combined public key from two signature schemes.
pub struct HybridSigPublicKey<S1: Signer, S2: Signer> {
    pub classic: S1::PublicKey,
    pub pqc: S2::PublicKey,
}

impl<S1: Signer, S2: Signer> Clone for HybridSigPublicKey<S1, S2> {
    fn clone(&self) -> Self {
        Self {
            classic: self.classic.clone(),
            pqc: self.pqc.clone(),
        }
    }
}

impl<S1: Signer, S2: Signer> AsRef<[u8]> for HybridSigPublicKey<S1, S2> {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

/// Combined secret key from two signature schemes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSigSecretKey<S1: Signer, S2: Signer> {
    pub classic: S1::SecretKey,
    pub pqc: S2::SecretKey,
}

/// Combined signature from two signature schemes.
pub struct HybridSignature<S1: Signer, S2: Signer> {
    pub classic: S1::Signature,
    pub pqc: S2::Signature,
}

impl<S1: Signer, S2: Signer> Clone for HybridSignature<S1, S2> {
    fn clone(&self) -> Self {
        Self {
            classic: self.classic.clone(),
            pqc: self.pqc.clone(),
        }
    }
}

impl<S1: Signer, S2: Signer> AsRef<[u8]> for HybridSignature<S1, S2> {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

/// Hybrid signature combining classical + PQC signatures.
///
/// Both signatures must verify for the hybrid to be valid.
pub struct HybridSigner<S1, S2>(std::marker::PhantomData<(S1, S2)>);

impl<S1: Signer, S2: Signer> Signer for HybridSigner<S1, S2> {
    type PublicKey = HybridSigPublicKey<S1, S2>;
    type SecretKey = HybridSigSecretKey<S1, S2>;
    type Signature = HybridSignature<S1, S2>;

    fn keygen<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let (pk1, sk1) = S1::keygen(rng);
        let (pk2, sk2) = S2::keygen(rng);
        (
            HybridSigPublicKey {
                classic: pk1,
                pqc: pk2,
            },
            HybridSigSecretKey {
                classic: sk1,
                pqc: sk2,
            },
        )
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        let classic_sig = S1::sign(&sk.classic, msg);
        let pqc_sig = S2::sign(&sk.pqc, msg);
        HybridSignature {
            classic: classic_sig,
            pqc: pqc_sig,
        }
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        S1::verify(&pk.classic, msg, &sig.classic) && S2::verify(&pk.pqc, msg, &sig.pqc)
    }
}

impl<S1: Signer, S2: Signer> HybridSignature<S1, S2> {
    /// Encode: classic_sig_len (2B LE) || classic_sig || pqc_sig
    pub fn to_bytes(&self) -> Vec<u8> {
        let classic_bytes = self.classic.as_ref();
        let pqc_bytes = self.pqc.as_ref();
        let classic_len = classic_bytes.len() as u16;

        let mut out = Vec::with_capacity(2 + classic_bytes.len() + pqc_bytes.len());
        out.extend_from_slice(&classic_len.to_le_bytes());
        out.extend_from_slice(classic_bytes);
        out.extend_from_slice(pqc_bytes);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::backend::pqc::ed25519::Ed25519Signer;
    use crate::crypto::backend::pqc::ml_dsa::MlDsa65Signer;
    use rand::rngs::OsRng;

    type Ed25519MlDsa65 = HybridSigner<Ed25519Signer, MlDsa65Signer>;

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let (pk, sk) = Ed25519MlDsa65::keygen(&mut OsRng);
        let msg = b"hello pqnodium";
        let sig = Ed25519MlDsa65::sign(&sk, msg);
        assert!(Ed25519MlDsa65::verify(&pk, msg, &sig));
    }

    #[test]
    fn verify_wrong_message_fails() {
        let (pk, sk) = Ed25519MlDsa65::keygen(&mut OsRng);
        let sig = Ed25519MlDsa65::sign(&sk, b"correct message");
        assert!(!Ed25519MlDsa65::verify(&pk, b"wrong message", &sig));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (_pk1, sk1) = Ed25519MlDsa65::keygen(&mut OsRng);
        let (pk2, _) = Ed25519MlDsa65::keygen(&mut OsRng);
        let sig = Ed25519MlDsa65::sign(&sk1, b"hello");
        assert!(!Ed25519MlDsa65::verify(&pk2, b"hello", &sig));
    }

    #[test]
    fn signature_encoding() {
        let (_, sk) = Ed25519MlDsa65::keygen(&mut OsRng);
        let sig = Ed25519MlDsa65::sign(&sk, b"test");
        let bytes = sig.to_bytes();
        // 2 (len prefix) + 64 (ed25519 sig) + 3309 (ml-dsa sig) = 3375
        assert_eq!(bytes.len(), 3375);
    }
}
