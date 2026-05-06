pub mod backend;
pub mod conformance;
pub mod hybrid;
pub mod traits;

#[cfg(test)]
mod tests {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    use rand::rngs::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    #[test]
    fn ml_kem_768_roundtrip() {
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let (ct, ss_sender) = ek.encapsulate(&mut OsRng).unwrap();
        let ss_receiver = dk.decapsulate(&ct).unwrap();
        assert_eq!(ss_sender, ss_receiver, "shared secrets must match");
    }

    #[test]
    fn x25519_ecdh_roundtrip() {
        let secret_alice = EphemeralSecret::random_from_rng(OsRng);
        let secret_bob = EphemeralSecret::random_from_rng(OsRng);
        let pk_alice = PublicKey::from(&secret_alice);
        let pk_bob = PublicKey::from(&secret_bob);

        let ss_alice = secret_alice.diffie_hellman(&pk_bob);
        let ss_bob = secret_bob.diffie_hellman(&pk_alice);
        assert_eq!(
            ss_alice.as_bytes(),
            ss_bob.as_bytes(),
            "DH shared secrets must match"
        );
    }

    #[test]
    fn hybrid_kem_both_succeed() {
        let sec_a = EphemeralSecret::random_from_rng(OsRng);
        let ss_classic =
            sec_a.diffie_hellman(&PublicKey::from(&EphemeralSecret::random_from_rng(OsRng)));

        let (_, ek) = MlKem768::generate(&mut OsRng);
        let (_ct, ss_pqc) = ek.encapsulate(&mut OsRng).unwrap();

        assert!(
            !ss_classic.as_bytes().is_empty(),
            "classic shared secret is empty"
        );
        assert!(!ss_pqc.is_empty(), "PQC shared secret is empty");
        let _ = (ss_classic, ss_pqc);
    }

    #[test]
    fn key_sizes_match_docs() {
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        assert_eq!(ek.as_bytes().len(), 1184, "ML-KEM-768 public key size");
        assert_eq!(
            dk.encapsulation_key().as_bytes().len(),
            1184,
            "ML-KEM-768 encapsulation key size"
        );
        assert_eq!(
            dk.as_bytes().len(),
            2400,
            "ML-KEM-768 decapsulation key size"
        );

        let (ct, _ss) = ek.encapsulate(&mut OsRng).unwrap();
        assert_eq!(ct.len(), 1088, "ML-KEM-768 ciphertext size");

        let pk = PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
        assert_eq!(pk.as_bytes().len(), 32, "X25519 public key size");

        let ss = EphemeralSecret::random_from_rng(OsRng).diffie_hellman(&pk);
        assert_eq!(ss.as_bytes().len(), 32, "X25519 shared secret size");
    }
}
