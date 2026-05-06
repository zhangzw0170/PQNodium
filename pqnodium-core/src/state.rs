use crate::crypto::backend::pqc::x25519::X25519Kem;
use crate::crypto::traits::aead::AeadCipher;
use crate::crypto::traits::kem::{KemError, KeyEncapsulation, SharedSecret};
use crate::identity::PublicIdentity;
use rand_core::CryptoRngCore;

/// Session state for the Noise PQ Hybrid handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    Idle,
    Initiated,
    Responded,
    Completed,
    Closed,
}

/// Error type for handshake operations.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidTransition {
        from: HandshakeState,
        to: HandshakeState,
    },
    #[error("KEM error: {0}")]
    Kem(#[from] KemError),
    #[error("handshake not completed")]
    NotCompleted,
}

/// Session keys derived from the handshake.
#[derive(Clone)]
pub struct SessionKeys {
    pub send_key: SharedSecret,
    pub recv_key: SharedSecret,
    pub send_nonce: u64,
    pub recv_nonce: u64,
}

impl SessionKeys {
    pub fn next_send_nonce(&mut self) -> [u8; 12] {
        let nonce = self.send_nonce;
        self.send_nonce += 1;
        let mut buf = [0u8; 12];
        buf[4..].copy_from_slice(&nonce.to_le_bytes());
        buf
    }

    pub fn next_recv_nonce(&mut self) -> [u8; 12] {
        let nonce = self.recv_nonce;
        self.recv_nonce += 1;
        let mut buf = [0u8; 12];
        buf[4..].copy_from_slice(&nonce.to_le_bytes());
        buf
    }

    pub fn encrypt(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, crate::crypto::traits::aead::AeadError> {
        let nonce = self.next_send_nonce();
        crate::crypto::backend::pqc::chacha20::ChaCha20Poly1305Cipher::encrypt(
            self.send_key.as_bytes(),
            &nonce,
            aad,
            plaintext,
        )
    }

    pub fn decrypt(
        &mut self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, crate::crypto::traits::aead::AeadError> {
        let nonce = self.next_recv_nonce();
        crate::crypto::backend::pqc::chacha20::ChaCha20Poly1305Cipher::decrypt(
            self.recv_key.as_bytes(),
            &nonce,
            aad,
            ciphertext,
        )
    }
}

/// The handshake session managing state transitions.
pub struct HandshakeSession {
    state: HandshakeState,
    local_sk: Option<Vec<u8>>,
    remote_identity: Option<PublicIdentity>,
    session_keys: Option<SessionKeys>,
}

impl HandshakeSession {
    pub fn new() -> Self {
        Self {
            state: HandshakeState::Idle,
            local_sk: None,
            remote_identity: None,
            session_keys: None,
        }
    }

    pub fn state(&self) -> &HandshakeState {
        &self.state
    }

    pub fn session_keys(&self) -> Result<&SessionKeys, HandshakeError> {
        self.session_keys
            .as_ref()
            .ok_or(HandshakeError::NotCompleted)
    }

    /// Initiate: generate ephemeral keypair, return public key.
    pub fn initiate<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        remote_identity: PublicIdentity,
    ) -> Result<Vec<u8>, HandshakeError> {
        self.require_state(&HandshakeState::Idle)?;
        self.remote_identity = Some(remote_identity);

        let (_pk, sk) = X25519Kem::keygen(rng);
        self.local_sk = Some(sk.0.to_vec());

        self.state = HandshakeState::Initiated;
        Ok(_pk.as_ref().to_vec())
    }

    /// Respond: generate own keypair, derive shared secret from initiator's public key.
    /// Returns our public key.
    pub fn respond<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        initiator_pk: &[u8],
        remote_identity: PublicIdentity,
    ) -> Result<Vec<u8>, HandshakeError> {
        self.require_state(&HandshakeState::Idle)?;
        self.remote_identity = Some(remote_identity);

        let (pk, sk) = X25519Kem::keygen(rng);
        let sk_arr: [u8; 32] = sk.0;
        let ss = X25519Kem::decapsulate(
            &crate::crypto::backend::pqc::x25519::X25519SecretKey(sk_arr),
            initiator_pk,
        )?;

        self.local_sk = None; // responder doesn't need local_sk after deriving
        self.session_keys = Some(SessionKeys {
            send_key: ss.clone(),
            recv_key: ss,
            send_nonce: 0,
            recv_nonce: 0,
        });

        self.state = HandshakeState::Completed;
        Ok(pk.as_ref().to_vec())
    }

    /// Complete as initiator: derive shared secret from responder's public key.
    pub fn complete_as_initiator(&mut self, responder_pk: &[u8]) -> Result<(), HandshakeError> {
        self.require_state(&HandshakeState::Initiated)?;

        let sk_bytes = self.local_sk.take().ok_or(HandshakeError::NotCompleted)?;
        let sk_arr: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|_| KemError::DecapsulationFailed)?;
        let sk = crate::crypto::backend::pqc::x25519::X25519SecretKey(sk_arr);
        let ss = X25519Kem::decapsulate(&sk, responder_pk)?;

        // TODO: Phase 2 — use HybridKem for full PQC key exchange.

        self.session_keys = Some(SessionKeys {
            send_key: ss.clone(),
            recv_key: ss,
            send_nonce: 0,
            recv_nonce: 0,
        });
        self.state = HandshakeState::Completed;
        Ok(())
    }

    pub fn close(&mut self) {
        self.state = HandshakeState::Closed;
        self.local_sk = None;
        self.session_keys = None;
    }

    fn require_state(&self, expected: &HandshakeState) -> Result<(), HandshakeError> {
        if &self.state != expected {
            return Err(HandshakeError::InvalidTransition {
                from: self.state.clone(),
                to: expected.clone(),
            });
        }
        Ok(())
    }
}

impl Default for HandshakeSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use rand::rngs::OsRng;

    /// Test-only helper to access mutable session keys.
    impl HandshakeSession {
        fn session_keys_mut(&mut self) -> &mut SessionKeys {
            self.session_keys.as_mut().unwrap()
        }
    }

    #[test]
    fn state_transitions() {
        let mut session = HandshakeSession::new();
        assert_eq!(session.state(), &HandshakeState::Idle);

        let identity = Identity::generate(&mut OsRng);
        let _ = session.initiate(&mut OsRng, identity.public()).unwrap();
        assert_eq!(session.state(), &HandshakeState::Initiated);

        session.close();
        assert_eq!(session.state(), &HandshakeState::Closed);
    }

    #[test]
    fn invalid_transition() {
        let mut session = HandshakeSession::new();
        assert!(session.complete_as_initiator(&[0u8; 32]).is_err());
    }

    #[test]
    fn session_keys_not_available_before_completion() {
        let session = HandshakeSession::new();
        assert!(session.session_keys().is_err());
    }

    #[test]
    fn nonce_monotonic() {
        let mut keys = SessionKeys {
            send_key: SharedSecret::new(vec![0u8; 32]),
            recv_key: SharedSecret::new(vec![0u8; 32]),
            send_nonce: 0,
            recv_nonce: 0,
        };
        let n1 = keys.next_send_nonce();
        let n2 = keys.next_send_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn full_handshake() {
        let mut initiator = HandshakeSession::new();
        let mut responder = HandshakeSession::new();

        let id_a = Identity::generate(&mut OsRng);
        let id_b = Identity::generate(&mut OsRng);

        // Initiator sends their ephemeral PK
        let initiator_pk = initiator.initiate(&mut OsRng, id_b.public()).unwrap();
        assert_eq!(initiator_pk.len(), 32);

        // Responder derives shared secret immediately
        let responder_pk = responder
            .respond(&mut OsRng, &initiator_pk, id_a.public())
            .unwrap();
        assert_eq!(responder.state(), &HandshakeState::Completed);

        // Initiator completes with responder's PK
        initiator.complete_as_initiator(&responder_pk).unwrap();
        assert_eq!(initiator.state(), &HandshakeState::Completed);

        // Both should have session keys
        assert!(initiator.session_keys().is_ok());
        assert!(responder.session_keys().is_ok());
    }

    #[test]
    fn symmetric_encryption_after_handshake() {
        let mut initiator = HandshakeSession::new();
        let mut responder = HandshakeSession::new();

        let id_a = Identity::generate(&mut OsRng);
        let id_b = Identity::generate(&mut OsRng);

        let initiator_pk = initiator.initiate(&mut OsRng, id_b.public()).unwrap();
        let responder_pk = responder
            .respond(&mut OsRng, &initiator_pk, id_a.public())
            .unwrap();
        initiator.complete_as_initiator(&responder_pk).unwrap();

        let aad = b"test_context";
        let plaintext = b"secret message";

        // Initiator encrypts, responder decrypts
        let ct = initiator
            .session_keys_mut()
            .encrypt(aad, plaintext)
            .unwrap();
        let pt = responder.session_keys_mut().decrypt(aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }
}
