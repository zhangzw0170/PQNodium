use crate::crypto::backend::pqc::ml_kem::MlKem768Kem;
use crate::crypto::backend::pqc::x25519::X25519Kem;
use crate::crypto::hybrid::hybrid_kem::{HybridKem, HybridKemPublicKey};
use crate::crypto::traits::aead::AeadCipher;
use crate::crypto::traits::kem::{KemError, KeyEncapsulation, SharedSecret};
use crate::identity::PublicIdentity;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

type PqHybridKem = HybridKem<X25519Kem, MlKem768Kem>;
type PqHybridKemPk = HybridKemPublicKey<X25519Kem, MlKem768Kem>;
type PqHybridKemSk = <PqHybridKem as KeyEncapsulation>::SecretKey;

/// Session state for the PQ Hybrid handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    Idle,
    Initiated,
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
    #[error("invalid handshake payload")]
    InvalidPayload,
    #[error("nonce counter exhausted")]
    NonceExhausted,
    #[error("encryption error: {0}")]
    Encryption(String),
}

/// Derive a 32-byte directional key from the shared secret and a label.
fn derive_directional_key(shared_secret: &SharedSecret, label: &[u8]) -> SharedSecret {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(label);
    SharedSecret::new(hasher.finalize().to_vec())
}

/// Whether this session belongs to the initiator side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// Session keys derived from the handshake.
///
/// Initiator: send_key = KDF(ss, "initiator-to-responder"), recv_key = KDF(ss, "responder-to-initiator")
/// Responder: send_key = KDF(ss, "responder-to-initiator"), recv_key = KDF(ss, "initiator-to-responder")
#[derive(Clone)]
pub struct SessionKeys {
    send_key: SharedSecret,
    recv_key: SharedSecret,
    send_nonce: u64,
    recv_nonce: u64,
}

impl SessionKeys {
    fn new(shared_secret: SharedSecret, role: HandshakeRole) -> Self {
        let initiator_to_responder =
            derive_directional_key(&shared_secret, b"initiator-to-responder");
        let responder_to_initiator =
            derive_directional_key(&shared_secret, b"responder-to-initiator");
        match role {
            HandshakeRole::Initiator => Self {
                send_key: initiator_to_responder,
                recv_key: responder_to_initiator,
                send_nonce: 0,
                recv_nonce: 0,
            },
            HandshakeRole::Responder => Self {
                send_key: responder_to_initiator,
                recv_key: initiator_to_responder,
                send_nonce: 0,
                recv_nonce: 0,
            },
        }
    }

    pub fn send_key(&self) -> &SharedSecret {
        &self.send_key
    }

    pub fn recv_key(&self) -> &SharedSecret {
        &self.recv_key
    }

    pub fn next_send_nonce(&mut self) -> Result<[u8; 12], HandshakeError> {
        if self.send_nonce == u64::MAX {
            return Err(HandshakeError::NonceExhausted);
        }
        let nonce = self.send_nonce;
        self.send_nonce += 1;
        let mut buf = [0u8; 12];
        buf[4..].copy_from_slice(&nonce.to_le_bytes());
        Ok(buf)
    }

    pub fn next_recv_nonce(&mut self) -> Result<[u8; 12], HandshakeError> {
        if self.recv_nonce == u64::MAX {
            return Err(HandshakeError::NonceExhausted);
        }
        let nonce = self.recv_nonce;
        self.recv_nonce += 1;
        let mut buf = [0u8; 12];
        buf[4..].copy_from_slice(&nonce.to_le_bytes());
        Ok(buf)
    }

    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let nonce = self.next_send_nonce()?;
        crate::crypto::backend::pqc::chacha20::ChaCha20Poly1305Cipher::encrypt(
            self.send_key.as_bytes(),
            &nonce,
            aad,
            plaintext,
        )
        .map_err(|e| HandshakeError::Encryption(e.to_string()))
    }

    pub fn decrypt(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let nonce = self.next_recv_nonce()?;
        crate::crypto::backend::pqc::chacha20::ChaCha20Poly1305Cipher::decrypt(
            self.recv_key.as_bytes(),
            &nonce,
            aad,
            ciphertext,
        )
        .map_err(|e| HandshakeError::Encryption(e.to_string()))
    }
}

/// The handshake session managing state transitions.
///
/// Uses HybridKem (X25519 + ML-KEM-768) for post-quantum secure key exchange.
///
/// Protocol (2-round):
/// ```text
/// Round 1 (Initiator → Responder):
///   [x25519_pk: 32][ml_kem_pk: 1184]
///
/// Round 2 (Responder → Initiator):
///   [x25519_pk: 32][ml_kem_pk: 1184][hybrid_ct: 1122]
///   where hybrid_ct = HybridKem::encapsulate(initiator_pk)
///
/// After Round 2, both sides derive the same shared secret via
/// KDF(X25519_ss || ML-KEM-768_ss).
/// ```
pub struct HandshakeSession {
    state: HandshakeState,
    /// Initiator's ephemeral secret key (for decapsulating responder's ct).
    initiator_sk: Option<PqHybridKemSk>,
    remote_identity: Option<PublicIdentity>,
    session_keys: Option<SessionKeys>,
}

impl HandshakeSession {
    pub fn new() -> Self {
        Self {
            state: HandshakeState::Idle,
            initiator_sk: None,
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

    /// Initiate: generate ephemeral hybrid keypair, send public keys to responder.
    ///
    /// Returns: `[x25519_pk: 32][ml_kem_pk: 1184]` (1216 bytes)
    pub fn initiate<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        remote_identity: PublicIdentity,
    ) -> Result<Vec<u8>, HandshakeError> {
        self.require_state(&HandshakeState::Idle)?;
        self.remote_identity = Some(remote_identity);

        let (_pk, sk) = PqHybridKem::keygen(rng);
        self.initiator_sk = Some(sk);
        self.state = HandshakeState::Initiated;

        // Encode: x25519_pk(32) || ml_kem_pk(1184)
        let mut payload = Vec::with_capacity(32 + 1184);
        payload.extend_from_slice(_pk.classic.as_ref());
        payload.extend_from_slice(_pk.pqc.as_ref());
        Ok(payload)
    }

    /// Respond: receive initiator's PK, generate own keypair, encapsulate to initiator's PK.
    ///
    /// Input: initiator's PK `[x25519_pk: 32][ml_kem_pk: 1184]`
    /// Returns: `[x25519_pk: 32][ml_kem_pk: 1184][hybrid_ct: 1122]`
    pub fn respond<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        initiator_pk_payload: &[u8],
        remote_identity: PublicIdentity,
    ) -> Result<Vec<u8>, HandshakeError> {
        self.require_state(&HandshakeState::Idle)?;
        self.remote_identity = Some(remote_identity);

        if initiator_pk_payload.len() < 32 + 1184 {
            return Err(HandshakeError::InvalidPayload);
        }

        // Reconstruct initiator's hybrid PK
        let initiator_pk = build_hybrid_pk(&initiator_pk_payload[..32 + 1184])?;

        // Generate responder's ephemeral keypair
        let (resp_pk, _resp_sk) = PqHybridKem::keygen(rng);

        // Encapsulate to initiator's PK → both sides will derive the same ss
        let (hybrid_ct, shared_secret) = PqHybridKem::encapsulate(&initiator_pk, rng)?;

        self.session_keys = Some(SessionKeys::new(shared_secret, HandshakeRole::Responder));
        self.state = HandshakeState::Completed;

        // Encode: resp_pk(32+1184) || hybrid_ct(1122)
        let mut payload = Vec::with_capacity(32 + 1184 + hybrid_ct.len());
        payload.extend_from_slice(resp_pk.classic.as_ref());
        payload.extend_from_slice(resp_pk.pqc.as_ref());
        payload.extend_from_slice(&hybrid_ct);
        Ok(payload)
    }

    /// Complete as initiator: decapsulate responder's ciphertext.
    ///
    /// Input: `[x25519_pk: 32][ml_kem_pk: 1184][hybrid_ct: 1122]`
    pub fn complete_as_initiator(
        &mut self,
        responder_payload: &[u8],
    ) -> Result<(), HandshakeError> {
        self.require_state(&HandshakeState::Initiated)?;

        // Minimum: hybrid_ct header (2 bytes) but we need the full 1122-byte ct
        let pk_len = 32 + 1184;
        let ct_offset = pk_len;
        if responder_payload.len() < ct_offset + 2 {
            return Err(HandshakeError::InvalidPayload);
        }

        let hybrid_ct = &responder_payload[ct_offset..];

        let sk = self
            .initiator_sk
            .take()
            .ok_or(HandshakeError::NotCompleted)?;
        let shared_secret = PqHybridKem::decapsulate(&sk, hybrid_ct)?;

        self.session_keys = Some(SessionKeys::new(shared_secret, HandshakeRole::Initiator));
        self.state = HandshakeState::Completed;

        drop(sk);
        Ok(())
    }

    pub fn close(&mut self) {
        self.state = HandshakeState::Closed;
        self.initiator_sk = None;
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

/// Build a HybridKem public key from raw bytes: `[x25519_pk: 32][ml_kem_pk: 1184]`.
fn build_hybrid_pk(data: &[u8]) -> Result<PqHybridKemPk, HandshakeError> {
    if data.len() < 32 + 1184 {
        return Err(HandshakeError::InvalidPayload);
    }
    let x25519_bytes: [u8; 32] = data[..32]
        .try_into()
        .map_err(|_| HandshakeError::InvalidPayload)?;
    Ok(crate::crypto::hybrid::hybrid_kem::HybridKemPublicKey {
        classic: crate::crypto::backend::pqc::x25519::X25519PublicKey(x25519_bytes),
        pqc: crate::crypto::backend::pqc::ml_kem::MlKem768PublicKey {
            encoded: data[32..32 + 1184].to_vec(),
        },
    })
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

    impl HandshakeSession {
        fn session_keys_mut(&mut self) -> &mut SessionKeys {
            self.session_keys.as_mut().unwrap()
        }
    }

    #[test]
    fn state_transitions() {
        let mut session = HandshakeSession::new();
        assert_eq!(session.state(), &HandshakeState::Idle);

        let id_b = Identity::generate(&mut OsRng);
        let _ = session.initiate(&mut OsRng, id_b.public()).unwrap();
        assert_eq!(session.state(), &HandshakeState::Initiated);

        session.close();
        assert_eq!(session.state(), &HandshakeState::Closed);
    }

    #[test]
    fn invalid_transition() {
        let mut session = HandshakeSession::new();
        assert!(session.complete_as_initiator(&[0u8; 10]).is_err());
    }

    #[test]
    fn session_keys_not_available_before_completion() {
        let session = HandshakeSession::new();
        assert!(session.session_keys().is_err());
    }

    #[test]
    fn nonce_monotonic() {
        let mut keys = SessionKeys::new(SharedSecret::new(vec![0u8; 32]), HandshakeRole::Initiator);
        let n1 = keys.next_send_nonce().unwrap();
        let n2 = keys.next_send_nonce().unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn directional_keys_differ() {
        let ss = SharedSecret::new(vec![42u8; 32]);
        let init_keys = SessionKeys::new(ss.clone(), HandshakeRole::Initiator);
        let resp_keys = SessionKeys::new(ss, HandshakeRole::Responder);
        // Initiator's send_key matches Responder's recv_key
        assert_eq!(
            init_keys.send_key().as_bytes(),
            resp_keys.recv_key().as_bytes()
        );
        // Initiator's recv_key matches Responder's send_key
        assert_eq!(
            init_keys.recv_key().as_bytes(),
            resp_keys.send_key().as_bytes()
        );
        // send_key != recv_key (no nonce reuse)
        assert_ne!(
            init_keys.send_key().as_bytes(),
            init_keys.recv_key().as_bytes()
        );
    }

    #[test]
    fn full_hybrid_handshake() {
        let mut initiator = HandshakeSession::new();
        let mut responder = HandshakeSession::new();

        let id_a = Identity::generate(&mut OsRng);
        let id_b = Identity::generate(&mut OsRng);

        // Round 1: initiator sends ephemeral PK
        let initiator_pk = initiator.initiate(&mut OsRng, id_b.public()).unwrap();
        assert_eq!(initiator_pk.len(), 32 + 1184);

        // Round 2: responder sends their PK + hybrid ciphertext
        let responder_msg = responder
            .respond(&mut OsRng, &initiator_pk, id_a.public())
            .unwrap();
        assert_eq!(responder.state(), &HandshakeState::Completed);

        // Initiator completes by decapsulating
        initiator.complete_as_initiator(&responder_msg).unwrap();
        assert_eq!(initiator.state(), &HandshakeState::Completed);

        assert!(initiator.session_keys().is_ok());
        assert!(responder.session_keys().is_ok());
    }

    #[test]
    fn symmetric_encryption_after_hybrid_handshake() {
        let mut initiator = HandshakeSession::new();
        let mut responder = HandshakeSession::new();

        let id_a = Identity::generate(&mut OsRng);
        let id_b = Identity::generate(&mut OsRng);

        let initiator_pk = initiator.initiate(&mut OsRng, id_b.public()).unwrap();
        let responder_msg = responder
            .respond(&mut OsRng, &initiator_pk, id_a.public())
            .unwrap();
        initiator.complete_as_initiator(&responder_msg).unwrap();

        let aad = b"test_context";
        let plaintext = b"secret post-quantum message";

        // Initiator → Responder
        let ct = initiator
            .session_keys_mut()
            .encrypt(aad, plaintext)
            .unwrap();
        let pt = responder.session_keys_mut().decrypt(aad, &ct).unwrap();
        assert_eq!(pt, plaintext);

        // Responder → Initiator (different direction key, same nonce space)
        let ct2 = responder
            .session_keys_mut()
            .encrypt(aad, plaintext)
            .unwrap();
        let pt2 = initiator.session_keys_mut().decrypt(aad, &ct2).unwrap();
        assert_eq!(pt2, plaintext);
    }

    #[test]
    fn handshake_produces_32_byte_session_key() {
        let mut initiator = HandshakeSession::new();
        let mut responder = HandshakeSession::new();

        let id_a = Identity::generate(&mut OsRng);
        let id_b = Identity::generate(&mut OsRng);

        let initiator_pk = initiator.initiate(&mut OsRng, id_b.public()).unwrap();
        let responder_msg = responder
            .respond(&mut OsRng, &initiator_pk, id_a.public())
            .unwrap();
        initiator.complete_as_initiator(&responder_msg).unwrap();

        let ik = initiator.session_keys().unwrap();
        let rk = responder.session_keys().unwrap();
        assert_eq!(ik.send_key().as_bytes().len(), 32);
        assert_eq!(rk.recv_key().as_bytes().len(), 32);
        // Initiator's send_key must match Responder's recv_key
        assert_eq!(ik.send_key().as_bytes(), rk.recv_key().as_bytes());
        // Initiator's recv_key must match Responder's send_key
        assert_eq!(ik.recv_key().as_bytes(), rk.send_key().as_bytes());
    }

    #[test]
    fn different_sessions_produce_different_keys() {
        let id_a = Identity::generate(&mut OsRng);
        let id_b = Identity::generate(&mut OsRng);

        let mut init1 = HandshakeSession::new();
        let mut resp1 = HandshakeSession::new();
        let pk1 = init1.initiate(&mut OsRng, id_b.public()).unwrap();
        let reply1 = resp1.respond(&mut OsRng, &pk1, id_a.public()).unwrap();
        init1.complete_as_initiator(&reply1).unwrap();

        let mut init2 = HandshakeSession::new();
        let mut resp2 = HandshakeSession::new();
        let pk2 = init2.initiate(&mut OsRng, id_b.public()).unwrap();
        let reply2 = resp2.respond(&mut OsRng, &pk2, id_a.public()).unwrap();
        init2.complete_as_initiator(&reply2).unwrap();

        let k1 = init1.session_keys().unwrap().send_key().as_bytes().to_vec();
        let k2 = init2.session_keys().unwrap().send_key().as_bytes().to_vec();
        assert_ne!(k1, k2);
    }

    #[test]
    fn respond_with_short_payload_fails() {
        let mut responder = HandshakeSession::new();
        let id = Identity::generate(&mut OsRng);
        let result = responder.respond(&mut OsRng, &[0u8; 10], id.public());
        assert!(result.is_err());
    }

    #[test]
    fn complete_with_short_payload_fails() {
        let mut initiator = HandshakeSession::new();
        let id = Identity::generate(&mut OsRng);
        initiator.initiate(&mut OsRng, id.public()).unwrap();
        let result = initiator.complete_as_initiator(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn build_hybrid_pk_invalid_length() {
        let result = build_hybrid_pk(&[0u8; 10]);
        assert!(result.is_err());
    }
}
