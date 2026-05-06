use crate::crypto::backend::pqc::chacha20::ChaCha20Poly1305Cipher;
use crate::crypto::traits::aead::{AeadCipher, AeadError};

/// Message types in the PQNodium protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    HandshakeComplete = 0x03,
    Data = 0x10,
    Ack = 0x11,
}

impl TryFrom<u8> for MessageType {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::HandshakeInit),
            0x02 => Ok(Self::HandshakeResponse),
            0x03 => Ok(Self::HandshakeComplete),
            0x10 => Ok(Self::Data),
            0x11 => Ok(Self::Ack),
            _ => Err(MessageError::UnknownMessageType(value)),
        }
    }
}

/// Error type for message operations.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("unknown message type: 0x{0:02x}")]
    UnknownMessageType(u8),
    #[error("message too short: expected at least {expected} bytes, got {got}")]
    TooShort { expected: usize, got: usize },
    #[error("AEAD encryption/decryption failed: {0}")]
    Aead(#[from] AeadError),
    #[error("invalid nonce")]
    InvalidNonce,
}

/// Header for all PQNodium messages.
///
/// Wire format:
/// ```text
/// 0        1        2        3
/// +--------+--------+--------+--------+
/// | version|  type  |   reserved       |
/// +--------+--------+--------+--------+
/// |          message length (u32 BE)  |
/// +--------+--------+--------+--------+
/// ```
pub const HEADER_SIZE: usize = 8;
pub const PROTOCOL_VERSION: u8 = 0x01;

#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub version: u8,
    pub msg_type: MessageType,
    pub payload_len: u32,
}

impl MessageHeader {
    pub fn new(msg_type: MessageType, payload_len: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            msg_type,
            payload_len,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = self.version;
        buf[1] = self.msg_type as u8;
        // bytes 2-3 reserved
        buf[4..8].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < HEADER_SIZE {
            return Err(MessageError::TooShort {
                expected: HEADER_SIZE,
                got: data.len(),
            });
        }
        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(MessageError::UnknownMessageType(version));
        }
        let msg_type = MessageType::try_from(data[1])?;
        let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        Ok(Self {
            version,
            msg_type,
            payload_len,
        })
    }
}

/// A complete message with header and encrypted payload.
#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl Message {
    /// Create a new message by encrypting the payload.
    pub fn new(
        msg_type: MessageType,
        key: &[u8],
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Self, MessageError> {
        let ciphertext = ChaCha20Poly1305Cipher::encrypt(key, &nonce, aad, plaintext)?;
        Ok(Self {
            header: MessageHeader::new(msg_type, ciphertext.len() as u32),
            nonce,
            ciphertext,
        })
    }

    /// Decrypt the message payload.
    pub fn decrypt(&self, key: &[u8], aad: &[u8]) -> Result<Vec<u8>, MessageError> {
        Ok(ChaCha20Poly1305Cipher::decrypt(
            key,
            &self.nonce,
            aad,
            &self.ciphertext,
        )?)
    }

    /// Encode the full message to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + 12 + self.ciphertext.len());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Decode a message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < HEADER_SIZE + 12 {
            return Err(MessageError::TooShort {
                expected: HEADER_SIZE + 12,
                got: data.len(),
            });
        }
        let header = MessageHeader::decode(data)?;
        let nonce: [u8; 12] = data[HEADER_SIZE..HEADER_SIZE + 12]
            .try_into()
            .map_err(|_| MessageError::InvalidNonce)?;
        let ciphertext = data[HEADER_SIZE + 12..].to_vec();
        if ciphertext.len() != header.payload_len as usize {
            return Err(MessageError::TooShort {
                expected: header.payload_len as usize,
                got: ciphertext.len(),
            });
        }
        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = MessageHeader::new(MessageType::Data, 42);
        let encoded = header.encode();
        let decoded = MessageHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.msg_type, MessageType::Data);
        assert_eq!(decoded.payload_len, 42);
    }

    #[test]
    fn message_encrypt_decrypt() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"test_aad";
        let plaintext = b"hello pqnodium message";

        let msg = Message::new(MessageType::Data, &key, nonce, aad, plaintext).unwrap();
        let decrypted = msg.decrypt(&key, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn message_encode_decode_roundtrip() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"test_aad";
        let plaintext = b"hello pqnodium message";

        let msg = Message::new(MessageType::Data, &key, nonce, aad, plaintext).unwrap();
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded.header.msg_type, MessageType::Data);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.ciphertext, msg.ciphertext);

        let decrypted = decoded.decrypt(&key, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn message_decode_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let nonce = [0u8; 12];
        let aad = b"test_aad";

        let msg = Message::new(MessageType::Data, &key, nonce, aad, b"test").unwrap();
        assert!(msg.decrypt(&wrong_key, aad).is_err());
    }

    #[test]
    fn unknown_message_type() {
        assert!(MessageType::try_from(0xFF).is_err());
    }

    #[test]
    fn too_short_decode() {
        assert!(Message::decode(&[0x01, 0x01]).is_err());
    }

    #[test]
    fn header_size() {
        assert_eq!(HEADER_SIZE, 8);
    }
}
