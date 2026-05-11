use sha2::{Digest, Sha256};

/// Wire envelope for Gossipsub broadcast messages.
///
/// ```text
/// [version: 1][timestamp_ms: 8 LE][sender_id_len: 2 BE][sender_id][payload_len: 4 BE][payload]
/// ```
///
/// Currently plaintext. Future versions will encrypt the payload with
/// a per-group symmetric key derived from the PQ handshake.
pub const ENVELOPE_VERSION: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub timestamp_ms: u64,
    pub sender_id: String,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn new(sender_id: String, payload: Vec<u8>) -> Self {
        Self {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            sender_id,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let sender_bytes = self.sender_id.as_bytes();
        let mut buf = Vec::with_capacity(1 + 8 + 2 + sender_bytes.len() + 4 + self.payload.len());
        buf.push(ENVELOPE_VERSION);
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf.extend_from_slice(&(sender_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(sender_bytes);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, EnvelopeError> {
        if data.len() < 15 {
            return Err(EnvelopeError::TooShort {
                expected: 15,
                got: data.len(),
            });
        }
        let version = data[0];
        if version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnknownVersion(version));
        }

        let timestamp_ms = u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);

        let sender_len = u16::from_be_bytes([data[9], data[10]]) as usize;
        if data.len() < 11 + sender_len {
            return Err(EnvelopeError::TooShort {
                expected: 11 + sender_len,
                got: data.len(),
            });
        }
        let sender_id = String::from_utf8(data[11..11 + sender_len].to_vec())
            .map_err(|_| EnvelopeError::InvalidSenderId)?;

        let payload_len_start = 11 + sender_len;
        if data.len() < payload_len_start + 4 {
            return Err(EnvelopeError::TooShort {
                expected: payload_len_start + 4,
                got: data.len(),
            });
        }
        let payload_len = u32::from_be_bytes([
            data[payload_len_start],
            data[payload_len_start + 1],
            data[payload_len_start + 2],
            data[payload_len_start + 3],
        ]) as usize;

        let payload_start = payload_len_start + 4;
        if data.len() < payload_start + payload_len {
            return Err(EnvelopeError::TooShort {
                expected: payload_start + payload_len,
                got: data.len(),
            });
        }
        let payload = data[payload_start..payload_start + payload_len].to_vec();

        let consumed = payload_start + payload_len;
        if data.len() > consumed {
            return Err(EnvelopeError::TrailingData {
                actual: data.len(),
                consumed,
            });
        }

        Ok(Self {
            timestamp_ms,
            sender_id,
            payload,
        })
    }

    /// Compute a content hash for message deduplication.
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.timestamp_ms.to_le_bytes());
        hasher.update(self.sender_id.as_bytes());
        hasher.update(&self.payload);
        hasher.finalize().into()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("envelope too short: expected {expected} bytes, got {got}")]
    TooShort { expected: usize, got: usize },
    #[error("unknown envelope version: {0}")]
    UnknownVersion(u8),
    #[error("invalid sender ID (non-UTF8)")]
    InvalidSenderId,
    #[error("trailing data: envelope is {actual} bytes but only {consumed} were expected")]
    TrailingData { actual: usize, consumed: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let env = Envelope::new("12D3Sender".to_string(), b"hello world".to_vec());
        let encoded = env.encode();
        let decoded = Envelope::decode(&encoded).unwrap();
        assert_eq!(decoded.sender_id, "12D3Sender");
        assert_eq!(decoded.payload, b"hello world");
        assert_eq!(decoded.timestamp_ms, env.timestamp_ms);
    }

    #[test]
    fn version_byte() {
        let env = Envelope::new("sender".to_string(), vec![]);
        let encoded = env.encode();
        assert_eq!(encoded[0], ENVELOPE_VERSION);
    }

    #[test]
    fn decode_too_short() {
        assert!(Envelope::decode(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn decode_wrong_version() {
        let mut data = vec![0xFF];
        data.extend_from_slice(&[0u8; 14]);
        assert!(Envelope::decode(&data).is_err());
    }

    #[test]
    fn empty_payload() {
        let env = Envelope::new("sender".to_string(), vec![]);
        let encoded = env.encode();
        let decoded = Envelope::decode(&encoded).unwrap();
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn large_payload() {
        let payload = vec![0xAB; 100_000];
        let env = Envelope::new("sender".to_string(), payload.clone());
        let encoded = env.encode();
        let decoded = Envelope::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn content_hash_deterministic() {
        let env = Envelope::new("sender".to_string(), b"test".to_vec());
        let h1 = env.content_hash();
        let h2 = env.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_differs_for_different_payloads() {
        let env1 = Envelope::new("sender".to_string(), b"msg1".to_vec());
        let env2 = Envelope::new("sender".to_string(), b"msg2".to_vec());
        assert_ne!(env1.content_hash(), env2.content_hash());
    }

    #[test]
    fn unicode_sender_id() {
        let env = Envelope::new("节点🧑‍🚀".to_string(), b"data".to_vec());
        let encoded = env.encode();
        let decoded = Envelope::decode(&encoded).unwrap();
        assert_eq!(decoded.sender_id, "节点🧑‍🚀");
    }
}
