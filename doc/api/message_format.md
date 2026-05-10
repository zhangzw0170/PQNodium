# Message Format

*Updated: Phase 1 implementation complete. Message protocol defined in `pqnodium-core/src/message.rs`.*

## Wire Format

All PQNodium messages use a custom binary format with a fixed header:

```
 0        1        2        3        4        5        6        7
+--------+--------+--------+--------+--------+--------+--------+--------+
| version|  type  |   reserved (2 bytes)      |  payload length (u32 BE)|
+--------+--------+--------+--------+--------+--------+--------+--------+
|                  nonce (12 bytes)                                     |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                  ciphertext + AEAD tag (variable)                     |
+--------+--------+--------+--------+--------+--------+--------+--------+
```

### Header (8 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `version` | Protocol version (currently `0x01`) |
| 1 | 1 | `type` | Message type (see below) |
| 2 | 2 | `reserved` | Reserved for future use (must be `0x0000`) |
| 4 | 4 | `payload_len` | Length of ciphertext + AEAD tag in bytes (big-endian) |

### Message Types

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| `HandshakeInit` | `0x01` | Initiator → Responder | Round 1: `[x25519_pk: 32][ml_kem_pk: 1184]` = 1216 bytes |
| `HandshakeResponse` | `0x02` | Responder → Initiator | Round 2: `[resp_pk: 1216][hybrid_ct: 1122]` = 2338 bytes |
| `HandshakeComplete` | `0x03` | Initiator → Responder | Handshake confirmation (encrypted) |
| `Data` | `0x10` | Bidirectional | Application data (encrypted) |
| `Ack` | `0x11` | Bidirectional | Acknowledgment (encrypted) |

### Encryption

- **Algorithm**: ChaCha20-Poly1305 (AEAD)
- **Key**: 32-byte session key derived from hybrid KEM handshake
- **Nonce**: 12 bytes, monotonically incremented per message
- **AAD**: Additional authenticated data (header bytes)
- **Ciphertext**: Plaintext + 16-byte Poly1305 authentication tag

### Minimum Message Size

- Header: 8 bytes
- Nonce: 12 bytes
- Minimum ciphertext (empty plaintext + 16-byte tag): 16 bytes
- **Total minimum**: 36 bytes

### Payload Length

The `payload_len` field in the header specifies the length of the encrypted payload (nonce excluded). The total message size is `8 + 12 + payload_len`.
