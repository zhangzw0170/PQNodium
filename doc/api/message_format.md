# Message Format

*Updated: Phase 1-8 implementation complete.*

## 1. Point-to-Point Message Format

Defined in `pqnodium-core/src/message.rs`. Used for 1:1 encrypted communication after hybrid handshake.

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

## 2. Broadcast Envelope Format

Defined in `pqnodium-core/src/envelope.rs`. Used for Gossipsub broadcast messages (Phase 6+).

```
+--------+--------+--------+--------+--------+--------+--------+--------+
| version (1 byte)                                                      |
+--------+--------+--------+--------+--------+--------+--------+--------+
| timestamp_ms (8 bytes, little-endian)                                 |
+--------+--------+--------+--------+--------+--------+--------+--------+
| sender_id_len (2 bytes, big-endian)                                   |
+--------+--------+--------+--------+--------+--------+--------+--------+
| sender_id (variable, up to 64 bytes)                                  |
+--------+--------+--------+--------+--------+--------+--------+--------+
| payload_len (4 bytes, big-endian)                                     |
+--------+--------+--------+--------+--------+--------+--------+--------+
| payload (variable)                                                    |
+--------+--------+--------+--------+--------+--------+--------+--------+
```

### Fields

| Field | Size | Description |
|-------|------|-------------|
| `version` | 1 byte | Envelope version (currently `0x01`) |
| `timestamp_ms` | 8 bytes LE | Unix epoch milliseconds (sender clock) |
| `sender_id_len` | 2 bytes BE | Length of sender ID string |
| `sender_id` | variable | Sender identifier (UTF-8, max 64 bytes) |
| `payload_len` | 4 bytes BE | Length of broadcast payload |
| `payload` | variable | Application payload (currently unencrypted) |

### Content Hash (Dedup)

`content_hash()` computes `SHA-256(version || timestamp_ms || sender_id || payload)` for message deduplication.

## 3. Message Deduplication

Defined in `pqnodium-p2p/src/node.rs`. LRU content-hash cache with TTL eviction.

| Parameter | Value | Description |
|-----------|-------|-------------|
| `DEDUP_CAPACITY` | 1024 | Maximum cached hashes |
| `DEDUP_TTL` | 5 minutes | Hash expiry time |
| Pruning | Automatic | Expired entries pruned on every `poll_next()` call |
