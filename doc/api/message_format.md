# Message Format

*Updated: Phase 1 implementation complete. Message protocol defined in `pqnodium-core/src/message.rs`.*

## Encoding
- Custom binary format with version prefix (not Protobuf).

## Packet Structure
- Header (Version, Type, Timestamp)
- Payload (AEAD-encrypted with ChaCha20-Poly1305)

## Wire Format
See `pqnodium-core/src/message.rs` for the current implementation. The message protocol includes:
- Message type enum (Text, File, etc.)
- Sender/recipient identity references
- Sequence numbers for replay protection
- AEAD nonce + ciphertext + tag
