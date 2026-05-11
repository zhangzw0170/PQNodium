# Phase 5-8 Risk Analysis: Gossipsub + Envelope + Integration Tests + Dedup

**Phase**: 5-8 — Gossipsub Broadcast, Envelope Wire Format, Integration Tests, Message Deduplication
**Date**: 2026-05-11
**Status**: ✅ Complete

## Scope

- **Phase 5**: Gossipsub broadcast messaging (signed, `pqnodium-v1` topic)
- **Phase 6**: Envelope wire format for structured Gossipsub messages
- **Phase 7**: Gossipsub integration tests (2-node, 3-node)
- **Phase 8**: Content-hash message deduplication (LRU + TTL)

## New Risks

| ID | Risk | Severity | Status | Mitigation |
|----|------|----------|--------|------------|
| RISK-801 | Broadcast payloads not end-to-end encrypted | HIGH | ⚠️ Accepted (current phase) | Known limitation — plaintext broadcasts visible to all subscribers. Encrypted payloads planned for future phase. |
| RISK-802 | Content-hash dedup TTL too short (5 min) | LOW | ✅ Accepted | After TTL expiry, identical content passes through. Acceptable for current broadcast use case. |
| RISK-803 | No Gossipsub publish rate limiting | MEDIUM | ⚠️ Accepted (current phase) | A malicious node can flood the topic. libp2p Gossipsub has built-in peer scoring, but no explicit rate limit on publish. |
| RISK-804 | Envelope sender_id spoofable | MEDIUM | ✅ Mitigated | Gossipsub uses signed message authenticity; sender identity verified at libp2p level. Envelope sender_id is informational. |
| RISK-805 | LRU dedup eviction under memory pressure | LOW | ✅ Mitigated | Fixed capacity (1024 entries) bounds memory usage. Pruning runs on every `poll_next()`. |
| RISK-806 | Gossipsub mesh instability under high churn | MEDIUM | ✅ Mitigated | libp2p's Gossipsub implementation handles mesh maintenance. Tested with 3-node broadcast scenario. |

## Resolved from Previous Phases

| ID | Risk | Phase | New Status |
|----|------|-------|------------|
| RISK-203 | No group/broadcast messaging | 2 | ✅ Mitigated — Gossipsub broadcast implemented |

## Implementation Details

### Gossipsub Configuration

- Signed message authenticity enabled
- Default topic: `pqnodium-v1`
- Max message size: 4 MiB (configurable via `PqNodeConfig`)
- Mesh parameters: libp2p defaults (6 ideal mesh peers)

### Envelope Wire Format

```
[version:1][timestamp_ms:8 LE][sender_id_len:2 BE][sender_id][payload_len:4 BE][payload]
```

Content hash: `SHA-256(version || timestamp_ms || sender_id || payload)`

### Dedup Cache

- Data structure: `LruCache<[u8; 32], Instant>` (SHA-256 hash → insertion time)
- Capacity: 1024 entries
- TTL: 5 minutes
- Pruning: automatic on every `poll_next()` call, removes expired entries

## Test Results

- `cargo test`: 193 passed (all suites)
- `cargo clippy -- -D warnings`: clean
- Integration tests: 10/10 (eight_node_mesh) + 4/4 (gossipsub_messaging)

### Gossipsub Integration Tests

| Test | Description | Result |
|------|-------------|--------|
| `gossipsub_subscribe_unsubscribe` | Subscribe and unsubscribe from topic | ✅ |
| `gossipsub_publish_without_subscribers` | Publish when no subscribers exist | ✅ |
| `two_nodes_gossipsub_message_delivery` | 2-node message delivery | ✅ |
| `three_nodes_broadcast` | 3-node broadcast fan-out | ✅ |

## Accepted Limitations

- **Broadcast payloads unencrypted**: All subscribers can read broadcast content. End-to-end encryption of broadcast payloads requires group key agreement (future).
- **No publish rate limit**: Gossipsub peer scoring provides some protection, but explicit rate limiting is not implemented.
- **Dedup TTL expiry**: After 5 minutes, duplicate messages may be re-delivered.
