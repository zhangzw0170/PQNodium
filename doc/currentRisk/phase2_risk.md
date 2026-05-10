# Phase 2 Risk Analysis: P2P Network Layer

## Phase Overview
- **Goal**: Implement libp2p-based P2P networking — QUIC + TCP transport, Kademlia DHT, Identify protocol.
- **Key Boundaries**: Dual transport (QUIC primary, TCP fallback), DHT for peer discovery, no centralized bootstrap servers.

## Risk Register

### [RISK-201] Unwrap in Transport Construction — MEDIUM
- **Severity**: Medium
- **Impact**: `noise::Config::new(id_keys).unwrap()` in transport.rs could panic if the keypair is incompatible with Noise, crashing the node.
- **Trigger**: Corrupted or invalid Keypair passed to transport construction.
- **Mitigation**: Replace `.unwrap()` with proper error propagation. Return a `Result` from the transport construction function so the caller can handle the error gracefully.
- **Status**: ✅ Fixed

### [RISK-202] No Rate Limiting on Incoming Connections — MEDIUM
- **Severity**: Medium
- **Impact**: An attacker can open thousands of connections to exhaust node resources (file descriptors, memory, CPU).
- **Trigger**: Any network-visible peer initiating excessive connections.
- **Mitigation**: Implement connection limits in the Swarm configuration (`SwarmBuilder::max_established_incoming`). Add per-peer rate limiting on DHT queries and message throughput.
- **Status**: ✅ Fixed — `max_incoming_connections` config (default 128) applied via `with_max_negotiating_inbound_streams()`.

### [RISK-203] No Identity Binding to PeerId — HIGH
- **Severity**: High
- **Impact**: PeerId is derived from the libp2p Ed25519 keypair, but there is no cryptographic binding to the ML-DSA-65 identity key. An attacker who compromises or generates a matching Ed25519 key can impersonate any peer at the transport level, regardless of the PQ identity layer.
- **Trigger**: Quantum computer breaking Ed25519, or Ed25519 key theft.
- **Mitigation**: Bind the PQ identity (ML-DSA-65 public key hash) into the Identify protocol's `app_version` or a custom protocol extension. Verify PQ identity on connection establishment. This requires a custom libp2p protocol or extension to Identify.
- **Status**: ✅ Fixed — PeerId is now derived from SHA-256(ed25519_pk || mldsa65_pk), cryptographically binding both key pairs.

### [RISK-205] No Relay/TURN Support for NAT Traversal — LOW
- **Severity**: Low
- **Impact**: Peers behind symmetric NATs cannot establish direct connections, limiting network reachability.
- **Trigger**: Common home/enterprise network configurations.
- **Mitigation**: Add libp2p Relay v2 protocol support in Phase 4+. Auto-relay for nodes that cannot be directly reached.
- **Status**: Deferred to Phase 4+

### [RISK-206] DHT Bootstrap Relies on Hardcoded Peers — LOW
- **Severity**: Low
- **Impact**: If all hardcoded bootstrap peers are offline or malicious, new nodes cannot join the network.
- **Trigger**: Bootstrap peer outage or compromise.
- **Mitigation**: Maintain a diverse set of bootstrap peers. Implement multi-source bootstrapping (DNS multi-address, well-known peer list). Monitor bootstrap peer health.
- **Status**: Accepted risk — standard for DHT-based networks

### [RISK-207] Connection Drops After ~10s Due to Idle Timeout — MEDIUM
- **Severity**: Medium
- **Impact**: P2P connections are silently closed by libp2p's default idle_connection_timeout (10s). Ping substreams use `ignore_for_keep_alive()` so they don't reset the swarm idle timer. After initial Identify exchange, the connection has no "active" substreams and the swarm closes it.
- **Trigger**: Any two-node connection without continuous application-level data exchange.
- **Mitigation**: Set `idle_connection_timeout` to 24h in `PqNodeConfig`. The QUIC transport already has a 5-second keepalive interval that keeps the transport alive independently.
- **Status**: ✅ Fixed — `idle_connection_timeout: Duration::from_secs(24 * 60 * 60)`

## Threat Model (Phase 2)
- **Attacker Capability**: Network-level attacker (MITM, connection flooding), malicious DHT peers, identity spoofing.
- **Attack Surface**: QUIC/TCP listeners, Kademlia DHT queries/responses, Identify protocol exchanges, connection management.
- **Trust Boundary**: Network is untrusted — all peers are potentially adversarial.

## Security Decisions (ADRs)
- **ADR-007**: Dual transport (QUIC primary, TCP+Noise+Yamux fallback) for maximum compatibility.
- **ADR-008**: mDNS removed from discovery — caused stale peer poisoning on shared networks.
- **ADR-009**: Identify protocol uses transport's Keypair (not random) to prevent public key mismatch errors.
