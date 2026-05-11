# Tauri IPC Interface

*Updated: Phase 3b shell exists with stub commands. Phase 5-8 additions reflected in P2P layer.*

## Implemented Commands (src-tauri/src/main.rs)

| Command | Description |
|---------|-------------|
| `get_peer_id` | Returns the local node's Peer ID (stub: returns "not yet implemented") |
| `get_version` | Returns the application version string |
| `get_status` | Returns the connection status (stub: returns "disconnected") |

## Planned Commands (Phase 8+)

| Command | Description |
|---------|-------------|
| `init` | Initialize node with identity |
| `send_message(peer_id, content)` | Send encrypted message to peer |
| `broadcast(content)` | Publish to Gossipsub topic |
| `get_contacts` | List known peers |
| `get_nat_status` | Get NAT type detection result |

## Planned Events (Core → Frontend)

| Event | Description |
|-------|-------------|
| `message_received` | Incoming encrypted message |
| `broadcast_received` | Incoming Gossipsub broadcast (Envelope payload) |
| `peer_connected` | New peer connected |
| `peer_disconnected` | Peer disconnected |
| `nat_status_changed` | NAT type detection result changed |
| `relay_reservation` | Relay reservation status update |
