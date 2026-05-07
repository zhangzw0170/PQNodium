# Tauri IPC Interface

*Updated: Phase 3b shell exists with stub commands.*

## Implemented Commands (src-tauri/src/main.rs)

| Command | Description |
|---------|-------------|
| `get_peer_id` | Returns the local node's Peer ID |
| `get_version` | Returns the application version string |

## Planned Commands (Phase 4+)

| Command | Description |
|---------|-------------|
| `init` | Initialize node with identity |
| `send_message(peer_id, content)` | Send encrypted message to peer |
| `get_contacts` | List known peers |

## Planned Events (Core → Frontend)

| Event | Description |
|-------|-------------|
| `message_received` | Incoming encrypted message |
| `peer_connected` | New peer connected |
| `peer_disconnected` | Peer disconnected |
