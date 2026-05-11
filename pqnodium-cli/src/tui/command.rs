use pqnodium_core::envelope::Envelope;
use pqnodium_p2p::event::PqEvent;
use tokio::sync::{mpsc, oneshot};

use super::{AppMessage, AppState, CommandResult, NodeCommand};
use crate::tui::render::LogEntry;

pub(super) fn shorten_peer_id(id: &str) -> String {
    if id.len() > 20 {
        format!("{}…{}", &id[..12], &id[id.len() - 5..])
    } else {
        id.to_string()
    }
}

pub(super) fn submit_input(
    input: &str,
    state: &mut AppState,
    cmd_tx: &mpsc::UnboundedSender<NodeCommand>,
) {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return;
    }

    if trimmed == "/quit" || trimmed == "/exit" {
        state.should_quit = true;
        return;
    }

    if trimmed == "/clear" {
        state.logs.clear();
        state.scroll_offset = 0;
        return;
    }

    if trimmed == "/id" {
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GetPeerId(tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(peer_id) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let _ =
                            tx.send(AppMessage::CommandResponse(CommandResult::PeerId(peer_id)));
                    }
                }
            });
        }
        return;
    }

    if trimmed == "/peers" {
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GetConnectedPeers(tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(peers) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let _ = tx.send(AppMessage::CommandResponse(
                            CommandResult::ConnectedPeers(peers),
                        ));
                    }
                }
            });
        }
        return;
    }

    if trimmed == "/listeners" {
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GetListeners(tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(listeners) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let _ = tx.send(AppMessage::CommandResponse(CommandResult::Listeners(
                            listeners,
                        )));
                    }
                }
            });
        }
        return;
    }

    if trimmed == "/nat" {
        state.push_info("NAT status is reported automatically via AutoNAT events");
        return;
    }

    if let Some(addr_str) = trimmed.strip_prefix("/relay ") {
        let addr = addr_str.trim().to_string();
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::ListenOnRelay(addr, tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let _ = tx.send(AppMessage::CommandResponse(CommandResult::RelayResult(
                            result,
                        )));
                    }
                }
            });
        }
        return;
    }

    if let Some(addr_str) = trimmed.strip_prefix("/dial ") {
        let addr = addr_str.to_string();
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::Dial(addr, tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let _ = tx.send(AppMessage::CommandResponse(CommandResult::DialResult(
                            result,
                        )));
                    }
                }
            });
        }
        return;
    }

    if trimmed.starts_with("/help") || trimmed == "/?" {
        let commands = [
            ("<message>", "Broadcast a text message"),
            ("/id", "Show local peer ID"),
            ("/peers", "Show connected peers"),
            ("/listeners", "Show listening addresses"),
            ("/dial <addr>", "Dial a peer"),
            ("/relay <addr>", "Listen via relay"),
            ("/nat", "Show NAT status info"),
            ("/clear", "Clear log panel"),
            ("/quit", "Exit"),
        ];
        state.push_info("Commands:");
        for (cmd, desc) in &commands {
            state.push_info(format!("  {:<18} {}", cmd, desc));
        }
        return;
    }

    state.push_info(format!("[sending] {trimmed}"));

    if let Some(msg_tx) = super::global_msg_tx() {
        let _ = msg_tx.send(AppMessage::SendMessage(trimmed.to_string()));
    }
}

pub(super) fn event_to_log(event: &PqEvent) -> LogEntry {
    match event {
        PqEvent::Listening { address } => LogEntry::success(format!("listening on {address}")),
        PqEvent::PeerConnected { peer_id } => {
            LogEntry::success(format!("peer connected: {}", shorten_peer_id(peer_id)))
        }
        PqEvent::PeerDisconnected { peer_id } => {
            LogEntry::warn(format!("peer disconnected: {}", shorten_peer_id(peer_id)))
        }
        PqEvent::PeerDiscovered { peer_id, addresses } => {
            let addrs: Vec<String> = addresses.iter().map(|a| a.to_string()).collect();
            LogEntry::info(format!(
                "discovered {} at {:?}",
                shorten_peer_id(peer_id),
                addrs
            ))
        }
        PqEvent::KademliaBootstrapResult {
            success,
            peers_found,
        } => {
            if *success {
                LogEntry::success(format!("Kademlia bootstrap ok ({peers_found} peers)"))
            } else {
                LogEntry::warn(format!("Kademlia bootstrap failed ({peers_found} peers)"))
            }
        }
        PqEvent::MessageReceived { from, data } => {
            if let Ok(env) = Envelope::decode(data) {
                let text = String::from_utf8_lossy(&env.payload);
                LogEntry::info(format!("{}: {text}", shorten_peer_id(&env.sender_id)))
            } else {
                let text = String::from_utf8_lossy(data);
                LogEntry::info(format!("message from {}: {text}", shorten_peer_id(from)))
            }
        }
        PqEvent::InboundConnectionError { error } => {
            LogEntry::error(format!("inbound connection error: {error}"))
        }
        PqEvent::OutboundConnectionError { peer_id, error } => LogEntry::error(format!(
            "outbound error to {}: {error}",
            shorten_peer_id(peer_id)
        )),
        PqEvent::UnknownEvent { description } => LogEntry::warn(format!("unknown: {description}")),
        PqEvent::NatStatus { is_public } => {
            let status = if *is_public { "public" } else { "private" };
            LogEntry::info(format!("NAT status: {status}"))
        }
        PqEvent::RelayReservation {
            relay_peer_id,
            accepted,
        } => {
            if *accepted {
                LogEntry::success(format!(
                    "relay reservation accepted: {}",
                    shorten_peer_id(relay_peer_id)
                ))
            } else {
                LogEntry::warn(format!(
                    "relay reservation failed: {}",
                    shorten_peer_id(relay_peer_id)
                ))
            }
        }
        PqEvent::DirectConnectionUpgraded { peer_id } => {
            LogEntry::success(format!("DCUtR upgrade: {}", shorten_peer_id(peer_id)))
        }
    }
}

pub(super) fn handle_command_result(result: &CommandResult, state: &mut AppState) {
    match result {
        CommandResult::PeerId(peer_id) => {
            state.peer_id_display = shorten_peer_id(peer_id);
            state.peer_id = peer_id.clone();
            state.push_info(format!("peer id: {peer_id}"));
        }
        CommandResult::Listeners(listeners) => {
            if listeners.is_empty() {
                state.push_warn("no listeners");
            } else {
                for addr in listeners {
                    state.push_info(format!("listening: {addr}"));
                }
            }
        }
        CommandResult::ConnectedPeers(peers) => {
            state.connected_count = peers.len();
            if peers.is_empty() {
                state.push_info("no connected peers");
            } else {
                state.push_success(format!("{} connected peer(s):", peers.len()));
                for peer in peers {
                    state.push_info(format!("  {}", shorten_peer_id(peer)));
                }
            }
        }
        CommandResult::DialResult(Ok(())) => {
            state.push_success("dial initiated");
        }
        CommandResult::DialResult(Err(e)) => {
            state.push_error(format!("dial failed: {e}"));
        }
        CommandResult::RelayResult(Ok(())) => {
            state.push_success("relay listen initiated");
        }
        CommandResult::RelayResult(Err(e)) => {
            state.push_error(format!("relay failed: {e}"));
        }
        CommandResult::PublishResult(Ok(())) => {
            state.push_success("message published");
        }
        CommandResult::PublishResult(Err(e)) => {
            state.push_error(format!("publish failed: {e}"));
        }
    }
}
