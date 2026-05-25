use pqnodium_core::envelope::Envelope;
use pqnodium_core::group::types::GroupId;
use pqnodium_p2p::event::PqEvent;
use pqnodium_p2p::group::GroupEvent;
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

fn shorten_hex(id: &str) -> String {
    if id.len() > 16 {
        format!("{}…{}", &id[..8], &id[id.len() - 4..])
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

    if trimmed == "/myid" {
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GetPqnodiumId(tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(id) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let _ = tx.send(AppMessage::CommandResponse(CommandResult::PqnodiumId(id)));
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

    // ── /keys commands ─────────────────────────────────────────────────

    if trimmed == "/keys show" {
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GetKemFingerprint(tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(fp) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let _ = tx.send(AppMessage::CommandResponse(
                            CommandResult::KemFingerprint(fp),
                        ));
                    }
                }
            });
        }
        return;
    }

    if trimmed == "/keys export" {
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GetKemPublicKey(tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(pk_b64) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let _ = tx.send(AppMessage::CommandResponse(CommandResult::KemPublicKey(
                            pk_b64,
                        )));
                    }
                }
            });
        }
        return;
    }

    if let Some(args) = trimmed.strip_prefix("/keys register ") {
        let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
        if parts.len() < 2 {
            state.push_error("usage: /keys register <peer_id_hex> <base64_public_key>");
            return;
        }
        let peer_id_hex = parts[0];
        let pk_b64 = parts[1].trim();

        let peer_id = match crate::parse_peer_id(peer_id_hex) {
            Ok(id) => id,
            Err(e) => {
                state.push_error(format!("invalid peer ID: {e}"));
                return;
            }
        };
        let pk = match crate::import_hybrid_pk_base64(pk_b64) {
            Ok(k) => k,
            Err(e) => {
                state.push_error(format!("invalid public key: {e}"));
                return;
            }
        };
        let (tx, rx) = oneshot::channel();
        if cmd_tx
            .send(NodeCommand::RegisterMemberPk(peer_id, pk, tx))
            .is_ok()
        {
            let peer_hex = peer_id_hex.to_string();
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let res = match result {
                            Ok(()) => CommandResult::MemberPkRegistered(peer_hex),
                            Err(e) => CommandResult::GroupError(e),
                        };
                        let _ = tx.send(AppMessage::CommandResponse(res));
                    }
                }
            });
        }
        return;
    }

    if trimmed == "/keys" || trimmed.starts_with("/keys ") {
        let known = ["/keys show", "/keys export", "/keys register <id> <key>"];
        state.push_info("Usage:");
        for cmd in &known {
            state.push_info(format!("  {cmd}"));
        }
        return;
    }

    // ── /group commands ───────────────────────────────────────────────

    if let Some(args) = trimmed.strip_prefix("/group create ") {
        let hex_ids: Vec<&str> = args.split_whitespace().collect();
        if hex_ids.is_empty() {
            state.push_error("usage: /group create <peer_id_hex> [peer_id_hex...]");
            return;
        }
        let mut members = Vec::new();
        for hex in &hex_ids {
            match crate::parse_peer_id(hex) {
                Ok(id) => members.push(id),
                Err(e) => {
                    state.push_error(format!("invalid peer ID '{hex}': {e}"));
                    return;
                }
            }
        }
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GroupCreate(members, tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let res = match result {
                            Ok(gid) => CommandResult::GroupCreated(gid.to_hex()),
                            Err(e) => CommandResult::GroupError(e),
                        };
                        let _ = tx.send(AppMessage::CommandResponse(res));
                    }
                }
            });
        }
        return;
    }

    if let Some(args) = trimmed.strip_prefix("/group invite ") {
        let parts: Vec<&str> = args.split_whitespace().collect();
        if parts.len() < 2 {
            state.push_error("usage: /group invite <group_id> <peer_id_hex>");
            return;
        }
        let gid_str = parts[0];
        let peer_hex = parts[1];
        let gid = GroupId::from_hex(gid_str);
        let gid_display = gid_str.to_string();
        let member = match crate::parse_peer_id(peer_hex) {
            Ok(id) => id,
            Err(e) => {
                state.push_error(format!("invalid peer ID: {e}"));
                return;
            }
        };
        let (tx, rx) = oneshot::channel();
        if cmd_tx
            .send(NodeCommand::GroupInvite(gid, member, tx))
            .is_ok()
        {
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let res = match result {
                            Ok(()) => CommandResult::GroupInvited(gid_display),
                            Err(e) => CommandResult::GroupError(e),
                        };
                        let _ = tx.send(AppMessage::CommandResponse(res));
                    }
                }
            });
        }
        return;
    }

    if trimmed == "/group list" {
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GroupList(tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(groups) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let _ = tx.send(AppMessage::CommandResponse(CommandResult::GroupList(
                            groups,
                        )));
                    }
                }
            });
        }
        return;
    }

    if let Some(gid_str) = trimmed.strip_prefix("/group members ") {
        let gid = GroupId::from_hex(gid_str.trim());
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GroupMembers(gid, tx)).is_ok() {
            let gid_display = gid_str.trim().to_string();
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let res = match result {
                            Ok(members) => {
                                let member_strs: Vec<String> =
                                    members.iter().map(|m| m.to_string()).collect();
                                CommandResult::GroupMembersList(gid_display, member_strs)
                            }
                            Err(e) => CommandResult::GroupError(e),
                        };
                        let _ = tx.send(AppMessage::CommandResponse(res));
                    }
                }
            });
        }
        return;
    }

    if let Some(gid_str) = trimmed.strip_prefix("/group leave ") {
        let gid = GroupId::from_hex(gid_str.trim());
        let gid_display = gid_str.trim().to_string();
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GroupLeave(gid, tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let res = match result {
                            Ok(()) => CommandResult::GroupLeft(gid_display),
                            Err(e) => CommandResult::GroupError(e),
                        };
                        let _ = tx.send(AppMessage::CommandResponse(res));
                    }
                }
            });
        }
        return;
    }

    if let Some(args) = trimmed.strip_prefix("/group send ") {
        let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
        if parts.len() < 2 {
            state.push_error("usage: /group send <group_id> <text>");
            return;
        }
        let gid = GroupId::from_hex(parts[0]);
        let gid_display = parts[0].to_string();
        let text = parts[1].as_bytes().to_vec();
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GroupSend(gid, text, tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let res = match result {
                            Ok(()) => CommandResult::GroupMessageSent(gid_display),
                            Err(e) => CommandResult::GroupError(e),
                        };
                        let _ = tx.send(AppMessage::CommandResponse(res));
                    }
                }
            });
        }
        return;
    }

    if let Some(gid_str) = trimmed.strip_prefix("/group rekey ") {
        let gid = GroupId::from_hex(gid_str.trim());
        let gid_display = gid_str.trim().to_string();
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GroupRekey(gid, tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let res = match result {
                            Ok(()) => CommandResult::GroupRekeyed(gid_display),
                            Err(e) => CommandResult::GroupError(e),
                        };
                        let _ = tx.send(AppMessage::CommandResponse(res));
                    }
                }
            });
        }
        return;
    }

    if let Some(gid_str) = trimmed.strip_prefix("/group dissolve ") {
        let gid = GroupId::from_hex(gid_str.trim());
        let gid_display = gid_str.trim().to_string();
        let (tx, rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::GroupDissolve(gid, tx)).is_ok() {
            tokio::spawn(async move {
                if let Ok(result) = rx.await {
                    if let Some(tx) = super::global_msg_tx() {
                        let res = match result {
                            Ok(()) => CommandResult::GroupDissolved(gid_display),
                            Err(e) => CommandResult::GroupError(e),
                        };
                        let _ = tx.send(AppMessage::CommandResponse(res));
                    }
                }
            });
        }
        return;
    }

    if trimmed == "/group" || trimmed.starts_with("/group ") {
        let commands = [
            ("/group create <members...>", "Create encrypted group"),
            ("/group invite <gid> <peer>", "Invite member to group"),
            ("/group list", "List joined groups"),
            ("/group members <gid>", "Show group members"),
            ("/group leave <gid>", "Leave a group"),
            ("/group send <gid> <text>", "Send encrypted message"),
            ("/group rekey <gid>", "Rotate group key"),
            ("/group dissolve <gid>", "Dissolve a group"),
        ];
        state.push_info("Group commands:");
        for (cmd, desc) in &commands {
            state.push_info(format!("  {:<28} {}", cmd, desc));
        }
        return;
    }

    // ── /help ─────────────────────────────────────────────────────────

    if trimmed.starts_with("/help") || trimmed == "/?" {
        let commands = [
            ("<message>", "Broadcast a text message"),
            ("/id", "Show libp2p peer ID"),
            ("/myid", "Show PQNodium peer ID"),
            ("/peers", "Show connected peers"),
            ("/listeners", "Show listening addresses"),
            ("/dial <addr>", "Dial a peer"),
            ("/relay <addr>", "Listen via relay"),
            ("/nat", "Show NAT status info"),
            ("/keys show", "Show KEM fingerprint"),
            ("/keys export", "Export KEM public key (base64)"),
            ("/keys register <id> <key>", "Register peer's public key"),
            ("/group create <members...>", "Create encrypted group"),
            ("/group invite <gid> <peer>", "Invite member"),
            ("/group list", "List groups"),
            ("/group members <gid>", "Show members"),
            ("/group leave <gid>", "Leave group"),
            ("/group send <gid> <text>", "Send encrypted message"),
            ("/group rekey <gid>", "Rotate group key"),
            ("/group dissolve <gid>", "Dissolve group"),
            ("/clear", "Clear log panel"),
            ("/quit", "Exit"),
        ];
        state.push_info("Commands:");
        for (cmd, desc) in &commands {
            state.push_info(format!("  {:<28} {}", cmd, desc));
        }
        return;
    }

    state.push_info(format!("[sending] {trimmed}"));

    if let Some(msg_tx) = super::global_msg_tx() {
        let _ = msg_tx.send(AppMessage::SendMessage(trimmed.to_string()));
    }
}

pub(super) fn p2p_event_to_log(event: &PqEvent) -> LogEntry {
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

pub(super) fn group_event_to_log(event: &GroupEvent) -> LogEntry {
    match event {
        GroupEvent::GroupMessage {
            group_id,
            sender_id,
            plaintext,
        } => {
            let text = String::from_utf8_lossy(plaintext);
            let gid_short = shorten_hex(&group_id.to_string());
            LogEntry::info(format!("[{gid_short}] {sender_id}: {text}"))
        }
        GroupEvent::GroupControlApplied { group_id, epoch } => {
            let gid_short = shorten_hex(&group_id.to_string());
            LogEntry::success(format!("group {gid_short} updated (epoch {epoch})"))
        }
        GroupEvent::GroupDissolved { group_id } => {
            let gid_short = shorten_hex(&group_id.to_string());
            LogEntry::warn(format!("group {gid_short} dissolved"))
        }
        GroupEvent::P2P(pq_event) => p2p_event_to_log(pq_event),
        GroupEvent::MalformedMessage { from, reason } => {
            LogEntry::error(format!("malformed message from {from}: {reason}"))
        }
    }
}

pub(super) fn handle_command_result(result: &CommandResult, state: &mut AppState) {
    match result {
        CommandResult::PeerId(peer_id) => {
            state.peer_id_display = shorten_peer_id(peer_id);
            state.peer_id = peer_id.clone();
            state.push_info(format!("libp2p peer id: {peer_id}"));
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
        CommandResult::KemPublicKey(b64) => {
            state.push_info("KEM public key (share with peers):");
            state.push_info(b64.clone());
        }
        CommandResult::KemFingerprint(fp) => {
            state.push_success(format!("KEM fingerprint: {fp}"));
        }
        CommandResult::PqnodiumId(id) => {
            state.push_success(format!("PQNodium ID: {id}"));
        }
        CommandResult::MemberPkRegistered(peer_hex) => {
            state.push_success(format!("registered public key for {peer_hex}"));
        }
        CommandResult::GroupCreated(gid) => {
            state.push_success(format!("group created: {gid}"));
        }
        CommandResult::GroupInvited(gid) => {
            state.push_success(format!("invitation sent to group {gid}"));
        }
        CommandResult::GroupList(groups) => {
            if groups.is_empty() {
                state.push_info("no groups");
            } else {
                state.push_success(format!("{} group(s):", groups.len()));
                for g in groups {
                    state.push_info(format!(
                        "  {}  epoch {}  {} member(s)",
                        shorten_hex(&g.group_id),
                        g.epoch,
                        g.member_count
                    ));
                }
            }
        }
        CommandResult::GroupMembersList(gid, members) => {
            if members.is_empty() {
                state.push_info(format!("no members in group {gid}"));
            } else {
                state.push_success(format!("{} member(s) in group {gid}:", members.len()));
                for m in members {
                    state.push_info(format!("  {}", shorten_hex(m)));
                }
            }
        }
        CommandResult::GroupLeft(gid) => {
            state.push_success(format!("left group {gid}"));
        }
        CommandResult::GroupMessageSent(gid) => {
            state.push_success(format!("message sent to group {gid}"));
        }
        CommandResult::GroupRekeyed(gid) => {
            state.push_success(format!("group {gid} rekeyed"));
        }
        CommandResult::GroupDissolved(gid) => {
            state.push_success(format!("group {gid} dissolved"));
        }
        CommandResult::GroupError(e) => {
            state.push_error(format!("group error: {e}"));
        }
    }
}
