pub mod command;
pub mod render;

use libp2p::Multiaddr;
use pqnodium_core::envelope::Envelope;
use pqnodium_p2p::event::PqEvent;
use pqnodium_p2p::node::PqNode;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::DefaultTerminal;
use std::collections::HashSet;
use std::io;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use command::{event_to_log, handle_command_result, shorten_peer_id, submit_input};
use render::LogEntry;

const MAX_DEDUP_MESSAGES: usize = 10000;

// ── App State ──────────────────────────────────────────────────────────

struct AppState {
    logs: Vec<LogEntry>,
    input: String,
    input_cursor: usize,
    scroll_offset: u16,
    auto_scroll: bool,
    should_quit: bool,
    peer_id: String,
    peer_id_display: String,
    connected_count: usize,
    nat_public: Option<bool>,
    seen_messages: HashSet<[u8; 32]>,
}

impl AppState {
    fn new(peer_id: String) -> Self {
        let display = shorten_peer_id(&peer_id);
        Self {
            logs: Vec::new(),
            input: String::new(),
            input_cursor: 0,
            scroll_offset: 0,
            auto_scroll: true,
            should_quit: false,
            peer_id,
            peer_id_display: display,
            connected_count: 0,
            nat_public: None,
            seen_messages: HashSet::new(),
        }
    }

    fn push_log(&mut self, entry: LogEntry) {
        self.logs.push(entry);
        if self.auto_scroll {
            self.scroll_offset = u16::MAX;
        }
    }

    fn push_info(&mut self, text: impl Into<String>) {
        self.push_log(LogEntry::info(text));
    }

    fn push_success(&mut self, text: impl Into<String>) {
        self.push_log(LogEntry::success(text));
    }

    fn push_warn(&mut self, text: impl Into<String>) {
        self.push_log(LogEntry::warn(text));
    }

    fn push_error(&mut self, text: impl Into<String>) {
        self.push_log(LogEntry::error(text));
    }
}

// ── Commands ───────────────────────────────────────────────────────────

enum NodeCommand {
    GetPeerId(oneshot::Sender<String>),
    GetListeners(oneshot::Sender<Vec<Multiaddr>>),
    GetConnectedPeers(oneshot::Sender<Vec<String>>),
    Dial(String, oneshot::Sender<Result<(), String>>),
    ListenOnRelay(String, oneshot::Sender<Result<(), String>>),
    Publish(Vec<u8>, oneshot::Sender<Result<(), String>>),
}

enum CommandResult {
    PeerId(String),
    Listeners(Vec<Multiaddr>),
    ConnectedPeers(Vec<String>),
    DialResult(Result<(), String>),
    RelayResult(Result<(), String>),
    PublishResult(Result<(), String>),
}

enum AppMessage {
    PqEvent(PqEvent),
    CommandResponse(CommandResult),
    SendMessage(String),
}

// ── Keyboard reader (OS thread) ────────────────────────────────────────

fn spawn_keyboard_thread(tx: mpsc::UnboundedSender<KeyEvent>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || loop {
        let has_event = event::poll(Duration::from_millis(250)).unwrap_or(false);
        if !has_event {
            continue;
        }
        let Ok(Event::Key(key)) = event::read() else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if tx.send(key).is_err() {
            break;
        }
    })
}

// ── Event poller task (owns PqNode) ────────────────────────────────────

fn spawn_event_poller(
    mut node: PqNode,
    mut cmd_rx: mpsc::UnboundedReceiver<NodeCommand>,
    msg_tx: mpsc::UnboundedSender<AppMessage>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(cmd) = cmd_rx.recv() => {
                    handle_node_command(cmd, &mut node, &msg_tx).await;
                }
                event = node.poll_next() => {
                    match event {
                        Some(pq_event) => {
                            let _ = msg_tx.send(AppMessage::PqEvent(pq_event));
                        }
                        None => break,
                    }
                }
            }
        }
    });
}

async fn handle_node_command(
    cmd: NodeCommand,
    node: &mut PqNode,
    _msg_tx: &mpsc::UnboundedSender<AppMessage>,
) {
    match cmd {
        NodeCommand::GetPeerId(reply) => {
            let _ = reply.send(node.peer_id().to_string());
        }
        NodeCommand::GetListeners(reply) => {
            let _ = reply.send(node.listeners().to_vec());
        }
        NodeCommand::GetConnectedPeers(reply) => {
            let _ = reply.send(node.connected_peers());
        }
        NodeCommand::Dial(addr_str, reply) => {
            let result = match addr_str.parse::<Multiaddr>() {
                Ok(addr) => node.dial(addr).map_err(|e| e.to_string()),
                Err(e) => Err(format!("invalid address: {e}")),
            };
            let _ = reply.send(result);
        }
        NodeCommand::ListenOnRelay(addr_str, reply) => {
            let result = match addr_str.parse::<Multiaddr>() {
                Ok(addr) => node.listen_on_relay(addr).map_err(|e| e.to_string()),
                Err(e) => Err(format!("invalid relay address: {e}")),
            };
            let _ = reply.send(result);
        }
        NodeCommand::Publish(data, reply) => {
            let result = node.publish(&data).map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
    }
}

// ── Key handling ───────────────────────────────────────────────────────

fn handle_key_event(
    key: KeyEvent,
    state: &mut AppState,
    cmd_tx: &mpsc::UnboundedSender<NodeCommand>,
) {
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
            state.should_quit = true;
        }
        KeyCode::Enter => {
            let input = state.input.clone();
            state.input.clear();
            state.input_cursor = 0;
            submit_input(&input, state, cmd_tx);
        }
        KeyCode::Backspace if state.input_cursor > 0 => {
            state.input.remove(state.input_cursor - 1);
            state.input_cursor -= 1;
        }
        KeyCode::Delete if state.input_cursor < state.input.len() => {
            state.input.remove(state.input_cursor);
        }
        KeyCode::Left if state.input_cursor > 0 => {
            state.input_cursor -= 1;
        }
        KeyCode::Right if state.input_cursor < state.input.len() => {
            state.input_cursor += 1;
        }
        KeyCode::Home => {
            state.input_cursor = 0;
        }
        KeyCode::End => {
            state.input_cursor = state.input.len();
        }
        KeyCode::Up => {
            state.auto_scroll = false;
            state.scroll_offset = state.scroll_offset.saturating_sub(1);
        }
        KeyCode::Down => {
            state.scroll_offset = state.scroll_offset.saturating_add(1);
        }
        KeyCode::PageUp => {
            state.auto_scroll = false;
            state.scroll_offset = state.scroll_offset.saturating_sub(10);
        }
        KeyCode::PageDown => {
            state.scroll_offset = state.scroll_offset.saturating_add(10);
        }
        KeyCode::Char(c) => {
            state.input.insert(state.input_cursor, c);
            state.input_cursor += 1;
        }
        _ => {}
    }
}

// ── Global message sender (for oneshot spawn forwarding) ───────────────

static MSG_TX: OnceLock<mpsc::UnboundedSender<AppMessage>> = OnceLock::new();

fn global_msg_tx() -> Option<mpsc::UnboundedSender<AppMessage>> {
    MSG_TX.get().cloned()
}

// ── Main loop ──────────────────────────────────────────────────────────

fn run_app(
    terminal: &mut DefaultTerminal,
    mut state: AppState,
    mut keyboard_rx: mpsc::UnboundedReceiver<KeyEvent>,
    mut msg_rx: mpsc::UnboundedReceiver<AppMessage>,
    cmd_tx: mpsc::UnboundedSender<NodeCommand>,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| render::render(frame, &mut state))?;

        std::thread::sleep(Duration::from_millis(50));

        while let Ok(msg) = msg_rx.try_recv() {
            match msg {
                AppMessage::PqEvent(event) => {
                    match &event {
                        PqEvent::PeerConnected { .. } => state.connected_count += 1,
                        PqEvent::PeerDisconnected { .. } => {
                            state.connected_count = state.connected_count.saturating_sub(1)
                        }
                        PqEvent::NatStatus { is_public } => state.nat_public = Some(*is_public),
                        PqEvent::MessageReceived { data, .. } => {
                            if let Ok(env) = Envelope::decode(data) {
                                let hash = env.content_hash();
                                if !state.seen_messages.insert(hash) {
                                    continue;
                                }
                                if state.seen_messages.len() > MAX_DEDUP_MESSAGES {
                                    let remove_count =
                                        state.seen_messages.len() - MAX_DEDUP_MESSAGES / 2;
                                    let hashes: Vec<[u8; 32]> = state
                                        .seen_messages
                                        .iter()
                                        .take(remove_count)
                                        .copied()
                                        .collect();
                                    for h in hashes {
                                        state.seen_messages.remove(&h);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    state.push_log(event_to_log(&event));
                }
                AppMessage::CommandResponse(result) => {
                    handle_command_result(&result, &mut state);
                }
                AppMessage::SendMessage(text) => {
                    let envelope = Envelope::new(state.peer_id.clone(), text.as_bytes().to_vec());
                    state.seen_messages.insert(envelope.content_hash());
                    let encoded = envelope.encode();
                    let (tx, rx) = oneshot::channel();
                    if cmd_tx.send(NodeCommand::Publish(encoded, tx)).is_ok() {
                        if let Some(msg_tx) = global_msg_tx() {
                            tokio::spawn(async move {
                                if let Ok(result) = rx.await {
                                    let _ = msg_tx.send(AppMessage::CommandResponse(
                                        CommandResult::PublishResult(result),
                                    ));
                                }
                            });
                        }
                    }
                }
            }
        }

        while let Ok(key) = keyboard_rx.try_recv() {
            handle_key_event(key, &mut state, &cmd_tx);
            if state.should_quit {
                break;
            }
        }

        if state.should_quit {
            break;
        }
    }
    Ok(())
}

// ── Public entry point ─────────────────────────────────────────────────

pub fn run_tui_with_peer_id(node: PqNode, peer_id: String) -> anyhow::Result<()> {
    let mut terminal = ratatui::init();

    let (keyboard_tx, keyboard_rx) = mpsc::unbounded_channel::<KeyEvent>();
    let (msg_tx, msg_rx) = mpsc::unbounded_channel::<AppMessage>();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<NodeCommand>();

    let _ = MSG_TX.set(msg_tx.clone());

    let _keyboard_handle = spawn_keyboard_thread(keyboard_tx);
    spawn_event_poller(node, cmd_rx, msg_tx);

    let mut state = AppState::new(peer_id);
    state.push_success("PQNodium started");
    state.push_info("Type /help for commands  ·  ↑↓ scroll  ·  Ctrl+C quit");

    let result = run_app(&mut terminal, state, keyboard_rx, msg_rx, cmd_tx);

    ratatui::restore();
    result.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqnodium_p2p::event::PqEvent;

    fn make_state() -> AppState {
        AppState::new("12D3KooWAbcdefghijklmnopqrstuvwxyz1234567890abcdefghij".to_string())
    }

    fn make_cmd_tx() -> mpsc::UnboundedSender<NodeCommand> {
        let (tx, _rx) = mpsc::unbounded_channel();
        tx
    }

    // ── shorten_peer_id ────────────────────────────────────────────────

    #[test]
    fn shorten_peer_id_long() {
        let id = "12D3KooWAbcdefghijklmnopqrstuvwxyz1234567890abcdefghij";
        let short = shorten_peer_id(id);
        assert!(short.contains("…"));
        assert_eq!(short.len(), 12 + "…".len() + 5);
    }

    #[test]
    fn shorten_peer_id_short() {
        let id = "short";
        assert_eq!(shorten_peer_id(id), "short");
    }

    #[test]
    fn shorten_peer_id_exact_20() {
        let id = "12345678901234567890";
        let short = shorten_peer_id(id);
        assert_eq!(short, id);
    }

    // ── submit_input ──────────────────────────────────────────────────

    #[test]
    fn submit_quit_sets_should_quit() {
        let mut state = make_state();
        let tx = make_cmd_tx();
        submit_input("/quit", &mut state, &tx);
        assert!(state.should_quit);
    }

    #[test]
    fn submit_exit_sets_should_quit() {
        let mut state = make_state();
        let tx = make_cmd_tx();
        submit_input("/exit", &mut state, &tx);
        assert!(state.should_quit);
    }

    #[test]
    fn submit_clear_clears_logs() {
        let mut state = make_state();
        let tx = make_cmd_tx();
        state.push_info("hello");
        assert_eq!(state.logs.len(), 1);
        submit_input("/clear", &mut state, &tx);
        assert!(state.logs.is_empty());
    }

    #[test]
    fn submit_empty_ignored() {
        let mut state = make_state();
        let tx = make_cmd_tx();
        submit_input("   ", &mut state, &tx);
        assert!(state.logs.is_empty());
    }

    #[test]
    fn submit_help_shows_commands() {
        let mut state = make_state();
        let tx = make_cmd_tx();
        submit_input("/help", &mut state, &tx);
        assert!(state.logs.len() >= 2);
        assert!(state.logs[0].text.contains("Commands"));
    }

    #[test]
    fn submit_nat_shows_info() {
        let mut state = make_state();
        let tx = make_cmd_tx();
        submit_input("/nat", &mut state, &tx);
        assert!(state.logs[0].text.contains("AutoNAT"));
    }

    #[test]
    fn submit_plain_text_sends_publish() {
        let mut state = make_state();
        let tx = make_cmd_tx();
        submit_input("hello world", &mut state, &tx);
        assert_eq!(state.logs.len(), 1);
        assert!(state.logs[0].text.contains("[sending]"));
    }

    // ── event_to_log ──────────────────────────────────────────────────

    #[test]
    fn event_to_log_nat_public() {
        let event = PqEvent::NatStatus { is_public: true };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("public"));
    }

    #[test]
    fn event_to_log_nat_private() {
        let event = PqEvent::NatStatus { is_public: false };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("private"));
    }

    #[test]
    fn event_to_log_relay_accepted() {
        let event = PqEvent::RelayReservation {
            relay_peer_id: "12D3Relay".to_string(),
            accepted: true,
        };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("accepted"));
    }

    #[test]
    fn event_to_log_relay_failed() {
        let event = PqEvent::RelayReservation {
            relay_peer_id: "12D3Relay".to_string(),
            accepted: false,
        };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("failed"));
    }

    #[test]
    fn event_to_log_dcutr_upgrade() {
        let event = PqEvent::DirectConnectionUpgraded {
            peer_id: "12D3Peer".to_string(),
        };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("DCUtR"));
        assert!(entry.text.contains("12D3Peer"));
    }

    #[test]
    fn event_to_log_listening() {
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/1234/quic-v1".parse().unwrap();
        let event = PqEvent::Listening { address: addr };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("listening"));
    }

    #[test]
    fn event_to_log_peer_connected() {
        let event = PqEvent::PeerConnected {
            peer_id: "12D3Test".to_string(),
        };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("connected"));
    }

    #[test]
    fn event_to_log_peer_disconnected() {
        let event = PqEvent::PeerDisconnected {
            peer_id: "12D3Test".to_string(),
        };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("disconnected"));
    }

    #[test]
    fn event_to_log_inbound_error() {
        let event = PqEvent::InboundConnectionError {
            error: "timeout".to_string(),
        };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("timeout"));
    }

    #[test]
    fn event_to_log_outbound_error() {
        let event = PqEvent::OutboundConnectionError {
            peer_id: "12D3P".to_string(),
            error: "refused".to_string(),
        };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("refused"));
    }

    #[test]
    fn event_to_log_unknown() {
        let event = PqEvent::UnknownEvent {
            description: "something".to_string(),
        };
        let entry = event_to_log(&event);
        assert!(entry.text.contains("something"));
    }

    // ── handle_command_result ──────────────────────────────────────────

    #[test]
    fn cmd_result_peer_id() {
        let mut state = make_state();
        handle_command_result(
            &CommandResult::PeerId("12D3FullPeerIdExample".to_string()),
            &mut state,
        );
        assert!(state.logs[0].text.contains("12D3FullPeerIdExample"));
    }

    #[test]
    fn cmd_result_listeners_empty() {
        let mut state = make_state();
        handle_command_result(&CommandResult::Listeners(vec![]), &mut state);
        assert!(state.logs[0].text.contains("no listeners"));
    }

    #[test]
    fn cmd_result_listeners_some() {
        let mut state = make_state();
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/9999/quic-v1".parse().unwrap();
        handle_command_result(&CommandResult::Listeners(vec![addr]), &mut state);
        assert!(state.logs[0].text.contains("9999"));
    }

    #[test]
    fn cmd_result_connected_peers_empty() {
        let mut state = make_state();
        handle_command_result(&CommandResult::ConnectedPeers(vec![]), &mut state);
        assert!(state.logs[0].text.contains("no connected"));
    }

    #[test]
    fn cmd_result_connected_peers_some() {
        let mut state = make_state();
        handle_command_result(
            &CommandResult::ConnectedPeers(vec!["peer1".to_string()]),
            &mut state,
        );
        assert!(state.logs[0].text.contains("1 connected"));
        assert_eq!(state.connected_count, 1);
    }

    #[test]
    fn cmd_result_dial_ok() {
        let mut state = make_state();
        handle_command_result(&CommandResult::DialResult(Ok(())), &mut state);
        assert!(state.logs[0].text.contains("dial initiated"));
    }

    #[test]
    fn cmd_result_dial_err() {
        let mut state = make_state();
        handle_command_result(
            &CommandResult::DialResult(Err("timeout".to_string())),
            &mut state,
        );
        assert!(state.logs[0].text.contains("dial failed"));
    }

    #[test]
    fn cmd_result_relay_ok() {
        let mut state = make_state();
        handle_command_result(&CommandResult::RelayResult(Ok(())), &mut state);
        assert!(state.logs[0].text.contains("relay listen initiated"));
    }

    #[test]
    fn cmd_result_relay_err() {
        let mut state = make_state();
        handle_command_result(
            &CommandResult::RelayResult(Err("denied".to_string())),
            &mut state,
        );
        assert!(state.logs[0].text.contains("relay failed"));
    }

    #[test]
    fn cmd_result_publish_ok() {
        let mut state = make_state();
        handle_command_result(&CommandResult::PublishResult(Ok(())), &mut state);
        assert!(state.logs[0].text.contains("published"));
    }

    #[test]
    fn cmd_result_publish_err() {
        let mut state = make_state();
        handle_command_result(
            &CommandResult::PublishResult(Err("no peers".to_string())),
            &mut state,
        );
        assert!(state.logs[0].text.contains("publish failed"));
    }

    // ── handle_key_event ──────────────────────────────────────────────

    #[test]
    fn key_ctrl_c_quits() {
        let mut state = make_state();
        let tx = make_cmd_tx();
        let key = KeyEvent::new(KeyCode::Char('c'), event::KeyModifiers::CONTROL);
        handle_key_event(key, &mut state, &tx);
        assert!(state.should_quit);
    }

    #[test]
    fn key_enter_clears_input() {
        let mut state = make_state();
        state.input = "hello".to_string();
        state.input_cursor = 5;
        let tx = make_cmd_tx();
        let key = KeyEvent::new(KeyCode::Enter, event::KeyModifiers::NONE);
        handle_key_event(key, &mut state, &tx);
        assert!(state.input.is_empty());
        assert_eq!(state.input_cursor, 0);
        assert_eq!(state.logs.len(), 1);
    }

    #[test]
    fn key_char_appends() {
        let mut state = make_state();
        let tx = make_cmd_tx();
        let key = KeyEvent::new(KeyCode::Char('x'), event::KeyModifiers::NONE);
        handle_key_event(key, &mut state, &tx);
        assert_eq!(state.input, "x");
        assert_eq!(state.input_cursor, 1);
    }

    #[test]
    fn key_backspace_removes() {
        let mut state = make_state();
        state.input = "ab".to_string();
        state.input_cursor = 2;
        let tx = make_cmd_tx();
        let key = KeyEvent::new(KeyCode::Backspace, event::KeyModifiers::NONE);
        handle_key_event(key, &mut state, &tx);
        assert_eq!(state.input, "a");
        assert_eq!(state.input_cursor, 1);
    }

    #[test]
    fn key_delete_removes_at_cursor() {
        let mut state = make_state();
        state.input = "ab".to_string();
        state.input_cursor = 0;
        let tx = make_cmd_tx();
        let key = KeyEvent::new(KeyCode::Delete, event::KeyModifiers::NONE);
        handle_key_event(key, &mut state, &tx);
        assert_eq!(state.input, "b");
        assert_eq!(state.input_cursor, 0);
    }

    #[test]
    fn key_left_right_moves_cursor() {
        let mut state = make_state();
        state.input = "abc".to_string();
        state.input_cursor = 2;
        let tx = make_cmd_tx();
        handle_key_event(
            KeyEvent::new(KeyCode::Left, event::KeyModifiers::NONE),
            &mut state,
            &tx,
        );
        assert_eq!(state.input_cursor, 1);
        handle_key_event(
            KeyEvent::new(KeyCode::Right, event::KeyModifiers::NONE),
            &mut state,
            &tx,
        );
        assert_eq!(state.input_cursor, 2);
    }

    #[test]
    fn key_home_end() {
        let mut state = make_state();
        state.input = "abc".to_string();
        state.input_cursor = 2;
        let tx = make_cmd_tx();
        handle_key_event(
            KeyEvent::new(KeyCode::Home, event::KeyModifiers::NONE),
            &mut state,
            &tx,
        );
        assert_eq!(state.input_cursor, 0);
        handle_key_event(
            KeyEvent::new(KeyCode::End, event::KeyModifiers::NONE),
            &mut state,
            &tx,
        );
        assert_eq!(state.input_cursor, 3);
    }

    #[test]
    fn key_scroll_up_disables_auto_scroll() {
        let mut state = make_state();
        state.auto_scroll = true;
        state.scroll_offset = 5;
        let tx = make_cmd_tx();
        handle_key_event(
            KeyEvent::new(KeyCode::Up, event::KeyModifiers::NONE),
            &mut state,
            &tx,
        );
        assert!(!state.auto_scroll);
        assert_eq!(state.scroll_offset, 4);
    }

    // ── AppState ──────────────────────────────────────────────────────

    #[test]
    fn app_state_push_log_auto_scroll() {
        let mut state = make_state();
        state.push_info("test");
        assert_eq!(state.logs.len(), 1);
        assert_eq!(state.scroll_offset, u16::MAX);
    }

    #[test]
    fn app_state_push_log_no_auto_scroll() {
        let mut state = make_state();
        state.auto_scroll = false;
        state.push_info("test");
        assert_eq!(state.scroll_offset, 0);
    }

    #[test]
    fn app_state_push_levels() {
        let mut state = make_state();
        state.push_info("info");
        state.push_success("ok");
        state.push_warn("warn");
        state.push_error("err");
        assert_eq!(state.logs.len(), 4);
    }
}
