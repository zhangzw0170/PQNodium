use clap::Parser;
use pqnodium_core::identity::Identity;
use pqnodium_p2p::config::PqNodeConfig;
use pqnodium_p2p::event::PqEvent;
use pqnodium_p2p::node::PqNode;
use std::io::Write;
use std::path::PathBuf;
use tokio::io::AsyncBufReadExt;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "pqnodium")]
#[command(about = "PQNodium — Post-Quantum Decentralized Messaging")]
#[command(version)]
enum Cli {
    /// Generate a new identity keypair and save to file
    #[command()]
    Generate {
        /// Output file path (default: identity.bin)
        #[arg(short, long, default_value = "identity.bin")]
        output: PathBuf,
    },
    /// Start the P2P node and run interactive CLI
    #[command()]
    Start {
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/udp/0/quic-v1")]
        listen: String,
        /// Bootstrap peer multiaddr
        #[arg(short = 'b', long = "bootstrap")]
        bootstrap: Vec<String>,
        /// Identity file path
        #[arg(short, long, default_value = "identity.bin")]
        identity: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli {
        Cli::Generate { output } => cmd_generate(&output),
        Cli::Start {
            listen,
            bootstrap,
            identity,
        } => {
            let config = build_config(&listen, &bootstrap)?;
            let id = load_or_generate_identity(&identity)?;
            cmd_start(config, id).await
        }
    }
}

fn init_tracing() {
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::new("PQNODIUM_LOG")
                .add_directive("pqnodium_cli=debug".parse().unwrap())
                .add_directive("pqnodium_p2p=info".parse().unwrap())
                .add_directive("pqnodium_core=info".parse().unwrap()),
        )
        .init();
}

fn build_config(listen: &str, bootstrap: &[String]) -> anyhow::Result<PqNodeConfig> {
    let listen_addr: libp2p::Multiaddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid listen address: {e}"))?;

    let mut config = PqNodeConfig::new(listen_addr);

    if !bootstrap.is_empty() {
        let peers = bootstrap.iter().filter_map(|s| s.parse().ok()).collect();
        config = config.with_bootstrap_peers(peers);
    }

    Ok(config)
}

fn cmd_generate(output: &PathBuf) -> anyhow::Result<()> {
    let mut rng = rand::rngs::OsRng;
    let id = Identity::generate(&mut rng);
    save_identity(&id, output)?;
    info!("Generated new identity: {}", id.peer_id());
    info!("Saved to {}", output.display());
    Ok(())
}

// Wire format: [ed_pk_len: u32][ed_pk][ed_sk_len: u32][ed_sk][ml_pk_len: u32][ml_pk][ml_sk_len: u32][ml_sk]
fn save_identity(id: &Identity, path: &PathBuf) -> anyhow::Result<()> {
    let ed_pk = id.ed25519_public_key().as_ref();
    let ed_sk = id.ed25519_secret_key().as_ref();
    let ml_pk = id.mldsa65_public_key().as_ref();
    let ml_sk = id.mldsa65_secret_key().as_ref();

    let mut data = Vec::new();
    data.extend_from_slice(&(ed_pk.len() as u32).to_le_bytes());
    data.extend_from_slice(ed_pk);
    data.extend_from_slice(&(ed_sk.len() as u32).to_le_bytes());
    data.extend_from_slice(ed_sk);
    data.extend_from_slice(&(ml_pk.len() as u32).to_le_bytes());
    data.extend_from_slice(ml_pk);
    data.extend_from_slice(&(ml_sk.len() as u32).to_le_bytes());
    data.extend_from_slice(ml_sk);

    std::fs::write(path, &data)?;
    Ok(())
}

fn load_or_generate_identity(path: &PathBuf) -> anyhow::Result<Identity> {
    if path.exists() {
        info!("Loading identity from {}", path.display());
        let data = std::fs::read(path)?;
        let mut pos = 0;

        let read_len = |data: &[u8], pos: &mut usize| -> anyhow::Result<usize> {
            if *pos + 4 > data.len() {
                anyhow::bail!("unexpected end of identity file");
            }
            let len = u32::from_le_bytes(data[*pos..*pos + 4].try_into()?) as usize;
            *pos += 4;
            Ok(len)
        };

        let read_bytes = |data: &[u8], pos: &mut usize, len: usize| -> anyhow::Result<Vec<u8>> {
            if *pos + len > data.len() {
                anyhow::bail!("unexpected end of identity file");
            }
            let bytes = data[*pos..*pos + len].to_vec();
            *pos += len;
            Ok(bytes)
        };

        let ed_pk_len = read_len(&data, &mut pos)?;
        let ed_pk_bytes = read_bytes(&data, &mut pos, ed_pk_len)?;
        let ed_sk_len = read_len(&data, &mut pos)?;
        let ed_sk_bytes = read_bytes(&data, &mut pos, ed_sk_len)?;
        let ml_pk_len = read_len(&data, &mut pos)?;
        let ml_pk_bytes = read_bytes(&data, &mut pos, ml_pk_len)?;
        let ml_sk_len = read_len(&data, &mut pos)?;
        let ml_sk_bytes = read_bytes(&data, &mut pos, ml_sk_len)?;

        use pqnodium_core::crypto::backend::pqc::ed25519::{Ed25519PublicKey, Ed25519SecretKey};
        use pqnodium_core::crypto::backend::pqc::ml_dsa::{MlDsa65PublicKey, MlDsa65SecretKey};

        let ed_pk = Ed25519PublicKey::try_from_slice(&ed_pk_bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid Ed25519 public key"))?;
        let ed_sk = Ed25519SecretKey::try_from_slice(&ed_sk_bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid Ed25519 secret key"))?;
        let ml_pk = MlDsa65PublicKey::try_from_slice(&ml_pk_bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid ML-DSA-65 public key"))?;
        let ml_sk = MlDsa65SecretKey::try_from_slice(&ml_sk_bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid ML-DSA-65 secret key"))?;

        let id = Identity::from_keys(ed_pk, ed_sk, ml_pk, ml_sk);
        info!("Loaded identity: peer_id={}", id.peer_id());
        Ok(id)
    } else {
        info!("Generating new identity...");
        let mut rng = rand::rngs::OsRng;
        let id = Identity::generate(&mut rng);
        save_identity(&id, path)?;
        info!("Saved identity to {}", path.display());
        info!("Peer ID: {}", id.peer_id());
        Ok(id)
    }
}

async fn cmd_start(config: PqNodeConfig, identity: Identity) -> anyhow::Result<()> {
    info!("Starting PQNodium node, peer_id={}", identity.peer_id());
    let mut node = PqNode::new(&config)?;
    info!("Local peer ID: {}", node.peer_id());

    node.start_listening(config.listen_addr.clone())?;
    info!("Listening on random QUIC port...");

    let bootstrapped = !config.bootstrap_peers.is_empty();
    if bootstrapped {
        for addr in &config.bootstrap_peers {
            info!("Adding bootstrap peer: {addr}");
            if let Some(peer_id) = addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::P2p(p) = p {
                    Some(p)
                } else {
                    None
                }
            }) {
                node.add_kad_address(peer_id, addr.clone());
            }
        }
        if let Err(e) = node.bootstrap() {
            tracing::warn!("Bootstrap initiated (may fail without peers): {e}");
        }
    }

    info!("PQNodium node is running. Press Ctrl+C to stop.");
    info!("Type a message and press Enter to broadcast.");

    run_interactive(node).await
}

async fn run_interactive(mut node: PqNode) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<PqEvent>(32);

    // Spawn event loop in background — forwards swarm events to channel.
    let event_handle = tokio::spawn(async move {
        while let Some(event) = node.poll_next().await {
            if tx.send(event).await.is_err() {
                break;
            }
        }
    });

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = std::io::BufWriter::new(std::io::stdout());
    let mut input = String::new();

    loop {
        // Print prompt
        write!(stdout, "> ")?;
        stdout.flush()?;

        input.clear();

        // Race between stdin input and P2P events.
        tokio::select! {
            line = stdin.read_line(&mut input) => {
                if line? == 0 {
                    info!("Input closed, shutting down...");
                    break;
                }

                let trimmed = input.trim();
                if trimmed.is_empty() {
                    continue;
                }

                if trimmed == "/quit" || trimmed == "/exit" {
                    info!("Shutting down...");
                    break;
                }

                if trimmed == "/peers" {
                    // Note: node is owned by the spawned task, so we can't call node methods here.
                    writeln!(stdout, "[peers] (node handle in background)")?;
                    continue;
                }

                if trimmed == "/id" {
                    writeln!(stdout, "[id] (node handle in background)")?;
                    continue;
                }

                if let Some(addr_str) = trimmed.strip_prefix("/dial ") {
                    writeln!(stdout, "[info] dial {addr_str} (not yet wired)")?;
                    continue;
                }

                if trimmed.starts_with("/help") || trimmed == "/?" {
                    writeln!(stdout, "Commands:")?;
                    writeln!(stdout, "  <message>     Broadcast a text message")?;
                    writeln!(stdout, "  /help         Show this help")?;
                    writeln!(stdout, "  /quit         Exit")?;
                    continue;
                }

                info!("Message (not yet encrypted): {trimmed}");
                writeln!(stdout, "[sent] {trimmed} ({} bytes)", trimmed.len())?;
            }

            event = rx.recv() => {
                let Some(event) = event else { break };
                match event {
                    PqEvent::Listening { address } => {
                        // Overwrite the "> " prompt with the event, then re-print prompt.
                        writeln!(stdout, "\r[listen] {address}")?;
                    }
                    PqEvent::PeerConnected { peer_id } => {
                        writeln!(stdout, "\r[connected] {peer_id}")?;
                    }
                    PqEvent::PeerDisconnected { peer_id } => {
                        writeln!(stdout, "\r[disconnected] {peer_id}")?;
                    }
                    PqEvent::PeerDiscovered { peer_id, addresses } => {
                        writeln!(stdout, "\r[discovered] {peer_id} at {addresses:?}")?;
                    }
                    PqEvent::KademliaBootstrapResult {
                        success,
                        peers_found,
                    } => {
                        writeln!(
                            stdout,
                            "\r[kad] bootstrap: {} ({peers_found} peers)",
                            if success { "ok" } else { "failed" },
                        )?;
                    }
                    _ => {}
                }
            }
        }
    }

    event_handle.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_args() {
        let cli = Cli::try_parse_from(["pqnodium", "start"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn parse_generate() {
        let cli = Cli::try_parse_from(["pqnodium", "generate", "-o", "test.bin"]);
        assert!(cli.is_ok());
        if let Cli::Generate { output } = cli.unwrap() {
            assert_eq!(output.to_string_lossy(), "test.bin");
        }
    }

    #[test]
    fn parse_start_with_listen() {
        let cli = Cli::try_parse_from([
            "pqnodium",
            "start",
            "--listen",
            "/ip4/127.0.0.1/udp/9999/quic-v1",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn parse_start_with_bootstrap() {
        let peer_id = libp2p::PeerId::random();
        let addr = format!("/ip4/1.2.3.4/udp/4001/quic-v1/p2p/{peer_id}");
        let config = build_config("/ip4/0.0.0.0/udp/0/quic-v1", &[addr]).unwrap();
        assert_eq!(config.bootstrap_peers.len(), 1);
    }

    #[test]
    fn parse_unknown_command() {
        let result = Cli::try_parse_from(["pqnodium", "fly-to-moon"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_help() {
        let cli = Cli::try_parse_from(["pqnodium", "start", "--help"]);
        assert!(cli.is_err());
    }

    #[test]
    fn build_config_default() {
        let config = build_config("/ip4/0.0.0.0/udp/0/quic-v1", &[]).unwrap();
        assert!(config.bootstrap_peers.is_empty());
    }

    #[test]
    fn build_config_invalid_addr() {
        let result = build_config("not-an-address", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn save_and_load_identity_roundtrip() {
        let tmp = std::env::temp_dir().join("pqnodium_test_identity_roundtrip.bin");
        let _ = std::fs::remove_file(&tmp);

        let mut rng = rand::rngs::OsRng;
        let original = Identity::generate(&mut rng);
        save_identity(&original, &tmp).unwrap();

        let loaded = load_or_generate_identity(&tmp).unwrap();
        assert_eq!(original.peer_id(), loaded.peer_id());

        let msg = b"roundtrip test message";
        let sig = original.sign(msg);
        assert!(loaded.public().verify(msg, &sig));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn save_identity_file_exists() {
        let tmp = std::env::temp_dir().join("pqnodium_test_identity_exists.bin");
        let _ = std::fs::remove_file(&tmp);

        let mut rng = rand::rngs::OsRng;
        let id = Identity::generate(&mut rng);
        save_identity(&id, &tmp).unwrap();
        assert!(tmp.exists());

        let data = std::fs::read(&tmp).unwrap();
        assert!(data.len() > 16);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_nonexistent_identity_generates_new() {
        let tmp = std::env::temp_dir().join("pqnodium_nonexistent.bin");
        let _ = std::fs::remove_file(&tmp);
        assert!(!tmp.exists());

        let result = load_or_generate_identity(&tmp);
        assert!(result.is_ok());
        assert!(tmp.exists());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_truncated_identity_fails() {
        let tmp = std::env::temp_dir().join("pqnodium_truncated.bin");
        std::fs::write(&tmp, &[0u8; 10]).unwrap();

        let result = load_or_generate_identity(&tmp);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_corrupted_identity_fails() {
        let tmp = std::env::temp_dir().join("pqnodium_corrupted.bin");
        let data = [255u8, 0, 0, 0, 0, 0, 0, 0];
        std::fs::write(&tmp, &data).unwrap();

        let result = load_or_generate_identity(&tmp);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_identity_with_extra_data_succeeds() {
        let tmp = std::env::temp_dir().join("pqnodium_extra_data.bin");
        let _ = std::fs::remove_file(&tmp);

        let mut rng = rand::rngs::OsRng;
        let id = Identity::generate(&mut rng);
        save_identity(&id, &tmp).unwrap();

        let mut data = std::fs::read(&tmp).unwrap();
        data.extend_from_slice(b"extra trailing data");
        std::fs::write(&tmp, &data).unwrap();

        let result = load_or_generate_identity(&tmp);
        assert!(result.is_ok());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn display_event() {
        let addr: libp2p::Multiaddr = "/ip4/127.0.0.1/udp/1234/quic-v1".parse().unwrap();
        let event = PqEvent::Listening { address: addr };
        let s = event.to_string();
        assert!(s.contains("127.0.0.1"));
    }

    #[test]
    fn save_identity_different_keys_produce_different_files() {
        let tmp1 = std::env::temp_dir().join("pqnodium_diff_id1.bin");
        let tmp2 = std::env::temp_dir().join("pqnodium_diff_id2.bin");
        let _ = std::fs::remove_file(&tmp1);
        let _ = std::fs::remove_file(&tmp2);

        let mut rng = rand::rngs::OsRng;
        let id1 = Identity::generate(&mut rng);
        let id2 = Identity::generate(&mut rng);
        save_identity(&id1, &tmp1).unwrap();
        save_identity(&id2, &tmp2).unwrap();

        let data1 = std::fs::read(&tmp1).unwrap();
        let data2 = std::fs::read(&tmp2).unwrap();
        assert_ne!(data1, data2);

        let _ = std::fs::remove_file(&tmp1);
        let _ = std::fs::remove_file(&tmp2);
    }
}
