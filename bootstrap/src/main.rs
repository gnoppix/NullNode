//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// NullNode Bootstrap DHT Server
#[derive(Parser, Debug)]
#[command(name = "nullnode-bootstrap", version, about)]
struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Listen port
    #[arg(long, default_value_t = 9001)]
    port: u16,

    /// Null ID for this node (auto-generated if not provided)
    #[arg(long)]
    id: Option<String>,

    /// SQLite database path for DHT storage
    #[arg(long)]
    db: Option<String>,

    /// Public URL advertised in DHT records when behind a reverse proxy.
    /// When set, the node advertises this URL (e.g. wss://bootstrap.example.com)
    /// instead of its local bind address. Use this when nginx terminates TLS on :443
    /// and forwards WebSocket to this daemon on localhost.
    #[arg(long)]
    advertised_url: Option<String>,

    /// Allow starting without a GPG key (uses a random, unstable Null ID).
    /// DANGER: This is intended only for development and testing. The node ID
    /// will change on every restart, breaking DHT routing. In production you
    /// MUST provide a GPG key so the Null ID is derived deterministically.
    #[arg(long)]
    allow_no_key: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nullnode=info".parse()?))
        .init();

    let args = Args::parse();

    let null_id = match args.id {
        Some(id) => id,
        None => {
            // SECURITY FIX (H5): Derive Null ID from GPG fingerprint instead of
            // using a random value. This ensures the bootstrap server's identity
            // is cryptographically linked to its GPG key, preventing impersonation.
            let gpg_home = dirs::home_dir()
                .map(|h| h.join(".nullnode/gnupg").to_string_lossy().to_string())
                .unwrap_or_else(|| "~/.nullnode/gnupg".to_string());

            // Try to get the server's GPG fingerprint
            match get_gpg_fingerprint(&gpg_home) {
                Some(fp) => nullnode_dht_core::compute_null_id(&fp),
                None => {
                    // In dev mode (#[cfg(test)] or --allow-no-key), fall back to a
                    // random ID so developers can still spin up a node quickly.
                    // In production, refuse to start — an unstable node ID breaks
                    // DHT routing because peers cannot find a consistent bootstrap.
                    #[cfg(test)]
                    {
                        tracing::warn!("No GPG key found -- using random ID (test mode)");
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        nullnode_dht_core::compute_null_id(&hex::encode(
                            rng.r#gen::<[u8; 8]>(),
                        ))
                    }
                    #[cfg(not(test))]
                    {
                        if args.allow_no_key {
                            tracing::warn!(
                                "No GPG key found -- using random ID (--allow-no-key). \
                                 DO NOT use this in production: the node ID will \
                                 change on every restart, breaking DHT routing."
                            );
                            use rand::Rng;
                            let mut rng = rand::thread_rng();
                            nullnode_dht_core::compute_null_id(&hex::encode(
                                rng.r#gen::<[u8; 8]>(),
                            ))
                        } else {
                            eprintln!(
                                "\n\
                                 ╔══════════════════════════════════════════════════════════╗\n\
                                 ║  FATAL: No GPG key found for the bootstrap server.      ║\n\
                                 ╚══════════════════════════════════════════════════════════╝\n\
                                 \n\
                                 The bootstrap server MUST have a stable, deterministic\n\
                                 Null ID derived from a GPG key. Without one, the node\n\
                                 ID changes on every restart, which breaks DHT routing\n\
                                 because peers cannot find a consistent bootstrap node.\n\
                                 \n\
                                 To fix this, generate or import a GPG key:\n\
                                 \n\
                                   1. Generate a new key (recommended):\n\
                                      gpg --homedir ~/.nullnode/gnupg \\\n\
                                          --batch --gen-key <<EOF\n\
                                 %%no-protection\n\
                                 Key-Type: EdDSA\n\
                                 Key-Curve: ed25519\n\
                                 Subkey-Type: ECDH\n\
                                 Subkey-Curve: cv25519\n\
                                 Name-Real: Gnoppix Bootstrap Node\n\
                                 Expire-Date: 0\n\
                                 EOF\n\
                                      gpg --homedir ~/.nullnode/gnupg \\\n\
                                          --armor --export > ~/.nullnode/gnupg/own_cert.asc\n\
                                 \n\
                                   2. Or import an existing key:\n\
                                      gpg --homedir ~/.nullnode/gnupg \\\n\
                                          --import <keyfile>\n\
                                      gpg --homedir ~/.nullnode/gnupg \\\n\
                                          --armor --export <fingerprint> \\\n\
                                          > ~/.nullnode/gnupg/own_cert.asc\n\
                                 \n\
                                 Alternatively, pass --id <NULL_ID> to use a specific\n\
                                 Null ID directly, or pass --allow-no-key to start\n\
                                 anyway with a random (unstable) ID — only for dev.\n"
                            );
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    };

    let db_path = args.db.unwrap_or_else(|| {
        dirs::home_dir()
            .map(|p| p.join(".nullnode/bootstrap_dht.db").to_string_lossy().to_string())
            .unwrap_or_else(|| "bootstrap_dht.db".to_string())
    });

    let config = nullnode_dht_core::NodeConfig {
        null_id: null_id.clone(),
        fingerprint: String::new(),
        host: args.host.clone(),
        port: args.port,
        db_path: Some(db_path.clone()),
        advertised_url: args.advertised_url.clone(),
        ..Default::default()
    };

    tracing::info!("starting bootstrap server");
    tracing::info!("  Null ID : {}", null_id);
    tracing::info!("  listen  : {}:{}", args.host, args.port);
    if let Some(ref url) = args.advertised_url {
        tracing::info!("  advertised URL: {}", url);
    }
    tracing::info!("  db      : {}", db_path);

    let runtime = nullnode_dht_core::DhtNodeRuntime::new(config).await?;
    runtime.start().await?;

    Ok(())
}

/// SECURITY FIX (H5): Get the server's GPG fingerprint from the local cert file.
/// Returns the first key's fingerprint, or None if no cert/key exists.
fn get_gpg_fingerprint(gpg_home: &str) -> Option<String> {
    use sequoia_openpgp::parse::{Parse, PacketParserBuilder};

    let cert_path = std::path::Path::new(gpg_home).join("own_cert.asc");
    if !cert_path.exists() {
        return None;
    }

    let armored = match std::fs::read_to_string(&cert_path) {
        Ok(content) => content,
        Err(_) => return None,
    };

    // Parse the cert and extract the fingerprint
    let pile = match PacketParserBuilder::from_bytes(armored.as_bytes())
        .map_err(|e| tracing::debug!("parse cert: {}", e))
        .ok()
        .and_then(|b| b.into_packet_pile().ok())
    {
        Some(pile) => pile,
        None => return None,
    };

    for packet in pile.descendants() {
        if let sequoia_openpgp::Packet::PublicKey(cert) = packet {
            return Some(cert.fingerprint().to_hex().to_uppercase());
        }
    }
    None
}
