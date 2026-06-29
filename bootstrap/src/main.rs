//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
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
    #[arg(long)]
    advertised_url: Option<String>,

    /// Allow starting without a GPG key (uses a random, unstable Null ID).
    #[arg(long)]
    allow_no_key: bool,

    /// Path to TLS certificate file (PEM) for direct TLS mode.
    /// When set, bootstrap accepts wss:// connections directly.
    /// For nginx TLS termination, omit this and use --advertised-url.
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to TLS private key file (PEM).
    /// Must be used with --tls-cert.
    #[arg(long)]
    tls_key: Option<String>,
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
            // Try GPG key first (recommended for production)
            let gpg_home = dirs::home_dir()
                .map(|h| h.join(".nullnode/gnupg").to_string_lossy().to_string())
                .unwrap_or_else(|| "~/.nullnode/gnupg".to_string());

            if let Some(fp) = get_gpg_fingerprint(&gpg_home) {
                nullnode_dht_core::compute_null_id(&fp)
            } else if args.allow_no_key {
                // --allow-no-key for dev/testing: random unstable ID, NO KEY GENERATION
                tracing::warn!("No GPG key found -- using random unstable ID (--allow-no-key)");
                use rand::Rng;
                let mut rng = rand::thread_rng();
                nullnode_dht_core::compute_null_id(&hex::encode(
                    rng.r#gen::<[u8; 8]>(),
                ))
            } else if let Some(id) = load_or_generate_kyber_id() {
                // Auto-generate Kyber keys for bootstrap identity (only when --allow-no-key NOT set)
                id
            } else {
                eprintln!(
                    "\n\
                     ╔══════════════════════════════════════════════════════════╗\n\
                     ║  FATAL: No GPG key found for the bootstrap server.      ║\n\
                     ╚══════════════════════════════════════════════════════════╝\n\
                     \n\
                     The bootstrap server MUST have a stable, deterministic\n\
                     Null ID derived from a GPG key (or auto-generated Kyber)\n\
                     Without one, the node ID changes on every restart.\n\
                     \n\
                     Options:\n\
                       1. GPG key: see gpg --help for key generation\n\
                       2. --id <NULL_ID> to use specific identity\n\
                       3. --allow-no-key for dev/testing (unstable ID)\n"
                );
                std::process::exit(1);
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
        ssl_certfile: args.tls_cert.clone().unwrap_or_default(),
        ssl_keyfile: args.tls_key.clone().unwrap_or_default(),
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

/// Load or generate Kyber keypair for bootstrap identity.
/// Stored at ~/.nullnode/kyber_keypair.json - persistent across restarts.
fn load_or_generate_kyber_id() -> Option<String> {
    use ml_kem::KeyExport;
    let home = dirs::home_dir()?;
    let kx_path = home.join(".nullnode").join("kyber_keypair.json");
    
    // Ensure directory exists
    let _ = std::fs::create_dir_all(home.join(".nullnode"));
    
    match nullnode_crypto::MlKem1024Keypair::load_or_generate_unencrypted(&kx_path) {
        Ok(kp) => {
            let enc_bytes = hex::encode(kp.enc.to_bytes());
            let id = nullnode_dht_core::compute_null_id(&enc_bytes);
            tracing::info!("Loaded persistent Kyber keypair for bootstrap identity");
            Some(id)
        }
        Err(e) => {
            tracing::error!("Failed to load/generate Kyber keypair: {}", e);
            None
        }
    }
}

/// SECURITY FIX (H5): Get the server's GPG fingerprint from the local cert file.
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
    let pile = PacketParserBuilder::from_bytes(armored.as_bytes())
        .map_err(|e| tracing::debug!("parse cert: {}", e))
        .ok()
        .and_then(|b| b.into_packet_pile().ok())?;

    for packet in pile.descendants() {
        if let sequoia_openpgp::Packet::PublicKey(cert) = packet {
            return Some(cert.fingerprint().to_hex().to_uppercase());
        }
    }
    None
}