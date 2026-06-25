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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nullnode=info".parse()?))
        .init();

    let args = Args::parse();

    let null_id = match args.id {
        Some(ref id) => id.clone(),
        None => {
            // SECURITY FIX (H5): Derive Null ID from GPG fingerprint instead of
            // using a random value. This ensures the bootstrap server's identity
            // is cryptographically linked to its GPG key, preventing impersonation.
            let gpg_home = dirs::home_dir()
                .map(|h| h.join(".nullnode/gnupg").to_string_lossy().to_string())
                .unwrap_or_else(|| "~/.nullnode/gnupg".to_string());

            // Try to get the server's GPG fingerprint
            let fingerprint = get_gpg_fingerprint(&gpg_home).unwrap_or_else(|| {
                tracing::warn!("No GPG key found for bootstrap server -- using fallback random ID");
                use rand::Rng;
                let mut rng = rand::thread_rng();
                hex::encode(&rng.r#gen::<[u8; 8]>())
            });

            nullnode_dht_core::compute_null_id(&fingerprint)
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
        ..Default::default()
    };

    tracing::info!("starting bootstrap server");
    tracing::info!("  Null ID : {}", null_id);
    tracing::info!("  listen  : {}:{}", args.host, args.port);
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
