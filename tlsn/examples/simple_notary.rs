use std::env;

use async_tungstenite::{accept_async, tokio::TokioAdapter};
use eyre::{eyre, Result};
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::{fs::File as StdFile, io::BufReader, sync::Arc};
use tlsn_notary::{bind_notary, NotaryConfig};
use tokio::{fs::File, net::TcpListener};
use tokio_rustls::TlsAcceptor;
use ws_stream_tungstenite::*;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    tokio::spawn(async move {
        let hc_addr = env::args()
            .nth(1)
            .unwrap_or_else(|| "0.0.0.0:8080".to_string());
        let hc_listener = TcpListener::bind(&hc_addr).await.unwrap();
        println!("Listening on: {}", hc_addr);
        loop {
            // Asynchronously wait for an inbound socket.
            let (hc_tcp_stream, _) = hc_listener.accept().await.unwrap();
            let _ = hc_tcp_stream.writable().await;
            let _ = hc_tcp_stream.try_write(b"ok");
        }
    });

    // Allow passing an address to listen on as the first argument of this
    // program, but otherwise we'll just set up our TCP listener on
    // 127.0.0.1:8080 for connections.
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:61288".to_string());

    // Next up we create a TCP listener which will listen for incoming
    // connections. This TCP listener is bound to the address we determined
    // above and must be associated with an event loop.
    let listener = TcpListener::bind(&addr).await.unwrap();

    println!("Listening on: {}", addr);

    // Generate a signing key
    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).unwrap();

    loop {
        // Asynchronously wait for an inbound socket.
        let (tcp_stream, peer_addr) = listener.accept().await.unwrap();

        println!("Accepted connections from: {}", peer_addr);

        // // Load the private key and cert needed for TLS connection from fixture folder — can be swapped out when we stop using static self signed cert
        // let (tls_private_key, tls_certificates) = load_tls_key_and_cert().await.unwrap();
        // // Build a TCP listener with TLS enabled
        // let mut server_config = ServerConfig::builder()
        //     .with_safe_defaults()
        //     .with_no_client_auth()
        //     .with_single_cert(tls_certificates, tls_private_key)
        //     .map_err(|err| eyre!("Failed to instantiate notary server tls config: {err}"))
        //     .unwrap();

        // // Set the http protocols we support
        // server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // let tls_config = Arc::new(server_config);
        // let acceptor = TlsAcceptor::from(tls_config);
        // let tls_stream = acceptor.accept(tcp_stream).await.unwrap();

        let s = accept_async(TokioAdapter::new(tcp_stream))
            .await
            .expect("ws handshake");
        let ws = WsStream::new(s);

        {
            let signing_key = signing_key.clone();

            // Spawn notarization task to be run concurrently
            tokio::spawn(async move {
                // Setup default notary config. Normally a different ID would be generated
                // for each notarization.
                let config = NotaryConfig::builder().id("example").build().unwrap();

                // Bind the notary to the socket
                let (notary, notary_fut) = bind_notary(config, ws).unwrap();

                // Run the notary
                tokio::try_join!(
                    notary_fut,
                    notary.notarize::<p256::ecdsa::Signature>(&signing_key)
                )
                .unwrap();
            });
        }
    }
}

/// Load notary tls private key and cert from static files
async fn load_tls_key_and_cert() -> Result<(PrivateKey, Vec<Certificate>)> {
    let mut private_key_file_reader = read_pem_file("/data/privkey1.pem").await?;
    let mut private_keys = rustls_pemfile::pkcs8_private_keys(&mut private_key_file_reader)?;
    let private_key = PrivateKey(private_keys.remove(0));

    let mut certificate_file_reader = read_pem_file("/data/cert1.pem").await?;
    let certificates = rustls_pemfile::certs(&mut certificate_file_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    Ok((private_key, certificates))
}

/// Read a PEM-formatted file and return its buffer reader
pub async fn read_pem_file(file_path: &str) -> Result<BufReader<StdFile>> {
    let key_file = File::open(file_path).await?.into_std().await;
    Ok(BufReader::new(key_file))
}

pub struct TLSSignatureProperties {
    pub private_key_pem_path: String,
    pub certificate_pem_path: String,
}
