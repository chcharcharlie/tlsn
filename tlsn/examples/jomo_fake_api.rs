use bytes::{BufMut, BytesMut};
use std::ops::Range;

use hyper::{body::to_bytes, Body, Request, StatusCode};

use futures::{AsyncWriteExt, TryFutureExt};
use tlsn_prover::{bind_prover, ProverConfig};

use tokio_util::compat::FuturesAsyncReadCompatExt;

use {
    async_tungstenite::tokio::connect_async,
    futures::future::ok,
    url::Url,
    ws_stream_tungstenite::*,
};

async fn run() {
    let server = "jomo.id";

    // Basic default prover config
    let config = ProverConfig::builder()
        .id("example")
        .server_dns(server)
        .build()
        .unwrap();

    let url    = Url::parse( "ws://127.0.0.1:61288" ).unwrap();
    let socket = ok( url ).and_then( connect_async ).await.expect( "ws handshake" );
    // Ref: https://github.com/najamelan/ws_stream_tungstenite/blob/f136412bda74579385d43c91bac8a8030cb527bf/examples/close.rs#L120
    let notary_socket     = WsStream::new( socket.0 );

    // Connect to the Server (twitter.com)
    let url_app    = Url::parse( "ws://127.0.0.1:61289" ).unwrap();
    let socket_app = ok( url_app ).and_then( connect_async ).await.expect( "ws handshake" );
    // Ref: https://github.com/najamelan/ws_stream_tungstenite/blob/f136412bda74579385d43c91bac8a8030cb527bf/examples/close.rs#L120
    let client_socket     = WsStream::new( socket_app.0 );

    // Bind the Prover to the sockets
    let (tls_connection, prover_fut, mux_fut) =
        bind_prover(config, client_socket, notary_socket)
            .await
            .unwrap();

    // Spawn the Prover and Mux tasks to be run concurrently
    tokio::spawn(mux_fut);

    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_connection.compat())
        .await
        .unwrap();


    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    let data = "{}".to_string();
    let path = "api/fake";
    let user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36";
    let method = "POST";
    let json: serde_json::Value = serde_json::from_str(data.as_str()).expect("json wrong");
    let mut buf = BytesMut::new().writer();
    serde_json::to_writer(&mut buf, &json)
        .expect("serialization of `serde_json::Value` into `BytesMut` cannot fail");

    // Build the HTTP request to fetch the DMs
    let request = Request::builder()
        .method(method)
        .uri(format!("https://{server}/{path}"))
        .header("Host", server)
        .header("Accept", "*/*")
        .header("Connection", "close")
        .header("User-Agent", user_agent)
        .header("Authority", server)
        .body(Body::from(buf.into_inner().freeze()))
        .unwrap();

    println!("Sending request");

    let response = request_sender.send_request(request).await.unwrap();

    println!("Sent request");

    assert!(response.status() == StatusCode::OK);

    println!("Request OK");

    // Pretty printing :)
    let payload = to_bytes(response.into_body()).await.unwrap().to_vec();
    let parsed =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    println!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // Close the connection to the server
    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();
    client_socket.close().await.unwrap();

    // The Prover task should be done now, so we can grab it.
    let mut prover = prover_task.await.unwrap().unwrap();

    // Identify the ranges in the transcript that contain secrets
    let (public_ranges, private_ranges) = find_ranges(prover.sent_transcript().data(), &[]);

    // Commit to the outbound transcript, isolating the data that contain secrets
    for range in public_ranges.iter().chain(private_ranges.iter()) {
        prover.add_commitment_sent(range.clone()).unwrap();
    }

    // Commit to the full received transcript in one shot, as we don't need to redact anything
    let recv_len = prover.recv_transcript().data().len();

    prover.add_commitment_recv(0..recv_len as u32).unwrap();

    // Finalize, returning the notarized session
    let notarized_session: tlsn_core::NotarizedSession = prover.finalize().await.unwrap();

    println!("Notarization complete!");

    println!(
        "{}",
        serde_json::to_string_pretty(&notarized_session).unwrap()
    );
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], sub_seq: &[&[u8]]) -> (Vec<Range<u32>>, Vec<Range<u32>>) {
    let mut private_ranges = Vec::new();
    for s in sub_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx as u32..(idx + w.len()) as u32);
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() as u32 {
        public_ranges.push(last_end..seq.len() as u32);
    }

    (public_ranges, private_ranges)
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(run());
}