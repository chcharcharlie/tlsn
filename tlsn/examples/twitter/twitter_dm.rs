// This example shows how to notarize Twitter DMs.
//
// The example uses the notary server implemented in ../../../notary/server

use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::{env, str};
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::{io::AsyncWriteExt as _, sync::mpsc::{UnboundedReceiver, UnboundedSender}};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio::sync::mpsc;
use tracing::{debug, info};
use tls_client_async::ProverEvent;

// Setting of the application server
const SERVER_DOMAIN: &str = "linkedin.com";
const ROUTE: &str = "i/api/1.1/dm/conversation";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

// Setting of the notary server — make sure these are the same with the config in ../../../notary/server
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Load secret variables from environment for twitter server connection
    dotenv::dotenv().ok();
    let conversation_id = env::var("CONVERSATION_ID").unwrap();
    let auth_token = env::var("AUTH_TOKEN").unwrap();
    let access_token = env::var("ACCESS_TOKEN").unwrap();
    let csrf_token = "ajax:6457261595253367649";
    let cookie = r#"li_sugr=ce077607-606e-4fd0-ad64-557016957d7b; bcookie="v=2&87877a76-1081-46e1-8e59-d5ea85717991"; bscookie="v=1&202302181651007f8d6d36-2c9f-4f96-8294-c4b8fda9ba5aAQERHKjKaCqUId1Xq6RIL2Ti1er6nFvx"; liap=true; JSESSIONID="ajax:6457261595253367649"; li_theme=light; li_theme_set=app; PLAY_SESSION=eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InNlc3Npb25faWQiOiI1ZmU0NGE0Yy1hODY4LTQ1NDctOTdhNy1hMDM0OTAwZGJmOGV8MTY5MDk5MjkyOCIsImFsbG93bGlzdCI6Int9IiwicmVjZW50bHktc2VhcmNoZWQiOiIiLCJyZWZlcnJhbC11cmwiOiJodHRwczovL3d3dy5saW5rZWRpbi5jb20vcHJlbWl1bS9zdXJ2ZXkvP3Ryaz1keW5hbWljX2FkX21rdGdfanNzX2hhX2NfUFJFTUlVTV9DX0pTU19BQ1FfREFfR0xPQkFMX0VOX0NvcmVfMTIyXzE2M18yNzhfVmlzaXRzX0FDQ05fVjFfTWF5MjAyMyZ1cHNlbGxPcmRlck9yaWdpbj1keW5hbWljX2FkX21rdGdfanNzX2hhX2NfUFJFTUlVTV9DX0pTU19BQ1FfREFfR0xPQkFMX0VOX0NvcmVfMTIyXzE2M18yNzhfVmlzaXRzX0FDQ05fVjFfTWF5MjAyMyZ1dHlwZT1qb2IiLCJyZWNlbnRseS12aWV3ZWQiOiIiLCJDUFQtaWQiOiLDhFx1MDAxRV_Dr2LCg0vCt8KpX8Kxw7g4fsOfRiIsImV4cGVyaWVuY2UiOiIiLCJ0cmsiOiIifSwibmJmIjoxNjkwOTkyOTI4LCJpYXQiOjE2OTA5OTI5Mjh9.HwBDL3Th_0TvHSqI1AQflx-6OYbnkExdKiVQvXpGSok; lang=v=2&lang=en-US; dfpfpt=830169ea6dd740048ad55b3b61e0a178; _guid=36c05d58-fe19-49fb-8e83-cc8fdd5c9992; li_at=AQEDAQUOe2MDsx_kAAABibQeXc4AAAGQ_7ARvVYAqUevNBw5oBKSxJ1rUIOLf-yqwdwgaObzwnp6OZHEDi2vgj5XYvCmcvoONeteolkhvZ5Dxy4RfOmumz_CuIWwTCud2Om2smko_hu-BjO8eYrA4R02; timezone=America/Los_Angeles; AnalyticsSyncHistory=AQKOMSwnUN-trQAAAZDbo5WszEnV1-35RgD1wL3lSU6UH-pJrl1uJydjFcz4RMWAUQspY1i75IUInROWWEVBKw; lms_ads=AQFlLwAC5JysIgAAAZDbo5X3aeCKtx9R3nE87shpz656CkGY2eDwTb3i0ZYbtkS9JoY1ZBHZqrktPRCqgnoYWQIPvcuu-Kib; lms_analytics=AQFlLwAC5JysIgAAAZDbo5X3aeCKtx9R3nE87shpz656CkGY2eDwTb3i0ZYbtkS9JoY1ZBHZqrktPRCqgnoYWQIPvcuu-Kib; AMCVS_14215E3D5995C57C0A495C55%40AdobeOrg=1; aam_uuid=73702265732347520422945008076147015497; gpv_pn=www.linkedin.com%2Fmynetwork%2Fgrow%2F; s_plt=3.13; s_pltp=www.linkedin.com%2Fmynetwork%2Fgrow%2F; s_ips=982; s_tp=982; s_ppv=www.linkedin.com%2Fmynetwork%2Fgrow%2F%2C100%2C100%2C982%2C1%2C1; s_cc=true; _gcl_au=1.1.1119383641.1721672018; s_sq=lnkdprod%3D%2526c.%2526a.%2526activitymap.%2526page%253Dwww.linkedin.com%25252Fmynetwork%25252Fgrow%25252F%2526link%253DDmitriy%252520Salkutsan%252520Support%252520Dmitriy%25253A%252520Dear%252520OpenLayer%252520team%25252C%252520I%252520hope%252520this%252520message%252520finds%252520you%252520well.%252520My%252520name%252520is%252520Dmitriy.%252520I%252520am%252520an%252520analyst%252520%2526region%253Dmain%2526pageIDType%253D1%2526.activitymap%2526.a%2526.c%2526pid%253Dwww.linkedin.com%25252Fmynetwork%25252Fgrow%25252F%2526pidt%253D1%2526oid%253Dhttps%25253A%25252F%25252Fwww.linkedin.com%25252Fcompany%25252F96339160%25252Fadmin%25252Finbox%25252Fthread%25252F2-YjhlYWMyODItZDI2YS00YzRkLWJiYjctMDM5Y%2526ot%253DA; s_tslv=1721672027403; AMCV_14215E3D5995C57C0A495C55%40AdobeOrg=-637568504%7CMCIDTS%7C19929%7CMCMID%7C73879806083344450252887346127539326082%7CMCAAMLH-1722448486%7C9%7CMCAAMB-1722448486%7CRKhpRz8krg2tLO6pguXWp5olkAcUniQYPHaMWWgdJ3xzPWQmdj0y%7CMCOPTOUT-1721850886s%7CNONE%7CMCCIDH%7C66223344%7CvVersion%7C5.1.1; fptctx2=taBcrIH61PuCVH7eNCyH0FWPWMZs3CpAZMKmhMiLe%252bGyQN0MSPdKbvGEqPWkhuqMpQARq8%252flWi80zRtB495Jeedswb8UMdGvUiYo0Z9W1ZyxHv4s84Wq96Bnz94RN3HRzNH%252b6sZi3%252bevAjA0nRryNXheQQgNlpiSqvB57Up%252fqzm%252bXnEA7DeX0aib7DhOnlgHRBk06wg2nDuoxE6Ec1EhJXMkytf%252brJgtxO68pk%252fM1JnaElJ4m24wt%252fpwW7kYkzFdkt2AJkMOpQ%252fWOqH%252bb2fLVI%252fJm%252fBPWFx9H4Kp8H72oLJFaIr0jMtUxoToGuoziT4Z%252f1TvfqhRk8IBCAl38Fd7ZWqf%252bMym1ei%252f1lulZt3TppQ%253d; li_mc=MTsyMTsxNzIxODQ0Mjk2OzE7MDIxjkjhIiw7bFWoDFzLpOnn3zGSk4zABhA2bx45/GC//tQ=; UserMatchHistory=AQK1eqLePmHD0AAAAZDl7I2Wx-dZAuwSHdoBrUJP7DTrVWQ-bEQnL5hlNJnqv_0Fyad8MDbccO4m3xk1V50vjjvuGCkYGCS9SLD3JgMUCH6EB0nM6OEDizCPww3sYE_84xoklFpK_H11G8No-N1Ev2Wy6Jjhb45vHeeXJ5J3EAWmBRFvCGlu6xuRR90L9B7dy2nOLWudvM_6gKL5TBqRU6yAnfwSGC2Go_DUluRyuhREGiNyUs2uCqIBimIvHGQvdP1nQfGKX9kC6OhVxBoParU3mPr8vmBJ7Zxt_wR8TrD54PqdEzHBWvtysFgotwwJ6J5O9ocRPtNd1aFUshA3cZMFdCOpx-5dd50B2sd1dTThAF49MA; lidc="b=OB71:s=O:r=O:a=O:p=O:g=3348:u=1005:x=1:i=1721844403:t=1721876879:v=2:sig=AQHz4kpO4jK6Rk3eUH-TA953F5NsGrsy""#;

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(NOTARY_HOST)
        .port(NOTARY_PORT)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder().max_sent_data(1<<14).max_recv_data(1<<14).build().unwrap();

    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .unwrap();

    // Configure a new prover with the unique session id returned from notary client.
    let prover_config = ProverConfig::builder()
        .id(session_id)
        .max_sent_data(1<<14)
        .max_recv_data(1<<14)
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    let (tx,mut rx ): (UnboundedSender<ProverEvent>, UnboundedReceiver<ProverEvent>) = mpsc::unbounded_channel();
    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(prover_config, tx)
        .setup(notary_connection.compat())
        .await
        .unwrap();

    tokio::spawn(async move {
        while let Some(i) = rx.recv().await {
            info!("Received prover event: {:?}", i);
        }
    });

    // Open a new socket to the application server.
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Grab a control handle to the Prover
    let prover_ctrl = prover_fut.control();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);
    info!("fffffff");

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .unwrap();
    info!("ggggg");
    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request to fetch the DMs
    let request = Request::builder()
        .uri(format!(
            "https://www.linkedin.com/voyager/api/relationships/dash/connections?decorationId=com.linkedin.voyager.dash.deco.web.mynetwork.ConnectionList-16&count=5&q=search&start=0"
        ))
        .header("Host", SERVER_DOMAIN)
    //     .header("Accept", "*/*")
    //     .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
    //     .header("Authorization", format!("Bearer {access_token}"))
    //     .header(
    //         "Cookie",
    //         format!("auth_token={auth_token}; ct0={csrf_token}"),
    //     )
    //     .header("Authority", SERVER_DOMAIN)
    //     .header("X-Twitter-Auth-Type", "OAuth2Session")
    //     .header("x-twitter-active-user", "yes")
        .header("Cookie", cookie.clone())
        .header("Csrf-Token", csrf_token.clone())
        .body(Empty::<Bytes>::new())
        .unwrap();
    // let request = Request::get("https://quote.cnbc.com/quote-html-webservice/restQuote/symbolType/symbol?symbols=@GC.1")
    // .body(Empty::<Bytes>::new()).unwrap();

    info!("Sending request");

    // Because we don't need to decrypt the response right away, we can defer decryption
    // until after the connection is closed. This will speed up the proving process!
    prover_ctrl.defer_decryption().await.unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    info!("Sent request");

    debug!("server response: {:?}", response);

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    info!("Request OK");

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    let parsed =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    debug!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Upgrade the prover to an HTTP prover, and start notarization.
    let mut prover = prover.to_http().unwrap().start_notarize();

    // Commit to the transcript with the default committer, which will commit using BLAKE3.
    prover.commit().unwrap();

    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    // Dump the notarized session to a file
    let mut file = tokio::fs::File::create("twitter_dm.json").await.unwrap();
    file.write_all(
        serde_json::to_string_pretty(notarized_session.session())
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.session().data().build_substrings_proof();

    // Prove the request, while redacting the secrets from it.
    let request = &notarized_session.transcript().requests[0];

    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)
        .unwrap();

    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)
        .unwrap();

    for header in &request.headers {
        // Only reveal the host header
        if header.name.as_str().eq_ignore_ascii_case("Host") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)
                .unwrap();
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)
                .unwrap();
        }
    }

    // Prove the entire response, as we don't need to redact anything
    let response = &notarized_session.transcript().responses[0];

    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)
        .unwrap();

    // Build the proof
    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    // Dump the proof to a file.
    let mut file = tokio::fs::File::create("twitter_dm_proof.json")
        .await
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();
}
