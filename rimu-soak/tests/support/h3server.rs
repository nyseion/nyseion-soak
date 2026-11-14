//! A reference HTTP/3 server on `quinn` and `h3` with a self-signed certificate for `localhost`,
//! serving the routes the HTTP/3 scenarios use: `GET /baseline2` answers `ok`, and
//! `GET /static/big.bin` `BIG_LEN` bytes where byte `i` is `i % 251`.

use bytes::Bytes;
use quinn::{Endpoint, ServerConfig, TransportConfig, VarInt};
use std::{
  net::SocketAddr,
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::Duration,
};

/// Counts a connection while it lives.
struct Live(Arc<AtomicUsize>);

impl Drop for Live {
  fn drop(&mut self) {
    let _ = self.0.fetch_sub(1, Ordering::Relaxed);
  }
}

/// The size of `/static/big.bin`.
pub const BIG_LEN: usize = 1 << 20;

/// The server's limits.
#[derive(Clone, Copy, Debug)]
pub struct H3Opts {
  pub idle: Duration,
  pub max_bidi_streams: u32,
  pub stream_window: u32,
  pub max_field_section: u64,
  /// Connections the server holds at once; one more is dropped silently.
  pub max_conns: Option<usize>,
}

impl Default for H3Opts {
  fn default() -> Self {
    Self {
      idle: Duration::from_secs(3),
      max_bidi_streams: 256,
      stream_window: 1 << 20,
      max_field_section: 16 << 10,
      max_conns: None,
    }
  }
}

fn server_config(opts: H3Opts) -> ServerConfig {
  let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
  let cert_der = cert.cert.der().clone();
  let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
  let provider = Arc::new(rustls::crypto::ring::default_provider());
  let mut tls = rustls::ServerConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key.into())
    .unwrap();
  tls.alpn_protocols = vec![b"h3".to_vec()];
  let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
  let mut cfg = ServerConfig::with_crypto(Arc::new(quic));
  let mut transport = TransportConfig::default();
  transport.max_idle_timeout(Some(opts.idle.try_into().unwrap()));
  transport.max_concurrent_bidi_streams(VarInt::from_u32(opts.max_bidi_streams));
  transport.stream_receive_window(VarInt::from_u32(opts.stream_window));
  cfg.transport_config(Arc::new(transport));
  cfg
}

/// Starts the server on an ephemeral loopback port.
pub fn spawn_h3(opts: H3Opts) -> SocketAddr {
  let endpoint = Endpoint::server(server_config(opts), "127.0.0.1:0".parse().unwrap()).unwrap();
  let addr = endpoint.local_addr().unwrap();
  let live = Arc::new(AtomicUsize::new(0));
  let _task = tokio::spawn(async move {
    while let Some(incoming) = endpoint.accept().await {
      if opts.max_conns.is_some_and(|el| live.load(Ordering::Relaxed) >= el) {
        incoming.ignore();
        continue;
      }
      let _ = live.fetch_add(1, Ordering::Relaxed);
      let live = live.clone();
      let _conn = tokio::spawn(async move {
        let _live = Live(live);
        let Ok(conn) = incoming.await else { return };
        let Ok(mut h3) = h3::server::builder()
          .max_field_section_size(opts.max_field_section)
          .build::<_, Bytes>(h3_quinn::Connection::new(conn))
          .await
        else {
          return;
        };
        while let Ok(Some(resolver)) = h3.accept().await {
          let _stream = tokio::spawn(async move {
            let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
            let ok = |status: u16| http::Response::builder().status(status).body(()).unwrap();
            match req.uri().path() {
              "/baseline2" => {
                if stream.send_response(ok(200)).await.is_ok() {
                  let _ = stream.send_data(Bytes::from_static(b"ok")).await;
                  let _ = stream.finish().await;
                }
              }
              "/static/big.bin" => {
                if stream.send_response(ok(200)).await.is_err() {
                  return;
                }
                for at in (0..BIG_LEN).step_by(64 << 10) {
                  let end = (at + (64 << 10)).min(BIG_LEN);
                  let chunk: Vec<u8> = (at..end).map(|idx| (idx % 251) as u8).collect();
                  if stream.send_data(Bytes::from(chunk)).await.is_err() {
                    return;
                  }
                }
                let _ = stream.finish().await;
              }
              _ => {
                if stream.send_response(ok(404)).await.is_ok() {
                  let _ = stream.finish().await;
                }
              }
            }
          });
        }
      });
    }
  });
  addr
}
