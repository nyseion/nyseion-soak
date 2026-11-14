//! A reference HTTP/2 server (cleartext, prior knowledge) on the `h2` crate, serving the routes the
//! HTTP/2 scenarios use: `GET /baseline2` answers `ok`, `POST /echo` its body, and
//! `GET /static/big.bin` `BIG_LEN` bytes where byte `i` is `i % 251`. A connection whose sends make
//! no progress for the idle timeout is dropped.

use bytes::Bytes;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Notify};

/// The size of `/static/big.bin`.
pub const BIG_LEN: usize = 1 << 20;

/// How the server behaves.
#[derive(Clone, Copy, Debug)]
pub struct H2Opts {
  /// A connection whose response sends make no progress this long is dropped.
  pub idle: Duration,
  /// The largest request body.
  pub max_body: usize,
  /// The largest header list.
  pub max_header_list: u32,
}

impl Default for H2Opts {
  fn default() -> Self {
    Self { idle: Duration::from_millis(500), max_body: 1 << 20, max_header_list: 16 << 10 }
  }
}

pub async fn spawn_h2(opts: H2Opts) -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let _task = tokio::spawn(async move {
    loop {
      let Ok((stream, _)) = listener.accept().await else { return };
      let _conn = tokio::spawn(serve(stream, opts));
    }
  });
  addr
}

async fn serve(stream: tokio::net::TcpStream, opts: H2Opts) {
  let builder = h2::server::Builder::new()
    .max_header_list_size(opts.max_header_list)
    .max_concurrent_streams(256)
    .max_pending_accept_reset_streams(50)
    .max_send_buffer_size(256 << 10)
    .clone();
  let Ok(Ok(mut conn)) = tokio::time::timeout(opts.idle * 4, builder.handshake(stream)).await
  else {
    return;
  };
  // Set by a stream whose sends stalled: the connection is dropped, which closes the socket.
  let stalled = Arc::new(Notify::new());
  loop {
    let next = tokio::select! {
      next = conn.accept() => next,
      () = stalled.notified() => return,
    };
    match next {
      Some(Ok((req, respond))) => {
        let stalled = stalled.clone();
        let _stream = tokio::spawn(async move {
          if handle(req, respond, opts).await.is_err() {
            stalled.notify_one();
          }
        });
      }
      // A connection error (h2 has sent its GOAWAY) or the end of the connection.
      Some(Err(_)) | None => {
        // Let a GOAWAY flush before the socket goes.
        let _ =
          tokio::time::timeout(opts.idle, std::future::poll_fn(|cx| conn.poll_closed(cx))).await;
        return;
      }
    }
  }
}

/// The error is a stall: the response could not be sent within the idle timeout.
async fn handle(
  req: http::Request<h2::RecvStream>,
  mut respond: h2::server::SendResponse<Bytes>,
  opts: H2Opts,
) -> Result<(), ()> {
  let (parts, mut body) = req.into_parts();
  let status = |code: u16| http::Response::builder().status(code).body(()).unwrap();
  match (parts.method.as_str(), parts.uri.path()) {
    ("GET", "/baseline2") => {
      let mut send = respond.send_response(status(200), false).map_err(drop)?;
      send.send_data(Bytes::from_static(b"ok"), true).map_err(drop)
    }
    ("POST", "/echo") => {
      let declared: Option<usize> = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|el| el.to_str().ok()?.parse().ok());
      if declared.is_some_and(|el| el > opts.max_body) {
        let _ = respond.send_response(status(413), true);
        return Ok(());
      }
      let mut got = Vec::new();
      while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return Ok(()) };
        let _ = body.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
        if got.len() > opts.max_body {
          let _ = respond.send_response(status(413), true);
          return Ok(());
        }
      }
      let mut send = respond.send_response(status(200), false).map_err(drop)?;
      send.send_data(Bytes::from(got), true).map_err(drop)
    }
    ("GET", "/static/big.bin") => {
      let mut send = respond.send_response(status(200), false).map_err(drop)?;
      let mut at = 0;
      while at < BIG_LEN {
        send.reserve_capacity((BIG_LEN - at).min(64 << 10));
        let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx));
        let n = match tokio::time::timeout(opts.idle, capacity).await {
          Ok(Some(Ok(n))) if n > 0 => n,
          Ok(Some(Ok(_))) => continue,
          Ok(_) => return Ok(()),
          Err(_) => return Err(()),
        };
        let chunk: Vec<u8> = (at..at + n).map(|idx| (idx % 251) as u8).collect();
        at += n;
        send.send_data(Bytes::from(chunk), at == BIG_LEN).map_err(drop)?;
      }
      Ok(())
    }
    _ => {
      let _ = respond.send_response(status(404), true);
      Ok(())
    }
  }
}
