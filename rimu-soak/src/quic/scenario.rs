//! The abusive QUIC/HTTP/3 clients, run in sequence while the steady clients
//! run on. Each returns a [`ScenarioResult`] naming the limit it tripped and the error or
//! rate-limiting it expected. Every scenario has its own deadline.
//!
//! The library abusers are driven with `quinn`; the raw floods — malformed first Initials,
//! overflowing CRYPTO, forged short headers, QPACK encoder-stream instructions — with
//! [`super::raw`] (Initial level) and hand-encoded bytes over `quinn` streams. The pure 1-RTT frame
//! floods (PING, PATH_CHALLENGE, NEW_CONNECTION_ID / RETIRE_CONNECTION_ID, empty packets,
//! out-of-order STREAM gaps, STREAM past the window, a 10,000-range ACK) are driven by the raw
//! 1-RTT client [`super::onertt`], which runs a real TLS handshake but keeps its own QUIC codecs.

use crate::quic::{
  client::{self, Closed},
  driver::{H3Config, H3Policy},
  onertt::{Close, OneRttClient, frames},
  raw,
  wrapsock::FlapSocket,
};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, TokioRuntime, VarInt};
use std::{
  net::{SocketAddr, UdpSocket},
  sync::Arc,
  time::Duration,
};
use tokio::time::Instant;

/// How one abuser went.
#[derive(Clone, Debug)]
pub struct ScenarioResult {
  pub name: String,
  pub pass: bool,
  pub detail: String,
}

/// A scenario that could not run against this target, which counts as passed.
fn skipped(name: &str, why: &str) -> ScenarioResult {
  pass(name, format!("skipped: {why}"))
}

/// Whether `target` is on IPv4 loopback, where the client can send from 127.0.0.2 too.
fn loopback_v4(target: SocketAddr) -> bool {
  target.is_ipv4() && target.ip().is_loopback()
}

fn pass(name: &str, detail: String) -> ScenarioResult {
  ScenarioResult { name: name.into(), pass: true, detail }
}
fn fail(name: &str, detail: String) -> ScenarioResult {
  ScenarioResult { name: name.into(), pass: false, detail }
}

/// Wraps a scenario in a deadline; a scenario that overruns is a failure, not a hang.
async fn with_deadline(
  name: &str,
  secs: u64,
  fut: impl std::future::Future<Output = ScenarioResult>,
) -> ScenarioResult {
  match tokio::time::timeout(Duration::from_secs(secs), fut).await {
    Ok(result) => result,
    Err(_) => fail(name, format!("exceeded its {secs} s deadline (treated as a stall)")),
  }
}

/// Reads the server's `VmRSS` in KiB.
fn rss_kib(pid: u32) -> u64 {
  std::fs::read_to_string(format!("/proc/{pid}/status"))
    .ok()
    .and_then(|text| crate::monitor::parse_status(&text))
    .map_or(0, |el| el.0)
}

/// The server's on-CPU time in nanoseconds, summed over its threads
/// (`/proc/<pid>/task/*/schedstat` field 0), for the flapper's cost.
fn cpu_ns(pid: u32) -> u64 {
  let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/task")) else { return 0 };
  let mut total = 0u64;
  for entry in dir.flatten() {
    if let Ok(text) = std::fs::read_to_string(entry.path().join("schedstat"))
      && let Some(ns) = text.split_whitespace().next().and_then(|el| el.parse::<u64>().ok())
    {
      total = total.wrapping_add(ns);
    }
  }
  total
}

/// Every scenario's name, in the order the soak runs them.
pub const ALL: &[&str] = &[
  "crypto_overflow",
  "initial_flood",
  "forged_short_header",
  "reset_churn",
  "credit_starved",
  "window_starved",
  "qpack_flood",
  "qpack_backlog",
  "oversized_heads",
  "slow_reader",
  "never_read",
  "rebind",
  "never_ack",
  "flapper",
  "raw_flapper",
  "onertt_ack_flood",
  "onertt_ping_flood",
  "onertt_path_challenge_flood",
  "onertt_new_cid_flood",
  "onertt_retire_cid",
  "onertt_empty_packet",
  "onertt_stream_gaps",
  "onertt_stream_past_window",
  "onertt_empty_frames_flood",
  "idle_cap",
];

/// Runs every selected abuser in sequence (except `idle_cap`, which the driver runs after stopping
/// the idle sampler) and collects their results.
pub async fn run_all(cfg: &H3Config, deadline: Instant) -> Vec<ScenarioResult> {
  let p = &cfg.policy;
  let main = cfg.main_addr;
  // The raw floods, the flappers and the ACK flood go to the one-worker server when there is one.
  let (raw_target, raw_pid) = match cfg.idle_addr {
    Some(addr) => (addr, cfg.idle_pid),
    None => (main, cfg.main_pid),
  };
  let mut out = Vec::new();
  macro_rules! step {
    ($name:expr, $secs:expr, $fut:expr) => {
      if p.wants($name) && Instant::now() < deadline {
        out.push(with_deadline($name, $secs, $fut).await);
      }
    };
  }

  // crypto_overflow needs a worker that will *process* its Initial (not Retry it), so it runs
  // against the main server, not the one-worker server that initial_flood saturates with half-opens.
  step!("crypto_overflow", 15, crypto_overflow(p, main));
  step!("initial_flood", 40, initial_flood(p, raw_target));
  step!("forged_short_header", 15, forged_short_header(p, raw_target));
  step!("reset_churn", 15, reset_churn(p, main));
  step!("credit_starved", 15, credit_starved(p, main));
  let starved_secs = (p.idle_timeout * 2).as_secs() + 10;
  step!("window_starved", starved_secs, window_starved(p, main));
  step!("qpack_flood", 15, qpack_flood(p, main));
  step!("qpack_backlog", 15, qpack_backlog(p, main));
  step!("oversized_heads", 15, oversized_heads(p, main));
  step!("slow_reader", 20, slow_reader(p, main));
  step!("never_read", 20, never_read(p, main));
  step!("rebind", 15, rebind(p, main));
  step!("never_ack", 18, never_ack(p, main));
  // The flappers and the ACK flood run on the one-worker monitored server (its own 4×4 steady
  // client) when there is one, so their CPU in ns is attributable and the 3× accounting isolated.
  step!("flapper", 20, flapper(p, raw_target, raw_pid));
  step!("raw_flapper", 20, raw_flapper(p, raw_target, raw_pid));
  step!("onertt_ack_flood", 45, ack_flood(p, raw_target, raw_pid));
  // The raw 1-RTT close-code floods, on the main server so the handshake is not Retry-intercepted.
  // Each has its own internal 3 s close wait; the whole batch is bounded.
  if Instant::now() < deadline {
    match tokio::time::timeout(Duration::from_secs(90), onertt_floods(p, main)).await {
      Ok(results) => out.extend(results),
      Err(_) => out.push(fail("onertt_floods", "exceeded the 90 s batch deadline".into())),
    }
  }
  out
}

/// A client UDP socket for the raw floods: from `127.0.0.<last_octet>` towards a loopback target,
/// from the unspecified address otherwise.
fn raw_socket(target: SocketAddr, last_octet: u8) -> std::io::Result<UdpSocket> {
  let sock = UdpSocket::bind(client::local_bind(target, last_octet))?;
  sock.set_read_timeout(Some(Duration::from_millis(200)))?;
  Ok(sock)
}

/// **Initial flood**: many distinct first Initials, each a one-byte (partial)
/// ClientHello so the handshake stays pending and holds a half-open slot, from several source
/// addresses (127.0.0.2..5, or ::1). Past its half-open limit (rimu-ws: `retry_above_half_open`, 64) the server answers with a
/// Retry. A well-behaved quinn client must still connect during the flood. Pass rule: at least one
/// Retry is seen and the quinn client connects.
async fn initial_flood(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "initial_flood";
  let flood = tokio::task::spawn_blocking(move || {
    let loopback_v4 = target.is_ipv4() && target.ip().is_loopback();
    let octets: &[u8] = if loopback_v4 { &[2, 3, 4, 5] } else { &[0] };
    let mut socks = Vec::new();
    for &o in octets {
      if let Ok(s) = raw_socket(target, o) {
        socks.push(s);
      }
    }
    if socks.is_empty() {
      return Err("no source sockets".to_string());
    }
    let mut rng = tiny_rng(0x1234_5678);
    for _ in 0..150u32 {
      for sock in &socks {
        let mut dcid = [0u8; 8];
        let mut scid = [0u8; 8];
        for b in dcid.iter_mut().chain(scid.iter_mut()) {
          *b = rng() as u8;
        }
        let dgram = raw::client_initial(&dcid, &scid, 0, &[0x01], 0, 1200);
        let _ = sock.send_to(&dgram, target);
      }
      std::thread::sleep(Duration::from_millis(2));
    }
    let (mut retries, mut initials, mut others) = (0u32, 0u32, 0u32);
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
      for sock in &socks {
        if let Ok((len, _)) = sock.recv_from(&mut buf) {
          match raw::classify(&buf[..len]) {
            raw::ReplyKind::Retry => retries += 1,
            raw::ReplyKind::Initial => initials += 1,
            _ => others += 1,
          }
        }
      }
    }
    Ok((socks.len(), retries, initials, others))
  });
  let legit = async {
    let cfg = client::client_config(None, Duration::from_secs(10));
    let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
    let ep = client::endpoint(bind, cfg).map_err(|err| err.to_string())?;
    let conn = client::connect(&ep, target, &p.server_name).await?;
    let got = client::h3_get(conn.clone(), &p.server_name, &p.routes.ok_path).await;
    let got = got.map(|r| r.status);
    ep.close(client::H3_NO_ERROR, b"");
    got
  }
  .await;
  match flood.await {
    Ok(Ok((sources, retries, initials, others))) => {
      let legit_ok = matches!(legit, Ok(200));
      let detail = format!(
        "{sources} sources × 150 Initials; replies {retries} Retry, {initials} Initial, {others} other; legit client {legit:?}"
      );
      if (retries >= 1 || !p.expect_retry) && legit_ok {
        pass(
          name,
          format!("Retry (address validation) and a legit client still connects: {detail}"),
        )
      } else if p.expect_retry {
        fail(name, format!("want ≥1 Retry and a legit connect: {detail}"))
      } else {
        fail(name, format!("want a legit connect: {detail}"))
      }
    }
    Ok(Err(err)) => fail(name, err),
    Err(err) => fail(name, format!("join: {err}")),
  }
}

/// **Forged short headers**: 1-RTT packets to a connection ID that no connection has. The server
/// drops them or sends at most a rate-limited stateless reset (`stateless_reset_per_sec` 100). Pass
/// rule: the server stays up and replies at most `100 × (elapsed_s + 1)` times.
async fn forged_short_header(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "forged_short_header";
  let result = tokio::task::spawn_blocking(move || {
    let sock = raw_socket(target, 3).map_err(|err| err.to_string())?;
    let mut rng = tiny_rng(0x9e37_79b9);
    let begin = std::time::Instant::now();
    for _ in 0..500u32 {
      let mut dcid = [0u8; 8];
      for b in dcid.iter_mut() {
        *b = rng() as u8;
      }
      let _ = sock.send_to(&raw::forged_short(&dcid, 60), target);
    }
    let mut replies = 0u32;
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
      if sock.recv_from(&mut buf).is_ok() {
        replies += 1;
      }
    }
    Ok::<_, String>((replies, begin.elapsed().as_secs()))
  })
  .await;
  match result {
    Ok(Ok((replies, elapsed))) => {
      let rate = p.stateless_reset_per_sec;
      let bound = rate.saturating_mul(u32::try_from(elapsed).unwrap_or(0).saturating_add(1));
      if replies <= bound {
        pass(name, format!("500 forged shorts; {replies} replies ≤ {bound} (rate-limited)"))
      } else {
        fail(name, format!("{replies} replies > {bound}: not rate-limited"))
      }
    }
    Ok(Err(err)) => fail(name, err),
    Err(err) => fail(name, format!("join: {err}")),
  }
}

/// **CRYPTO overflow**: a first Initial whose CRYPTO frame starts more than
/// `CRYPTO_BUFFER_LEN` (4096) bytes past offset 0. The server closes the connection at the Initial
/// level with CRYPTO_BUFFER_EXCEEDED (0x0d); the reply is decrypted with the server-side Initial
/// keys and its CONNECTION_CLOSE code asserted.
async fn crypto_overflow(_: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "crypto_overflow";
  let result = tokio::task::spawn_blocking(move || {
    let sock = raw_socket(target, 4).map_err(|err| err.to_string())?;
    let mut rng = tiny_rng(0xdead_beef);
    let mut dcid = [0u8; 8];
    let mut scid = [0u8; 8];
    for b in dcid.iter_mut().chain(scid.iter_mut()) {
      *b = rng() as u8;
    }
    let dgram = raw::client_initial(&dcid, &scid, 5000, &[0x01], 0, 1200);
    sock.send_to(&dgram, target).map_err(|err| err.to_string())?;
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    // Diagnostics: datagrams received, long-header Initials among them, Initials we could decrypt,
    // and the CONNECTION_CLOSE code if one was found.
    let (mut received, mut initials, mut decrypted) = (0u32, 0u32, 0u32);
    let mut code = None;
    while std::time::Instant::now() < deadline && code.is_none() {
      if let Ok((len, _)) = sock.recv_from(&mut buf) {
        received += 1;
        if matches!(raw::classify(&buf[..len]), raw::ReplyKind::Initial) {
          initials += 1;
        }
        if let Some(frames) = raw::open_server_initial(&dcid, &buf[..len]) {
          decrypted += 1;
          if let Some(found) = raw::connection_close_code(&frames) {
            code = Some(found);
          }
        }
      }
    }
    Ok::<_, String>((received, initials, decrypted, code))
  })
  .await;
  match result {
    Ok(Ok((_, _, _, Some(0x0d)))) => {
      pass(name, "CONNECTION_CLOSE 0x0d CRYPTO_BUFFER_EXCEEDED at the Initial level".into())
    }
    Ok(Ok((r, i, d, Some(code)))) => fail(
      name,
      format!("expected 0x0d, got 0x{code:02x} ({r} dgrams, {i} Initial, {d} decrypted)"),
    ),
    Ok(Ok((r, i, d, None))) => fail(
      name,
      format!("no CONNECTION_CLOSE found ({r} dgrams received, {i} Initial, {d} decrypted in 3 s)"),
    ),
    Ok(Err(err)) => fail(name, err),
    Err(err) => fail(name, format!("join: {err}")),
  }
}

async fn abuser_conn(
  p: &H3Policy,
  target: SocketAddr,
) -> Result<(quinn::Endpoint, quinn::Connection), String> {
  let cfg = client::client_config(None, Duration::from_secs(30));
  let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let ep = client::endpoint(bind, cfg).map_err(|err| err.to_string())?;
  let conn = client::connect(&ep, target, &p.server_name).await?;
  Ok((ep, conn))
}

/// **Stream churn (rapid reset)**: open a stream and reset it, over and over. Past `reset_budget`
/// (100/10 s) the server closes with `H3_EXCESSIVE_LOAD` (0x0107).
async fn reset_churn(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "reset_churn";
  let (ep, conn) = match abuser_conn(p, target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let cancel = VarInt::from_u32(0x010c);
  let mut opened = 0u32;
  for _ in 0..200u32 {
    match conn.open_bi().await {
      Ok((mut send, mut recv)) => {
        let _ = send.write_all(b"x").await;
        let _ = send.reset(cancel);
        let _ = recv.stop(cancel);
        opened += 1;
      }
      Err(_) => break,
    }
  }
  let closed = client::wait_closed(&conn, Duration::from_secs(5)).await;
  ep.close(client::H3_NO_ERROR, b"");
  match closed {
    Closed::App(code) if code == p.excessive_load => {
      pass(name, format!("excessive load (0x{code:04x}) after {opened} resets"))
    }
    other => {
      let want = p.excessive_load;
      fail(name, format!("expected App(0x{want:04x}), got {other:?} after {opened} resets"))
    }
  }
}

/// **Credit-starved streams (stream count)**: open the whole bidi-stream allowance (256) and hold
/// it, then a 257th. The server enforces the limit, so the 257th never gets stream credit.
async fn credit_starved(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "credit_starved";
  let (ep, conn) = match abuser_conn(p, target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let mut held = Vec::new();
  for _ in 0..p.max_bidi_streams {
    match tokio::time::timeout(Duration::from_secs(2), conn.open_bi()).await {
      Ok(Ok((mut send, recv))) => {
        let _ = send.write_all(b"GET").await;
        held.push((send, recv));
      }
      _ => break,
    }
  }
  let opened = held.len();
  let starved = tokio::time::timeout(Duration::from_millis(800), conn.open_bi()).await.is_err();
  let alive = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  if opened >= 1 && starved && alive {
    pass(name, format!("{opened} streams held, one more starved, connection alive"))
  } else {
    fail(name, format!("{opened} held, starved={starved}, alive={alive}"))
  }
}

/// **Window-starved**: a client whose per-stream receive window is 0 asks
/// for the 10 MiB file but keeps its HTTP/3 control and QPACK streams alive (no harness-caused
/// close). The server can send no request-stream data and closes on *its* idle timeout (30 s).
/// quinn's own idle timeout is set to 90 s — well above — so a close near 30 s is the server's, not
/// quinn's, and a [`FlapSocket`] byte counter shows the server's traffic goes quiet (no stream
/// data). Pass: the counter stops growing, no body arrives, and the connection closes in 20..60 s.
async fn window_starved(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "window_starved";
  if target.is_ipv6() {
    return skipped(name, "IPv4 only");
  }
  let runtime = Arc::new(TokioRuntime);
  let inner = match UdpSocket::bind(client::local_bind(target, 1)).and_then(|s| {
    s.set_nonblocking(true)?;
    runtime.wrap_udp_socket(s)
  }) {
    Ok(sock) => sock,
    Err(err) => return fail(name, format!("socket: {err}")),
  };
  let flap = FlapSocket::new(vec![inner]);
  // Per-stream window 0, quinn's idle timeout well above the server's.
  let (lo, hi) = (p.idle_timeout * 2 / 3, p.idle_timeout * 2);
  let quinn_idle = (p.idle_timeout * 3).max(Duration::from_secs(90));
  let cfg = client::client_config_windows(quinn_idle, 0);
  let mut ep = match Endpoint::new_with_abstract_socket(
    EndpointConfig::default(),
    None,
    flap.clone() as Arc<dyn AsyncUdpSocket>,
    runtime,
  ) {
    Ok(ep) => ep,
    Err(err) => return fail(name, format!("endpoint: {err}")),
  };
  ep.set_default_client_config(cfg);
  let conn = match client::connect(&ep, target, &p.server_name).await {
    Ok(conn) => conn,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  // Keep the H3 session (control + QPACK streams) alive for the whole wait.
  let mut session = match client::H3Session::open(conn.clone(), &p.server_name).await {
    Ok(s) => s,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("h3 session: {err}"));
    }
  };
  // Start the request; its response cannot flow with a zero stream window.
  let got = tokio::time::timeout(Duration::from_secs(2), session.get(&p.routes.big_path)).await;
  let body_arrived = matches!(got, Ok(Ok(ref r)) if !r.body.is_empty());
  // Let it settle, then confirm the server's traffic has gone quiet (no stream data).
  tokio::time::sleep(Duration::from_secs(2)).await;
  let quiet_a = flap.bytes_in(0);
  tokio::time::sleep(Duration::from_secs(2)).await;
  let quiet_b = flap.bytes_in(0);
  let begin = Instant::now();
  let closed = client::wait_closed(&conn, hi.saturating_sub(Duration::from_secs(5))).await;
  let close_s = begin.elapsed().as_secs_f64() + 4.0; // includes the 4 s quiet window above
  drop(session);
  ep.close(client::H3_NO_ERROR, b"");
  let went_quiet = quiet_b.saturating_sub(quiet_a) < 4096;
  let window = lo.as_secs_f64()..hi.as_secs_f64();
  let server_timeout = matches!(closed, Closed::TimedOutOrReset) && window.contains(&close_s);
  let detail = format!(
    "zero stream window: body_arrived={body_arrived}, server traffic quiet (Δ {} B over 2 s), close={closed:?} at ~{close_s:.0} s",
    quiet_b.saturating_sub(quiet_a)
  );
  if !body_arrived && went_quiet && server_timeout {
    pass(name, detail)
  } else {
    fail(name, format!("want no body + quiet + server idle close in {window:.0?} s: {detail}"))
  }
}

/// **QPACK encoder-stream flood**: a client QPACK encoder stream that sends Set
/// Dynamic Table Capacity 4096 while the server's advertised capacity is 0. The server closes with
/// QPACK_ENCODER_STREAM_ERROR (0x0201).
async fn qpack_flood(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "qpack_flood";
  let (ep, conn) = match abuser_conn(p, target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let streams = async {
    let mut control = conn.open_uni().await.map_err(|err| format!("open control: {err}"))?;
    control.write_all(&raw::h3_control_stream()).await.map_err(|err| format!("control: {err}"))?;
    let mut enc = conn.open_uni().await.map_err(|err| format!("open enc: {err}"))?;
    // type 0x02, then Set Dynamic Table Capacity 4096 (0x3f, 0xe1, 0x1f), above the server's 0.
    enc
      .write_all(&[raw::H3_QPACK_ENCODER, 0x3f, 0xe1, 0x1f])
      .await
      .map_err(|err| format!("enc: {err}"))?;
    Ok::<_, String>((control, enc))
  }
  .await;
  // Hold the control and encoder streams open until the server acts: dropping them early would
  // reset the control stream (H3_CLOSED_CRITICAL_STREAM) before the encoder instruction is read.
  let held = match streams {
    Ok(held) => held,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("send: {err}"));
    }
  };
  let closed = client::wait_closed(&conn, Duration::from_secs(5)).await;
  drop(held);
  ep.close(client::H3_NO_ERROR, b"");
  match closed {
    Closed::App(0x0201) => {
      pass(name, "QPACK_ENCODER_STREAM_ERROR (0x0201) for capacity above the maximum".into())
    }
    other => fail(name, format!("expected 0x0201, got {other:?}")),
  }
}

/// **QPACK encoder-stream backlog**: on the encoder stream, a long run of Set Dynamic
/// Table Capacity 0 (byte 0x20) — which the decoder consumes as valid no-ops — followed by one
/// unterminated Set Dynamic Table Capacity instruction (0x3f and a long run of 0x80 continuation
/// bytes) that cannot be consumed and so accumulates past the server's backlog cap
/// (`qpack_max_table_capacity * 4 + RETAIN_MAX`, here RETAIN_MAX), or that the server refuses as
/// malformed once its integer cannot fit 62 bits. The server closes with one of
/// `H3Policy::qpack_backlog_codes`: H3_EXCESSIVE_LOAD (0x0107) for a backlog cap, or
/// QPACK_ENCODER_STREAM_ERROR (0x0201) for the malformed integer. The plain 0x20
/// run alone is consumed and draws no close; this scenario confirms the backlog cap it is meant to
/// probe.
async fn qpack_backlog(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "qpack_backlog";
  let (ep, conn) = match abuser_conn(p, target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let streams = async {
    let mut control = conn.open_uni().await.map_err(|err| format!("open control: {err}"))?;
    control.write_all(&raw::h3_control_stream()).await.map_err(|err| format!("control: {err}"))?;
    let mut enc = conn.open_uni().await.map_err(|err| format!("open enc: {err}"))?;
    // Encoder stream: the type byte, then many valid Set-Dynamic-Table-Capacity-0 no-ops, then one
    // unterminated capacity instruction (0x3f prefix + endless 0x80 continuation) of ~8 KiB that
    // the decoder cannot complete, so it backs up past the cap.
    let mut bytes = vec![raw::H3_QPACK_ENCODER];
    bytes.extend(std::iter::repeat_n(0x20u8, 4096));
    bytes.push(0x3f);
    bytes.extend(std::iter::repeat_n(0x80u8, 8192));
    enc.write_all(&bytes).await.map_err(|err| format!("enc: {err}"))?;
    Ok::<_, String>((control, enc))
  }
  .await;
  let held = match streams {
    Ok(held) => held,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("send: {err}"));
    }
  };
  let closed = client::wait_closed(&conn, Duration::from_secs(5)).await;
  drop(held);
  ep.close(client::H3_NO_ERROR, b"");
  match closed {
    Closed::App(code) if p.accepts_qpack_backlog_close(code) => pass(
      name,
      format!("closed with 0x{code:04x} for an encoder-stream instruction that never completes"),
    ),
    other => {
      let want: Vec<String> =
        p.qpack_backlog_codes.iter().map(|el| format!("0x{el:04x}")).collect();
      fail(
        name,
        format!(
          "expected App({}) for the encoder-stream backlog, got {other:?}",
          want.join(" or ")
        ),
      )
    }
  }
}

/// **Oversized heads**: a hand-encoded request with a ~20 KiB QPACK field section. The framework
/// answers 431 on the request stream (RFC 9114 §4.2.2), not a connection kill.
async fn oversized_heads(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "oversized_heads";
  let (ep, conn) = match abuser_conn(p, target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let result = async {
    let mut control = conn.open_uni().await.map_err(|err| format!("open control: {err}"))?;
    control.write_all(&raw::h3_control_stream()).await.map_err(|err| format!("control: {err}"))?;
    let mut enc = conn.open_uni().await.map_err(|err| format!("open enc: {err}"))?;
    enc.write_all(&[raw::H3_QPACK_ENCODER]).await.map_err(|err| format!("enc: {err}"))?;
    let mut dec = conn.open_uni().await.map_err(|err| format!("open dec: {err}"))?;
    dec.write_all(&[raw::H3_QPACK_DECODER]).await.map_err(|err| format!("dec: {err}"))?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|err| format!("open bi: {err}"))?;
    send
      .write_all(&raw::h3_oversized_headers_frame(&p.server_name, &p.routes.ok_path, 20 * 1024))
      .await
      .map_err(|err| format!("write: {err}"))?;
    send.finish().map_err(|err| format!("finish: {err}"))?;
    let bytes = recv.read_to_end(64 * 1024).await.map_err(|err| format!("read: {err}"))?;
    let _ = (&control, &enc, &dec);
    Ok::<Vec<u8>, String>(bytes)
  }
  .await;
  let still_open = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  match result {
    Ok(bytes) => match parse_431_headers(&bytes) {
      Ok(()) if still_open => pass(
        name,
        format!(
          "431 HEADERS frame parsed on the request stream, connection open ({} bytes)",
          bytes.len()
        ),
      ),
      Ok(()) => fail(name, "431 parsed but the connection was closed".into()),
      Err(why) => fail(
        name,
        format!("want a parsed 431 HEADERS frame, connection open: {why} (open={still_open})"),
      ),
    },
    Err(err) => fail(name, format!("expected a 431 answer, not an error: {err}")),
  }
}

/// Parses an HTTP/3 HEADERS frame and confirms it carries `:status: 431`: the frame type
/// (0x01), its length, the QPACK encoded-field-section prefix (required insert count, delta base),
/// then the `:status` field line's value `431`.
fn parse_431_headers(bytes: &[u8]) -> Result<(), String> {
  let (ty, a) = raw::read_varint(bytes).ok_or("truncated frame type")?;
  if ty != 0x01 {
    return Err(format!("frame type 0x{ty:x}, not HEADERS (0x01)"));
  }
  let (len, b) = raw::read_varint(bytes.get(a..).ok_or("truncated length")?).ok_or("bad length")?;
  let start = a + b;
  let section = bytes.get(start..start + len as usize).ok_or("length past end")?;
  // QPACK field-section prefix: Required Insert Count and Delta Base (RFC 9204 section 4.5.1).
  let (_ric, c) = raw::read_varint(section).ok_or("no required insert count")?;
  let (_base, d) =
    raw::read_varint(section.get(c..).ok_or("no delta base")?).ok_or("bad delta base")?;
  let fields = section.get(c + d..).ok_or("no field lines")?;
  // The QPACK static table has no 431, so :status 431 is a literal field line whose value is
  // "431", either raw or Huffman-coded (a string whose first byte has the H bit and length 3).
  let huffman = fields.iter().enumerate().any(|(at, byte)| {
    byte & 0x80 != 0
      && byte & 0x7f == 3
      && fields
        .get(at + 1..at + 4)
        .is_some_and(|el| crate::h2codec::huffman_digits(el).as_deref() == Some("431"))
  });
  if huffman || fields.windows(3).any(|w| w == b"431") {
    Ok(())
  } else {
    Err("no :status 431 in the field section".into())
  }
}

/// **Slow reader**: ask for the large file and read it slowly, verifying the bytes (`i % 251`) when
/// the route serves the pattern file. The server is held by its own in-flight cap and flow control.
async fn slow_reader(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "slow_reader";
  let (ep, conn) = match abuser_conn(p, target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let big_uri = p.big_uri();
  let pattern = p.routes.big_pattern;
  let result = async {
    use bytes::Buf as _;
    let h3c = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut sr) = h3::client::new(h3c).await.map_err(|err| format!("h3: {err}"))?;
    let drive = tokio::spawn(async move {
      let _ = driver.wait_idle().await;
    });
    let req = http::Request::builder()
      .method("GET")
      .uri(&big_uri)
      .body(())
      .map_err(|err| format!("request: {err}"))?;
    let mut stream = sr.send_request(req).await.map_err(|err| format!("send: {err}"))?;
    stream.finish().await.map_err(|err| format!("finish: {err}"))?;
    let _resp = stream.recv_response().await.map_err(|err| format!("response: {err}"))?;
    let (mut off, mut checked) = (0usize, 0usize);
    for _ in 0..20 {
      match tokio::time::timeout(Duration::from_secs(2), stream.recv_data()).await {
        Ok(Ok(Some(mut chunk))) => {
          while chunk.has_remaining() {
            let b = chunk.chunk();
            for (i, byte) in b.iter().enumerate().filter(|_| pattern) {
              if *byte != ((off + i) % 251) as u8 {
                return Err(format!("byte {} is {} not {}", off + i, byte, (off + i) % 251));
              }
            }
            off += b.len();
            checked += b.len();
            let step = b.len();
            chunk.advance(step);
          }
        }
        Ok(Ok(None)) => break,
        _ => break,
      }
      tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drive.abort();
    Ok::<usize, String>(checked)
  }
  .await;
  let alive = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  match result {
    Ok(n) if n > 0 && alive => {
      pass(name, format!("read {n} verified bytes slowly, connection held"))
    }
    Ok(n) => fail(name, format!("read {n} bytes, alive={alive}")),
    Err(err) => fail(name, err),
  }
}

/// **Never-read**: 20 concurrent requests for the large file on one connection,
/// whose responses are never read. The bytes the server sends are bounded by the client's windows,
/// and the server stays bounded (the RSS gate).
async fn never_read(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "never_read";
  let (ep, conn) = match abuser_conn(p, target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let big_uri = p.big_uri();
  let result = async {
    let h3c = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut sr) = h3::client::new(h3c).await.map_err(|err| format!("h3: {err}"))?;
    let drive = tokio::spawn(async move {
      let _ = driver.wait_idle().await;
    });
    let mut held = Vec::new();
    for _ in 0..20u32 {
      let req = http::Request::builder()
        .method("GET")
        .uri(&big_uri)
        .body(())
        .map_err(|err| format!("request: {err}"))?;
      match sr.send_request(req).await {
        Ok(mut stream) => {
          let _ = stream.finish().await;
          held.push(stream);
        }
        Err(_) => break,
      }
    }
    // Held for 6 s, or half the server's idle timeout if that is shorter: a connection that goes
    // quiet for the idle timeout may rightly be closed.
    tokio::time::sleep((p.idle_timeout / 2).min(Duration::from_secs(6))).await;
    let n = held.len();
    drive.abort();
    Ok::<usize, String>(n)
  }
  .await;
  let alive = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  match result {
    Ok(n) if alive => {
      pass(name, format!("{n} unread large responses held; server bounded, connection alive"))
    }
    Ok(_) => fail(
      name,
      format!("connection closed while holding unread responses: {:?}", conn.close_reason()),
    ),
    Err(err) => fail(name, err),
  }
}

/// **Rebinding (well-behaved migrant)**: a client that keeps requesting while its
/// local port, then its source address (127.0.0.1 → 127.0.0.2), change.
async fn rebind(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "rebind";
  if !loopback_v4(target) {
    return skipped(name, "needs an IPv4 loopback target");
  }
  let cfg = client::client_config(Some(Duration::from_secs(2)), Duration::from_secs(30));
  let ep = match client::endpoint("127.0.0.1:0".parse().unwrap(), cfg) {
    Ok(ep) => ep,
    Err(err) => return fail(name, format!("endpoint: {err}")),
  };
  let conn = match client::connect(&ep, target, &p.server_name).await {
    Ok(conn) => conn,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let mut session = match client::H3Session::open(conn.clone(), &p.server_name).await {
    Ok(s) => s,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("h3 session: {err}"));
    }
  };
  let mut steps = Vec::new();
  steps.push(("before", session.get(&p.routes.ok_path).await.map(|r| r.status)));
  let port_rebind = UdpSocket::bind("127.0.0.1:0").and_then(|s| ep.rebind(s)).is_ok();
  tokio::time::sleep(Duration::from_millis(200)).await;
  steps.push(("after_port", session.get(&p.routes.ok_path).await.map(|r| r.status)));
  let addr_rebind = UdpSocket::bind("127.0.0.2:0").and_then(|s| ep.rebind(s)).is_ok();
  tokio::time::sleep(Duration::from_millis(200)).await;
  steps.push(("after_addr", session.get(&p.routes.ok_path).await.map(|r| r.status)));
  drop(session);
  ep.close(client::H3_NO_ERROR, b"");
  let ok = steps.iter().all(|(_, r)| matches!(r, Ok(200)));
  let detail = format!("port_rebind={port_rebind}, addr_rebind={addr_rebind}, {steps:?}");
  if ok {
    pass(name, format!("answered across both rebinds: {detail}"))
  } else {
    fail(name, format!("a GET failed after a rebind: {detail}"))
  }
}

/// Builds a quinn endpoint over a [`FlapSocket`] of two loopback sockets (127.0.0.1 and 127.0.0.2),
/// returning the endpoint and the socket so its per-address byte counters can be read.
fn flap_endpoint() -> Result<(Endpoint, Arc<FlapSocket>), String> {
  let runtime = Arc::new(TokioRuntime);
  let mk = |addr: &str| -> Result<Arc<dyn AsyncUdpSocket>, String> {
    let sock = UdpSocket::bind(addr).map_err(|err| format!("bind {addr}: {err}"))?;
    sock.set_nonblocking(true).map_err(|err| err.to_string())?;
    runtime.wrap_udp_socket(sock).map_err(|err| err.to_string())
  };
  let a = mk("127.0.0.1:0")?;
  let b = mk("127.0.0.2:0")?;
  let flap = FlapSocket::new(vec![a, b]);
  let mut ep = Endpoint::new_with_abstract_socket(
    EndpointConfig::default(),
    None,
    flap.clone() as Arc<dyn AsyncUdpSocket>,
    runtime,
  )
  .map_err(|err| format!("endpoint: {err}"))?;
  ep.set_default_client_config(client::client_config(
    Some(Duration::from_millis(300)),
    Duration::from_secs(30),
  ));
  Ok((ep, flap))
}

/// **Migration flapper**: a confirmed connection whose source address
/// alternates on *every datagram* (a [`FlapSocket`] over two loopback addresses). Bytes in and out
/// are counted per address, so the pass rule asserts the server sends at most 3× to each address
/// what that address sent (RFC 9000 anti-amplification, section 8); the server CPU over the window
/// is measured in ns on the monitored (one-worker) server with its steady client running, and the
/// close code/time is recorded. The concurrent steady client's no-stall check is `steady_idle`.
async fn flapper(p: &H3Policy, target: SocketAddr, pid: Option<u32>) -> ScenarioResult {
  let name = "flapper";
  if !loopback_v4(target) {
    return skipped(name, "needs an IPv4 loopback target");
  }
  let (ep, flap) = match flap_endpoint() {
    Ok(elem) => elem,
    Err(err) => return fail(name, err),
  };
  let conn = match client::connect(&ep, target, &p.server_name).await {
    Ok(conn) => conn,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let mut session = match client::H3Session::open(conn.clone(), &p.server_name).await {
    Ok(s) => s,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("h3 session: {err}"));
    }
  };
  if session.get(&p.routes.ok_path).await.is_err() {
    drop(session);
    ep.close(client::H3_NO_ERROR, b"");
    return fail(name, "could not confirm the connection before flapping".into());
  }
  // Now turn on per-datagram flapping and drive requests as fast as they go for ~6 s.
  flap.flap_handle().store(true, std::sync::atomic::Ordering::Relaxed);
  let watch = conn.clone();
  let closer = tokio::spawn(async move { client::closed_as(&watch.closed().await) });
  let cpu0 = pid.map(cpu_ns).unwrap_or(0);
  let begin = Instant::now();
  let mut flips = 0u32;
  while begin.elapsed() < Duration::from_secs(6) && conn.close_reason().is_none() {
    let _ = tokio::time::timeout(Duration::from_millis(150), session.get(&p.routes.ok_path)).await;
    flips = flips.wrapping_add(1);
  }
  let wall_ms = begin.elapsed().as_millis() as u64;
  let cpu_ms = (pid.map(cpu_ns).unwrap_or(0).saturating_sub(cpu0)) / 1_000_000;
  let alive_at_end = conn.close_reason().is_none();
  // The frames the client sent, per type: the server's 0x0107 sites are the PING, PATH_CHALLENGE
  // and NEW_CONNECTION_ID budgets and the stream reset budget, so these attribute the close.
  let tx = conn.stats().frame_tx;
  let frames_tx = format!(
    "client tx ping={} path_challenge={} new_cid={} reset_stream={} stop_sending={}",
    tx.ping, tx.path_challenge, tx.new_connection_id, tx.reset_stream, tx.stop_sending
  );
  drop(session);
  ep.close(client::H3_NO_ERROR, b"");
  let close = tokio::time::timeout(Duration::from_secs(2), closer).await.ok().and_then(|r| r.ok());
  let (out0, in0, out1, in1) =
    (flap.bytes_out(0), flap.bytes_in(0), flap.bytes_out(1), flap.bytes_in(1));
  // Anti-amplification: the server must not send more than 3× to an address than it received from
  // it (plus one datagram of slack for the first challenge). Checked per source address.
  let ok0 = in0 <= out0.saturating_mul(3).saturating_add(1500);
  let ok1 = in1 <= out1.saturating_mul(3).saturating_add(1500);
  let server_ok =
    alive_at_end || matches!(close, Some(Closed::App(_)) | Some(Closed::Transport(_)));
  let detail = format!(
    "{flips} req over {wall_ms} ms, server CPU +{cpu_ms} ms, close={close:?}; addr0 out={out0} in={in0}, addr1 out={out1} in={in1} (≤3× each: {ok0}/{ok1}); {frames_tx}"
  );
  if server_ok && ok0 && ok1 {
    pass(name, detail)
  } else if !server_ok {
    fail(name, format!("server did not survive flapping: {detail}"))
  } else {
    fail(name, format!("amplification over 3× on an address: {detail}"))
  }
}

/// **Raw per-datagram flapper with no PING** on the one-worker monitored
/// server. [`OneRttClient::raw_flap`] sends one MAX_DATA packet per datagram, alternating between
/// the validated handshake address and a second, perpetually-unvalidated address — and, unlike
/// quinn, it sends no PING, so the PING budget cannot be what bounds it. Server CPU per flip is
/// measured in ns and gated; the amplification bound is asserted on the unvalidated address. If the
/// per-flip CPU is unbounded that is a finding (migration flapping costs the server unbounded
/// work), and the run fails.
async fn raw_flapper(p: &H3Policy, target: SocketAddr, pid: Option<u32>) -> ScenarioResult {
  let name = "raw_flapper";
  if !loopback_v4(target) {
    return skipped(name, "needs an IPv4 loopback target");
  }
  let mut client = match OneRttClient::connect(target, &p.server_name).await {
    Ok(client) => client,
    Err(err) => return fail(name, format!("handshake: {err}")),
  };
  let alt = match tokio::net::UdpSocket::bind("127.0.0.2:0").await {
    Ok(sock) => match sock.connect(target).await {
      Ok(()) => sock,
      Err(err) => return fail(name, format!("alt connect: {err}")),
    },
    Err(err) => return fail(name, format!("alt bind: {err}")),
  };
  // A no-flap baseline of the same length so the per-flip figure is over the idle worker's rate.
  let idle0 = pid.map(cpu_ns).unwrap_or(0);
  tokio::time::sleep(Duration::from_secs(5)).await;
  let baseline_ns = pid.map(cpu_ns).unwrap_or(0).saturating_sub(idle0);
  let cpu0 = pid.map(cpu_ns).unwrap_or(0);
  let res = client.raw_flap(&alt, Duration::from_secs(5)).await;
  let cpu_ns_total = pid.map(cpu_ns).unwrap_or(0).saturating_sub(cpu0);
  let per_flip_ns =
    cpu_ns_total.saturating_sub(baseline_ns).checked_div(res.flips).unwrap_or(u64::MAX);
  // The bound: a flip (one source-address change) must cost no more than 100 µs of server CPU over
  // the idle baseline. Above this, the O(ring) retag plus challenge per flip is unbounded work.
  const PER_FLIP_BOUND_NS: u64 = 100_000;
  // Anti-amplification on the unvalidated address (socket 1), per its traffic.
  let ok_amp = res.bytes_in[1] <= res.bytes_out[1].saturating_mul(3).saturating_add(1500);
  let bounded = per_flip_ns <= PER_FLIP_BOUND_NS;
  let detail = format!(
    "{} flips, no PING; CPU {per_flip_ns} ns/flip (idle baseline {baseline_ns} ns, flap {cpu_ns_total} ns); addr0 out={} in={}, addr1 out={} in={} (unvalidated ≤3×: {ok_amp}); close={:?}",
    res.flips, res.bytes_out[0], res.bytes_in[0], res.bytes_out[1], res.bytes_in[1], res.closed
  );
  if bounded && ok_amp {
    pass(name, detail)
  } else if !bounded {
    fail(
      name,
      format!(
        "FINDING: per-flip server CPU over {PER_FLIP_BOUND_NS} ns (unbounded migration-flap work): {detail}"
      ),
    )
  } else {
    fail(name, format!("amplification over 3× on the unvalidated address: {detail}"))
  }
}

/// **Never-ACK slow reader**: request the large file, then black-hole the
/// client's transmit (a [`FlapSocket`] with one inner socket and the blackhole flag set) so no ACK
/// ever leaves. The server is then bounded by its own in-flight cap / sent ring and closes on its
/// idle timeout (the RSS gate covers its memory). Pass rule: the connection closes (idle/reset)
/// and no body completed.
async fn never_ack(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "never_ack";
  if target.is_ipv6() {
    return skipped(name, "IPv4 only");
  }
  let runtime = Arc::new(TokioRuntime);
  let inner = match UdpSocket::bind(client::local_bind(target, 1)).and_then(|s| {
    s.set_nonblocking(true)?;
    runtime.wrap_udp_socket(s)
  }) {
    Ok(sock) => sock,
    Err(err) => return fail(name, format!("socket: {err}")),
  };
  let flap = FlapSocket::new(vec![inner]);
  let blackhole = flap.blackhole_handle();
  let mut ep = match Endpoint::new_with_abstract_socket(
    EndpointConfig::default(),
    None,
    flap.clone() as Arc<dyn AsyncUdpSocket>,
    runtime,
  ) {
    Ok(ep) => ep,
    Err(err) => return fail(name, format!("endpoint: {err}")),
  };
  ep.set_default_client_config(client::client_config(None, Duration::from_secs(8)));
  let conn = match client::connect(&ep, target, &p.server_name).await {
    Ok(conn) => conn,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  // Start the request, then cut the client's transmit so no ACK leaves.
  let big_uri = p.big_uri();
  let result = async {
    let h3c = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut sr) = h3::client::new(h3c).await.map_err(|err| format!("h3: {err}"))?;
    let drive = tokio::spawn(async move {
      let _ = driver.wait_idle().await;
    });
    let req = http::Request::builder()
      .method("GET")
      .uri(&big_uri)
      .body(())
      .map_err(|err| format!("request: {err}"))?;
    let mut stream = sr.send_request(req).await.map_err(|err| format!("send: {err}"))?;
    stream.finish().await.map_err(|err| format!("finish: {err}"))?;
    let _ = stream.recv_response().await;
    // Black-hole the transmit: from here the client ACKs nothing.
    blackhole.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok::<_, String>(drive)
  }
  .await;
  let drive = match result {
    Ok(drive) => drive,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("request setup: {err}"));
    }
  };
  // Sample the received-byte counter: after the blackhole the server retransmits a little (its
  // in-flight cap / PTO), then goes quiet. This bounds what it sent post-blackhole and shows the
  // close is an idle close, not continued sending.
  let after_blackhole = flap.bytes_in(0);
  tokio::time::sleep(Duration::from_secs(2)).await;
  let quiet_a = flap.bytes_in(0);
  tokio::time::sleep(Duration::from_secs(2)).await;
  let quiet_b = flap.bytes_in(0);
  let post_blackhole_bytes = quiet_b.saturating_sub(after_blackhole);
  let went_quiet = quiet_b.saturating_sub(quiet_a) < 4096;
  // The server is held by its own in-flight cap; it must close on idle (negotiated 8 s) within ~12 s.
  let closed = client::wait_closed(&conn, Duration::from_secs(12)).await;
  drive.abort();
  ep.close(client::H3_NO_ERROR, b"");
  let detail = format!(
    "transmit black-holed; server sent {post_blackhole_bytes} B after (bounded by in-flight cap), went quiet={went_quiet}, close={closed:?}"
  );
  match closed {
    Closed::TimedOutOrReset | Closed::App(_) | Closed::Transport(_) if went_quiet => {
      pass(name, detail)
    }
    _ => fail(name, format!("want a quiet idle close: {detail}")),
  }
}

/// What filling the cap took: connects that failed (by error), and retries made with fresh connects.
#[derive(Debug, Default)]
pub struct FillStats {
  /// Failed connects, by their error text (a timeout is "timeout").
  pub failures: std::collections::BTreeMap<String, u32>,
  /// Fresh connects made to replace failed ones.
  pub retries: u32,
}

/// Opens exactly `want` idle keep-alive connections to `target` over 16 endpoints, with at most
/// `conc` handshakes under way at once (`SOAK_FILL_CONC`, default 32: below rimu-ws's
/// `retry_above_half_open` 64, so the fill neither draws Retries nor reaches the
/// `max_half_open_per_worker` drop). A failed connect is retried with a fresh one, each failure
/// counted by its error, until `want` are held or 4 × `want` attempts are spent. Returns the held
/// connections, their endpoints, and the stats.
async fn fill_cap(
  p: &H3Policy,
  target: SocketAddr,
  want: usize,
) -> (Vec<quinn::Connection>, Vec<quinn::Endpoint>, FillStats) {
  let conc: usize =
    std::env::var("SOAK_FILL_CONC").ok().and_then(|el| el.parse().ok()).unwrap_or(32).max(1);
  let cfg = client::client_config(Some(Duration::from_secs(10)), Duration::from_secs(30));
  let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let eps: Vec<quinn::Endpoint> =
    (0..16).filter_map(|_| client::endpoint(bind, cfg.clone()).ok()).collect();
  let mut stats = FillStats::default();
  let mut held: Vec<quinn::Connection> = Vec::new();
  if eps.is_empty() {
    stats.failures.insert("no endpoints".into(), 1);
    return (held, eps, stats);
  }
  let sem = Arc::new(tokio::sync::Semaphore::new(conc));
  let mut attempts = 0usize;
  while held.len() < want && attempts < want * 4 {
    let batch = want - held.len();
    let mut tasks = Vec::with_capacity(batch);
    for i in 0..batch {
      let ep = eps[(attempts + i) % eps.len()].clone();
      let sem = sem.clone();
      let server_name = p.server_name.clone();
      tasks.push(tokio::spawn(async move {
        let _permit = sem.acquire_owned().await;
        match tokio::time::timeout(
          Duration::from_secs(10),
          client::connect(&ep, target, &server_name),
        )
        .await
        {
          Ok(Ok(conn)) => Ok(conn),
          Ok(Err(why)) => Err(why),
          Err(_) => Err("timeout".to_string()),
        }
      }));
    }
    if attempts > 0 {
      stats.retries = stats.retries.wrapping_add(batch as u32);
    }
    attempts += batch;
    for task in tasks {
      match task.await {
        Ok(Ok(conn)) => held.push(conn),
        Ok(Err(why)) => *stats.failures.entry(why).or_insert(0) += 1,
        Err(_) => *stats.failures.entry("join".into()).or_insert(0) += 1,
      }
    }
  }
  (held, eps, stats)
}

/// `GET` of the stats route (`H3Policy::stats_path`: the server's own report, such as its worker
/// count and per-worker open connections) over an already-open connection, as text; one H3
/// session on it, bounded at 5 s. `None` without the route.
async fn stats_on(p: &H3Policy, conn: &quinn::Connection) -> Option<String> {
  let path = p.stats_path.as_deref()?;
  let get = client::h3_get(conn.clone(), &p.server_name, path);
  let reply = tokio::time::timeout(Duration::from_secs(5), get).await.ok()?.ok()?;
  String::from_utf8(reply.body).ok()
}

/// The server's net live heap bytes as the memory route (`H3Policy::mem_path`) reports them, as a
/// decimal number, over an already-open connection (one H3 session on it, bounded at 5 s). `None`
/// without the route.
async fn live_bytes_on(p: &H3Policy, conn: &quinn::Connection) -> Option<i64> {
  let path = p.mem_path.as_deref()?;
  let get = client::h3_get(conn.clone(), &p.server_name, path);
  let reply = tokio::time::timeout(Duration::from_secs(5), get).await.ok()?.ok()?;
  core::str::from_utf8(&reply.body).ok()?.trim().parse::<i64>().ok()
}

/// [`live_bytes_on`] over a fresh connection.
async fn server_live_bytes(p: &H3Policy, target: SocketAddr) -> Option<i64> {
  let mem = p.mem_path.as_deref()?;
  let cfg = client::client_config(None, Duration::from_secs(5));
  let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let ep = client::endpoint(bind, cfg).ok()?;
  let conn = client::connect(&ep, target, &p.server_name).await.ok()?;
  let reply = client::h3_get(conn, &p.server_name, mem).await.ok()?;
  ep.close(client::H3_NO_ERROR, b"");
  core::str::from_utf8(&reply.body).ok()?.trim().parse::<i64>().ok()
}

/// Probes the per-worker connection cap with one extra connection. Returns how it
/// ended: `Ok(())` if it connected (the cap did not hold), or `Err(text)` with the connect error —
/// the documented silent drop at the cap shows as a handshake timeout.
async fn probe_cap(
  p: &H3Policy,
  target: SocketAddr,
  bind: SocketAddr,
  cfg: quinn::ClientConfig,
) -> Result<(), String> {
  let ep = client::endpoint(bind, cfg).map_err(|err| format!("endpoint: {err}"))?;
  let r =
    tokio::time::timeout(Duration::from_secs(5), client::connect(&ep, target, &p.server_name))
      .await;
  ep.close(client::H3_NO_ERROR, b"");
  match r {
    Ok(Ok(_)) => Ok(()),
    Ok(Err(why)) => Err(why),
    Err(_) => Err("timeout (5 s)".into()),
  }
}

/// **Idle connections up to the per-worker cap** (`H3Policy::conns_per_worker`, 4,096 for rimu-ws):
/// open a one-worker server's whole allowance as idle, kept-alive connections, then one more. Pass
/// rule: exactly the cap held, twice (a cold and a warm fill), the extra one times out (the silent
/// drop at the cap), the server stays alive and a held connection still answers. The RSS per
/// connection is reported, and, with a memory route, the server's live heap per connection; a
/// figure above 8 KiB is reported as a finding.
pub async fn idle_connections(p: &H3Policy, target: SocketAddr, pid: u32) -> ScenarioResult {
  let name = "idle_cap";
  let cap = p.conns_per_worker as usize;
  let rss_before = rss_kib(pid);
  let live_before = server_live_bytes(p, target).await;
  let (held, eps, fill1) = fill_cap(p, target, cap).await;
  let opened = held.len();
  tokio::time::sleep(Duration::from_secs(2)).await;
  let rss_fill = rss_kib(pid);
  // Held connections the client still counts but which already closed (with their reasons).
  let mut closed_before: std::collections::BTreeMap<String, u32> =
    std::collections::BTreeMap::new();
  for conn in &held {
    if let Some(why) = conn.close_reason() {
      *closed_before.entry(why.to_string()).or_insert(0) += 1;
    }
  }
  // The 4,097th, probed first, before any request touches a held connection: a GET on a held
  // connection opens an HTTP/3 session whose drop ends that connection (the server closes it with
  // H3_CLOSED_CRITICAL_STREAM), which would free a slot and let the probe in. The documented
  // behaviour at the cap is a silent drop: the probe must fail with a handshake timeout.
  let extra_cfg = client::client_config(None, Duration::from_secs(4));
  let extra_bind: SocketAddr =
    if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let extra = probe_cap(p, target, extra_bind, extra_cfg).await;
  let extra_timed_out =
    matches!(&extra, Err(why) if why.contains("timed out") || why.starts_with("timeout"));
  // Then the server's own count (ground truth) and live heap, each over its own held connection.
  let stats_probe = match held.get(2) {
    Some(conn) => stats_on(p, conn).await,
    None => None,
  };
  let live_fill = match held.get(1) {
    Some(conn) => live_bytes_on(p, conn).await,
    None => None,
  };
  let server_alive = rss_kib(pid) > 0;
  let held_answers = match held.first() {
    Some(conn) => {
      matches!(
        tokio::time::timeout(
          Duration::from_secs(5),
          client::h3_get(conn.clone(), &p.server_name, &p.routes.ok_path)
        )
        .await
        .map(|r| r.map(|el| el.status)),
        Ok(Ok(200))
      )
    }
    None => false,
  };

  // Idle trim: drop the whole batch, let the worker go idle, measure the resident and live baseline.
  for ep in &eps {
    ep.close(client::H3_NO_ERROR, b"");
  }
  drop(held);
  drop(eps);
  tokio::time::sleep(Duration::from_secs(5)).await;
  let rss_trim = rss_kib(pid);
  let live_trim = server_live_bytes(p, target).await;

  // A second, warm batch of 4,096.
  let (held2, eps2, fill2) = fill_cap(p, target, cap).await;
  let opened2 = held2.len();
  tokio::time::sleep(Duration::from_secs(2)).await;
  let rss_warm = rss_kib(pid);
  let live_warm = match held2.get(1) {
    Some(conn) => live_bytes_on(p, conn).await,
    None => None,
  };
  for ep in &eps2 {
    ep.close(client::H3_NO_ERROR, b"");
  }
  drop(held2);

  // Server-measured net-live heap per connection: the first-fill delta is the authoritative figure
  //; the warm batch cross-checks it.
  let per_conn_live_b = match (live_before, live_fill) {
    (Some(b), Some(f)) if opened > 0 => Some((f - b) / opened as i64),
    _ => None,
  };
  let per_conn_warm_b = match (live_trim, live_warm) {
    (Some(t), Some(w)) if opened2 > 0 => Some((w - t) / opened2 as i64),
    _ => None,
  };
  let rss_per_fill =
    if opened > 0 { rss_fill.saturating_sub(rss_before) / opened as u64 } else { 0 };

  let live_detail = match (per_conn_live_b, per_conn_warm_b) {
    (Some(a), Some(b)) => format!("LIVE heap/conn {a} B (fill), {b} B (warm)"),
    _ => "LIVE heap/conn unavailable (no memory route)".into(),
  };
  let detail = format!(
    "fill {opened}/{cap} RSS {rss_before}->{rss_fill} KiB (~{rss_per_fill} KiB/conn RSS); trim RSS {rss_trim} KiB; warm {opened2}/{cap} ->{rss_warm} KiB; server live bytes {live_before:?}->{live_fill:?} trim {live_trim:?} warm {live_warm:?}; {live_detail}; extra (cap + 1) {extra:?}, alive={server_alive}, held answers={held_answers}; held closed before probe {closed_before:?}; server stats after the probe {stats_probe:?}; fill1 {fill1:?}; fill2 {fill2:?}"
  );
  // Exactly the cap held in both fills (no tolerance), the extra connection refused (the silent
  // drop at the cap, as a handshake timeout, on the first attempt), the server alive and a held
  // connection still answering.
  let cap_ok = opened == cap && opened2 == cap && extra_timed_out && server_alive && held_answers;
  // The live figure is a FINDING if above 8 KiB; it does not fail the cap check.
  let over = per_conn_live_b.is_some_and(|b| b > 8192);
  if cap_ok && over {
    pass(
      name,
      format!(
        "cap held and enforced; LIVE heap/conn > 8 KiB — FINDING (no layout change this round): {detail}"
      ),
    )
  } else if cap_ok {
    pass(name, detail)
  } else {
    fail(
      name,
      format!(
        "want exactly {cap} held twice + the first extra refused + alive + held answers: {detail}"
      ),
    )
  }
}

/// The 1-RTT frame floods, each driven by the raw [`OneRttClient`]: a real TLS handshake, then
/// abusive frames a conforming client never sends. Each asserts the close code for its limit (see
/// each entry), and only the selected ones run. They run on the main server, whose handshake load
/// is low, so no Retry intercepts the raw Initial.
pub async fn onertt_floods(p: &H3Policy, target: SocketAddr) -> Vec<ScenarioResult> {
  let excessive = Close::App(p.excessive_load);
  let mut floods: Vec<(&str, Close, Vec<Vec<u8>>)> = Vec::new();

  // PING flood → excessive load (rimu-ws: `ping_budget`, 64 plus 2 per RTT, capped at 16,384 a
  // second); 40 packets of 1,200 PING frames is ~48,000 in well under a second.
  floods.push(("onertt_ping_flood", excessive, (0..40u32).map(|_| frames::pings(1200)).collect()));

  // PATH_CHALLENGE flood → excessive load (rimu-ws: `path_challenge_budget` 16). 64 in one packet.
  let mut path = Vec::new();
  for i in 0..64u8 {
    path.extend_from_slice(&frames::path_challenge([i; 8]));
  }
  floods.push(("onertt_path_challenge_flood", excessive, vec![path]));

  // NEW_CONNECTION_ID flood → excessive load (rimu-ws: `new_connection_id_budget` 16). 20 frames,
  // each retiring all lower sequence numbers (retire_prior_to = seq), so the active count stays at
  // 1 — under the server's advertised active_connection_id_limit — and the per-second budget is
  // what trips, rather than CONNECTION_ID_LIMIT_ERROR. One packet.
  let mut ncid = Vec::new();
  for seq in 1..=20u64 {
    ncid.extend_from_slice(&frames::new_connection_id(seq, seq, [seq as u8; 8], [seq as u8; 16]));
  }
  floods.push(("onertt_new_cid_flood", excessive, vec![ncid]));

  // RETIRE_CONNECTION_ID of sequence 0, sent in a packet addressed to that very connection ID →
  // PROTOCOL_VIOLATION (Transport 0x0a), which RFC 9000 section 19.16 allows.
  floods.push(("onertt_retire_cid", Close::Transport(0x0a), vec![frames::retire_connection_id(0)]));

  // An empty 1-RTT packet (no frames) → PROTOCOL_VIOLATION (Transport 0x0a), RFC 9000 section 12.4.
  floods.push(("onertt_empty_packet", Close::Transport(0x0a), vec![Vec::new()]));

  // Out-of-order STREAM gaps past the server's range limit (rimu-ws: `max_out_of_order_ranges`
  // 256) → PROTOCOL_VIOLATION (Transport 0x0a). 300 one-byte frames at disjoint offsets 2,4,6,…
  // leave a gap before each, so each is a separate range. Packed ~180 per datagram.
  let mut gaps: Vec<Vec<u8>> = Vec::new();
  let mut payload = Vec::new();
  for k in 1..=300u64 {
    payload.extend_from_slice(&frames::stream(0, k * 2, b"x"));
    if k % 180 == 0 {
      gaps.push(std::mem::take(&mut payload));
    }
  }
  if !payload.is_empty() {
    gaps.push(payload);
  }
  floods.push(("onertt_stream_gaps", Close::Transport(0x0a), gaps));

  // STREAM data past the per-stream flow-control window → FLOW_CONTROL_ERROR (Transport 0x03), RFC
  // 9000 section 4.1. One byte at twice the window (`H3Policy::stream_window`) from offset 0.
  let past = frames::stream(0, p.stream_window.saturating_mul(2), b"x");
  floods.push(("onertt_stream_past_window", Close::Transport(0x03), vec![past]));

  let mut out = Vec::new();
  for (name, expect, packets) in floods {
    if p.wants(name) {
      out.push(one_rtt_flood(p, name, target, expect, packets).await);
    }
  }
  // Empty-frames flood: many PADDING-only 1-RTT packets (each 200 PADDING bytes). PADDING is not
  // ack-eliciting and is ignored, so the server neither closes nor replies. (The single
  // genuinely-empty packet → 0x0a is `onertt_empty_packet` above.)
  if p.wants("onertt_empty_frames_flood") {
    out.push(empty_frames_flood(p, target).await);
  }
  out
}

/// **Empty-frames flood**: 200 PADDING-only 1-RTT packets, then assert the connection is still
/// open (PADDING is ignored, no close, no reply storm).
async fn empty_frames_flood(p: &H3Policy, target: SocketAddr) -> ScenarioResult {
  let name = "onertt_empty_frames_flood";
  if target.is_ipv6() {
    return skipped(name, "IPv4 only");
  }
  let mut client = match OneRttClient::connect(target, &p.server_name).await {
    Ok(client) => client,
    Err(err) => return fail(name, format!("handshake: {err}")),
  };
  for _ in 0..200u32 {
    if client.send_1rtt(&[0x00; 200]).await.is_err() {
      break;
    }
  }
  let close = client.wait_close(Duration::from_millis(500)).await;
  match close {
    Close::None => pass(name, "200 PADDING-only packets: ignored, no close".into()),
    other => {
      fail(name, format!("PADDING-only packets must not close the connection; got {other:?}"))
    }
  }
}

/// Runs one 1-RTT flood: handshake, send every packet in `packets`, then assert the server closes
/// with `expect` within 3 s.
async fn one_rtt_flood(
  p: &H3Policy,
  name: &str,
  target: SocketAddr,
  expect: Close,
  packets: Vec<Vec<u8>>,
) -> ScenarioResult {
  if target.is_ipv6() {
    return skipped(name, "IPv4 only");
  }
  let mut client = match OneRttClient::connect(target, &p.server_name).await {
    Ok(client) => client,
    Err(err) => return fail(name, format!("handshake: {err}")),
  };
  for packet in &packets {
    if let Err(err) = client.send_1rtt(packet).await {
      return fail(name, format!("inject: {err}"));
    }
  }
  let close = client.wait_close(Duration::from_secs(3)).await;
  if close == expect {
    pass(name, format!("closed {close:?} as documented"))
  } else {
    fail(name, format!("expected {expect:?}, got {close:?}"))
  }
}

/// The 10,000-range ACK flood: assert no close and report the server CPU (ns) spent on it.
/// **ACK-range flood**, on the one-worker monitored server so the CPU is
/// attributable. First raise the server's 1-RTT packet numbers with ~1,500 MAX_DATA frames (ack-
/// eliciting, no budget), learn its largest sent PN, then send many ACK packets of 300 valid
/// ranges each (gap 0 / length 0 walking down from that PN, ~600 B, well inside a 1,452-B
/// datagram). Pass: no close (`max_ack_ranges` 256 ignores the rest) and the server CPU per flood
/// packet is bounded by a no-flood window of the same length. A second, fresh connection sends one
/// malformed ACK reaching below PN 0 → FRAME_ENCODING_ERROR (Transport 0x07).
async fn ack_flood(p: &H3Policy, target: SocketAddr, pid: Option<u32>) -> ScenarioResult {
  let name = "onertt_ack_flood";
  if target.is_ipv6() {
    return skipped(name, "IPv4 only");
  }
  let mut client = match OneRttClient::connect(target, &p.server_name).await {
    Ok(client) => client,
    Err(err) => return fail(name, format!("handshake: {err}")),
  };
  // Raise the server's 1-RTT packet number for this connection with MAX_DATA (ack-eliciting, no
  // budget). The server coalesces and paces its ACKs to a one-sided flooder, so a single
  // connection only draws a few hundred ACKs — its packet number does not reach the 514 that 257
  // walking ranges would need. We therefore flood with as many valid ranges as the reached PN
  // allows (gap 0 / length 0 walking down, each ~2 B), which still exercises the ACK-range parser;
  // `max_ack_ranges` (256) ignoring the rest past 256 is additionally pinned by the server's own
  // unit test. The ACK's `largest` stays ≤ the server's next PN (else AckOfUnsentPacket).
  let mut largest = 0u64;
  let raise_begin = Instant::now();
  let mut fc = 1u64 << 20;
  while raise_begin.elapsed() < Duration::from_secs(12) {
    for _ in 0..8u32 {
      fc = fc.wrapping_add(1);
      let _ = client.send_1rtt(&frames::max_data(fc)).await;
    }
    largest = largest.max(client.drain(Duration::from_millis(12)).await.unwrap_or(0));
  }
  largest = largest.max(client.drain(Duration::from_millis(200)).await.unwrap_or(0));
  if largest < 20 {
    return fail(name, format!("could not raise server PNs at all: largest {largest}"));
  }
  // The most valid ranges the reached PN allows (each walks down two), capped at 320 so a high PN
  // (e.g. under concurrent load) still clearly exceeds max_ack_ranges' 256.
  let ranges = (largest.saturating_sub(2) / 2).clamp(1, 320);
  // A no-flood baseline window, then a flood window of the same length, both on the one worker.
  let idle0 = pid.map(cpu_ns).unwrap_or(0);
  tokio::time::sleep(Duration::from_secs(1)).await;
  let baseline_ns = pid.map(cpu_ns).unwrap_or(0).saturating_sub(idle0);
  let cpu0 = pid.map(cpu_ns).unwrap_or(0);
  let begin = Instant::now();
  let mut sent = 0u64;
  while begin.elapsed() < Duration::from_secs(1) {
    // Re-read the largest in case concurrent load raised it, keeping `largest` valid.
    if client.send_1rtt(&frames::ack_ranges(largest, ranges)).await.is_ok() {
      sent = sent.wrapping_add(1);
    }
  }
  let flood_ns = pid.map(cpu_ns).unwrap_or(0).saturating_sub(cpu0);
  let close = client.wait_close(Duration::from_millis(500)).await;
  // The bound: a flood packet must cost no more server CPU than 50 µs over the idle baseline rate.
  let per_pkt_ns = flood_ns.saturating_sub(baseline_ns).checked_div(sent).unwrap_or(u64::MAX);
  const PER_PKT_BOUND_NS: u64 = 50_000;

  // A separate connection for the malformed ACK (below PN 0) → FRAME_ENCODING_ERROR 0x07.
  let malformed = match OneRttClient::connect(target, &p.server_name).await {
    Ok(mut c) => {
      let _ = c.send_1rtt(&frames::ack_below_zero()).await;
      c.wait_close(Duration::from_secs(3)).await
    }
    Err(err) => return fail(name, format!("malformed-ACK handshake: {err}")),
  };

  let over_256 = if ranges > 256 {
    "(> max_ack_ranges 256)"
  } else {
    "(PN-limited ≤ 256; server unit-test covers the >256 ignore)"
  };
  let detail = format!(
    "{sent} × {ranges}-range ACKs {over_256} (largest {largest}): close={close:?}, CPU {per_pkt_ns} ns/pkt (idle baseline {baseline_ns} ns, flood {flood_ns} ns); malformed ACK → {malformed:?}"
  );
  let no_close = matches!(close, Close::None);
  let bounded = per_pkt_ns <= PER_PKT_BOUND_NS;
  let malformed_ok = matches!(malformed, Close::Transport(0x07));
  if no_close && bounded && malformed_ok {
    pass(name, detail)
  } else {
    fail(
      name,
      format!(
        "want no close + CPU ≤ {PER_PKT_BOUND_NS} ns/pkt + malformed Transport(0x07): {detail}"
      ),
    )
  }
}

/// A tiny deterministic xorshift.
pub(crate) fn tiny_rng(seed: u64) -> impl FnMut() -> u64 {
  let mut state = seed | 1;
  move || {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
  }
}
