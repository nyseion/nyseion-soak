//! The QUIC/HTTP/3 soak: a well-behaved steady client (by default 64 connections × 64 streams) on
//! the main server and a small one (4 × 4) on an optional one-worker server, both running for the
//! whole run, beside abusive clients run in sequence. Both servers are watched once a second. Each
//! abuser is bounded by one server limit ([`H3Policy`]); the run passes when the server's RSS stays
//! within 10 % of the plateau the steady client settles at during the warmup, the steady clients
//! never stall, and every abuser is closed with the error it expected or rate-limited.

use crate::{
  monitor::{Monitor, Sample},
  quic::{client, scenario},
  scenario::Routes,
};
use std::{
  net::SocketAddr,
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
  },
  time::Duration,
};
use tokio::time::Instant;

/// The server limits and routes the HTTP/3 scenarios judge the server by. The defaults are rimu-ws's
/// (its HttpArena entry), so a run against another server sets what differs, and leaves out (see
/// [`H3Policy::scenarios`]) the scenarios that test a limit the server does not have.
#[derive(Clone, Debug)]
pub struct H3Policy {
  /// SNI and `:authority`. The certificate is not checked.
  pub server_name: String,
  /// The ok route (`GET` answers 200 with its body) and the large file. The echo route is unused.
  pub routes: Routes,
  /// The application close code for a peer over a rate budget (stream resets, PINGs,
  /// PATH_CHALLENGEs, NEW_CONNECTION_IDs, QPACK encoder backlog): RFC 9114's H3_EXCESSIVE_LOAD,
  /// 0x0107, by default.
  pub excessive_load: u64,
  /// The bidirectional streams the server allows a client at once (`initial_max_streams_bidi`).
  pub max_bidi_streams: u32,
  /// Stateless resets (or any replies) the server may send per second to unknown connection IDs.
  pub stateless_reset_per_sec: u32,
  /// The server's idle timeout. `window_starved` expects its close between 2/3 and 2 times this.
  pub idle_timeout: Duration,
  /// The per-stream receive window the server grants; `onertt_stream_past_window` sends at twice
  /// it.
  pub stream_window: u64,
  /// Connections one worker accepts; `idle_cap` fills them all on the one-worker server.
  pub conns_per_worker: u32,
  /// Whether `initial_flood` must draw a Retry. RFC 9000 makes address validation optional;
  /// without it the scenario still requires that a well-behaved client connects during the flood.
  pub expect_retry: bool,
  /// A route answering the server's live heap bytes as a decimal number, for `idle_cap`'s
  /// per-connection figure.
  pub mem_path: Option<String>,
  /// A route answering the server's own connection report as text, for `idle_cap`'s detail.
  pub stats_path: Option<String>,
  /// The scenarios to run, by name ([`scenario::ALL`]); `None` runs them all.
  pub scenarios: Option<Vec<String>>,
}

impl Default for H3Policy {
  fn default() -> Self {
    Self {
      server_name: "localhost".into(),
      routes: Routes::default(),
      excessive_load: 0x0107,
      max_bidi_streams: 256,
      stateless_reset_per_sec: 100,
      idle_timeout: Duration::from_secs(30),
      stream_window: 1 << 20,
      conns_per_worker: 4096,
      expect_retry: true,
      mem_path: None,
      stats_path: None,
      scenarios: None,
    }
  }
}

impl H3Policy {
  /// Whether scenario `name` is selected.
  pub fn wants(&self, name: &str) -> bool {
    self.scenarios.as_ref().is_none_or(|el| el.iter().any(|el| el == name))
  }

  /// The URI of the large file.
  pub fn big_uri(&self) -> String {
    format!("https://{}{}", self.server_name, self.routes.big_path)
  }
}

/// What the soak runs against and for how long.
#[derive(Clone, Debug)]
pub struct H3Config {
  pub main_addr: SocketAddr,
  pub main_pid: Option<u32>,
  pub idle_addr: Option<SocketAddr>,
  pub idle_pid: Option<u32>,
  pub duration: Duration,
  pub warmup: Duration,
  pub conns: u32,
  pub streams: u32,
  pub main_workers: u32,
  pub memlock_kib: Option<u64>,
  pub policy: H3Policy,
}

/// One JSONL line.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Line {
  pub kind: &'static str,
  pub name: String,
  pub pass: bool,
  pub detail: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub rss_peak_kib: Option<u64>,
}

/// Counters a steady client keeps.
#[derive(Debug, Default)]
pub struct Steady {
  pub ok: AtomicU64,
  pub bad: AtomicU64,
  pub stalls: AtomicU64,
  pub max_rtt_us: AtomicU64,
}

/// A steady request slower than this (or one that fails while the run is live) is a stall of a
/// well-behaved client.
const STALL: Duration = Duration::from_secs(2);

/// One `GET` of the ok route, bounded by [`STALL`]: `Some(true)` = 200 and the ok body,
/// `Some(false)` = a bad answer, `None` = timed out (a stall).
async fn one_request(
  sr: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
  p: &H3Policy,
) -> Option<bool> {
  use bytes::Buf as _;
  let fut = async {
    let uri = format!("https://{}{}", p.server_name, p.routes.ok_path);
    let req = http::Request::builder().method("GET").uri(uri).body(()).ok()?;
    let mut stream = sr.send_request(req).await.ok()?;
    stream.finish().await.ok()?;
    let resp = stream.recv_response().await.ok()?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.ok()? {
      while chunk.has_remaining() {
        let n = chunk.chunk().len();
        body.extend_from_slice(chunk.chunk());
        chunk.advance(n);
      }
    }
    Some(resp.status().as_u16() == 200 && body == p.routes.ok_body.as_bytes())
  };
  match tokio::time::timeout(STALL, fut).await {
    Ok(Some(ok)) => Some(ok),
    Ok(None) => Some(false),
    Err(_) => None,
  }
}

/// Runs a steady client until `stop`: `conns` connections, each driving `streams` concurrent
/// request loops over a shared (cloned) `SendRequest`, each request bounded by [`STALL`].
async fn steady_client(
  p: Arc<H3Policy>,
  addr: SocketAddr,
  conns: u32,
  streams: u32,
  idle: Duration,
  stop: Arc<AtomicBool>,
  counters: Arc<Steady>,
) {
  let cfg = client::client_config(Some(Duration::from_secs(5)), idle);
  let mut tasks = Vec::new();
  for _ in 0..conns {
    let (cfg, stop, counters, p) = (cfg.clone(), stop.clone(), counters.clone(), p.clone());
    tasks.push(tokio::spawn(async move {
      let Ok(ep) = client::endpoint(client::any_bind(addr), cfg) else {
        counters.bad.fetch_add(1, Ordering::Relaxed);
        return;
      };
      while !stop.load(Ordering::Relaxed) {
        let Ok(conn) = client::connect(&ep, addr, &p.server_name).await else {
          counters.bad.fetch_add(1, Ordering::Relaxed);
          if !stop.load(Ordering::Relaxed) {
            counters.stalls.fetch_add(1, Ordering::Relaxed);
          }
          tokio::time::sleep(Duration::from_millis(200)).await;
          continue;
        };
        let h3c = h3_quinn::Connection::new(conn);
        let Ok((mut driver, send_request)) = h3::client::new(h3c).await else {
          counters.bad.fetch_add(1, Ordering::Relaxed);
          tokio::time::sleep(Duration::from_millis(200)).await; // no spin on failure
          continue;
        };
        let drive = tokio::spawn(async move {
          let _ = driver.wait_idle().await;
        });
        let mut stream_tasks = Vec::new();
        for _ in 0..streams {
          let (mut sr, stop, counters, p) =
            (send_request.clone(), stop.clone(), counters.clone(), p.clone());
          stream_tasks.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
              let begin = Instant::now();
              let got = one_request(&mut sr, &p).await;
              counters.max_rtt_us.fetch_max(begin.elapsed().as_micros() as u64, Ordering::Relaxed);
              match got {
                Some(true) => {
                  counters.ok.fetch_add(1, Ordering::Relaxed);
                }
                Some(false) => {
                  counters.bad.fetch_add(1, Ordering::Relaxed);
                  if !stop.load(Ordering::Relaxed) {
                    counters.stalls.fetch_add(1, Ordering::Relaxed);
                  }
                  break;
                }
                None => {
                  if !stop.load(Ordering::Relaxed) {
                    counters.stalls.fetch_add(1, Ordering::Relaxed);
                  }
                  break;
                }
              }
              tokio::time::sleep(Duration::from_millis(25)).await;
            }
          }));
        }
        for task in stream_tasks {
          let _ = task.await;
        }
        drive.abort();
        if stop.load(Ordering::Relaxed) {
          break;
        }
      }
      ep.close(client::H3_NO_ERROR, b"bye");
    }));
  }
  for task in tasks {
    let _ = task.await;
  }
}

/// Primes the server's caches by fetching the large file over `fetches` connections, so the
/// warm-up plateau includes the cache the abuser routes touch. Enough connections that connection
/// ID steering spreads them over all workers.
async fn prime_cache(p: Arc<H3Policy>, addr: SocketAddr, fetches: u32, idle: Duration) {
  let cfg = client::client_config(None, idle);
  let Ok(ep) = client::endpoint(client::any_bind(addr), cfg) else { return };
  let mut tasks = Vec::new();
  for _ in 0..fetches {
    let (ep, p) = (ep.clone(), p.clone());
    tasks.push(tokio::spawn(async move {
      if let Ok(conn) = client::connect(&ep, addr, &p.server_name).await {
        if let Ok(mut session) = client::H3Session::open(conn.clone(), &p.server_name).await {
          let _ = session.get(&p.routes.big_path).await;
        }
        conn.close(client::H3_NO_ERROR, b"");
      }
    }));
  }
  for task in tasks {
    let _ = task.await;
  }
  ep.wait_idle().await;
}

/// Samples the server once a second until `stop`.
async fn sample_loop(pid: Option<u32>, port: u16, stop: Arc<AtomicBool>) -> Vec<Sample> {
  let mut out = Vec::new();
  let Some(pid) = pid else { return out };
  let Ok(mut monitor) = Monitor::new(pid, port) else { return out };
  while !stop.load(Ordering::Relaxed) {
    if let Ok(sample) = monitor.sample() {
      out.push(sample);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  out
}

fn plateau_kib(samples: &[Sample]) -> u64 {
  samples.iter().map(|el| el.rss_kib).max().unwrap_or(0)
}

/// Runs the whole soak, writes each result to `out` as a JSON line, and returns them all.
pub async fn run(cfg: H3Config, out: &mut dyn std::io::Write) -> H3Report {
  let idle_to = Duration::from_secs(30);
  let run_begin = Instant::now();
  let deadline = run_begin + cfg.duration;

  // Prime the static cache on both servers first, so the plateau already holds it.
  let policy = Arc::new(cfg.policy.clone());
  // 32 connections reach all of 4 workers but for a 0.4 % chance.
  prime_cache(policy.clone(), cfg.main_addr, 32, idle_to).await;
  if let Some(idle_addr) = cfg.idle_addr {
    prime_cache(policy.clone(), idle_addr, 4, idle_to).await;
  }

  let main_stop = Arc::new(AtomicBool::new(false));
  let main_counters = Arc::new(Steady::default());
  let main_steady = tokio::spawn(steady_client(
    policy.clone(),
    cfg.main_addr,
    cfg.conns,
    cfg.streams,
    idle_to,
    main_stop.clone(),
    main_counters.clone(),
  ));
  let idle_stop = Arc::new(AtomicBool::new(false));
  let idle_counters = Arc::new(Steady::default());
  let idle_steady = cfg.idle_addr.map(|idle_addr| {
    let (stop, counters) = (idle_stop.clone(), idle_counters.clone());
    tokio::spawn(steady_client(policy.clone(), idle_addr, 4, 4, idle_to, stop, counters))
  });

  // Plateau: warm-up window only.
  let warm_stop = Arc::new(AtomicBool::new(false));
  let warm_main = tokio::spawn(sample_loop(cfg.main_pid, cfg.main_addr.port(), warm_stop.clone()));
  let warm_idle =
    cfg.idle_addr.map(|a| tokio::spawn(sample_loop(cfg.idle_pid, a.port(), warm_stop.clone())));
  tokio::time::sleep(cfg.warmup).await;
  warm_stop.store(true, Ordering::Relaxed);
  let plateau_main = plateau_kib(&warm_main.await.unwrap_or_default());
  let plateau_idle = match warm_idle {
    Some(h) => plateau_kib(&h.await.unwrap_or_default()),
    None => 0,
  };

  // Whole-run sampling for the peak. The idle sampler is stopped before the idle_cap phase, so the
  // idle server's RSS gate reflects the steady client plus the raw floods, not the deliberate
  // spike of a full worker (idle_cap does its own per-connection RSS check).
  let samp_main_stop = Arc::new(AtomicBool::new(false));
  let samp_idle_stop = Arc::new(AtomicBool::new(false));
  let samp_main =
    tokio::spawn(sample_loop(cfg.main_pid, cfg.main_addr.port(), samp_main_stop.clone()));
  let samp_idle = cfg
    .idle_addr
    .map(|a| tokio::spawn(sample_loop(cfg.idle_pid, a.port(), samp_idle_stop.clone())));

  let mut lines = Vec::new();
  lines.push(Line {
    kind: "env",
    name: "run".into(),
    pass: true,
    detail: format!(
      "main_workers={}, memlock={}, plateau_main={plateau_main} KiB, plateau_idle={plateau_idle} KiB",
      cfg.main_workers,
      cfg.memlock_kib.map_or("unlimited".into(), |el| format!("{el} KiB"))
    ),
    rss_peak_kib: None,
  });

  // Abusers (each with its own deadline), while the steady clients run. idle_cap is handled
  // separately below, after the idle sampler is stopped.
  let results = scenario::run_all(&cfg, deadline).await;
  for r in results {
    lines.push(Line {
      kind: "scenario",
      name: r.name,
      pass: r.pass,
      detail: r.detail,
      rss_peak_kib: None,
    });
  }

  // idle_cap phase: stop the idle steady client and its RSS sampler, then run the cap scenario,
  // which does its own per-connection RSS check.
  samp_idle_stop.store(true, Ordering::Relaxed);
  let idle_samples = match samp_idle {
    Some(h) => h.await.unwrap_or_default(),
    None => Vec::new(),
  };
  let idle_cap = cfg.policy.wants("idle_cap");
  if let (Some(idle_addr), Some(idle_pid), true) = (cfg.idle_addr, cfg.idle_pid, idle_cap) {
    idle_stop.store(true, Ordering::Relaxed);
    if let Some(h) = idle_steady {
      let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
    }
    // Let the idle steady client's connections drain from the one-worker server so the cap is free
    // for the 4,096-connection fill.
    tokio::time::sleep(Duration::from_secs(3)).await;
    // Its own deadline: a wedged fill fails the scenario instead of hanging the run.
    let r = match tokio::time::timeout(
      Duration::from_secs(300),
      scenario::idle_connections(&cfg.policy, idle_addr, idle_pid),
    )
    .await
    {
      Ok(r) => r,
      Err(_) => scenario::ScenarioResult {
        name: "idle_cap".into(),
        pass: false,
        detail: "exceeded its 300 s deadline".into(),
      },
    };
    lines.push(Line {
      kind: "scenario",
      name: r.name,
      pass: r.pass,
      detail: r.detail,
      rss_peak_kib: None,
    });
  } else {
    idle_stop.store(true, Ordering::Relaxed);
    if let Some(h) = idle_steady {
      let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
    }
  }

  // Keep the main steady client running until the full duration elapses.
  let remaining = deadline.saturating_duration_since(Instant::now());
  if remaining > Duration::ZERO {
    tokio::time::sleep(remaining).await;
  }

  main_stop.store(true, Ordering::Relaxed);
  samp_main_stop.store(true, Ordering::Relaxed);
  let _ = tokio::time::timeout(Duration::from_secs(20), main_steady).await;
  let main_samples = samp_main.await.unwrap_or_default();

  let mut fails = 0u32;
  let mut results = Vec::new();
  let mut emit = |line: Line, fails: &mut u32| {
    if !line.pass {
      *fails = fails.wrapping_add(1);
    }
    if let Ok(text) = serde_json::to_string(&line) {
      let _ = writeln!(out, "{text}");
    }

    eprintln!(
      "{} {} {} — {}",
      if line.pass { "PASS" } else { "FAIL" },
      line.kind,
      line.name,
      line.detail
    );
    results.push(line);
  };

  for (label, plateau, samples) in
    [("rss_main", plateau_main, &main_samples), ("rss_idle", plateau_idle, &idle_samples)]
  {
    if plateau == 0 && samples.is_empty() {
      continue;
    }
    let peak = samples.iter().map(|el| el.rss_kib).max().unwrap_or(0).max(plateau);
    let bound = plateau.saturating_mul(110) / 100;
    emit(
      Line {
        kind: "rss",
        name: label.into(),
        pass: peak <= bound,
        detail: format!(
          "peak {peak} KiB, plateau {plateau} KiB, bound {bound} KiB (×1.10, no slack)"
        ),
        rss_peak_kib: Some(peak),
      },
      &mut fails,
    );
  }

  for (label, c, present) in [
    ("steady_main", &main_counters, true),
    ("steady_idle", &idle_counters, cfg.idle_addr.is_some()),
  ] {
    if !present {
      continue;
    }
    let (ok, bad, stalls) = (
      c.ok.load(Ordering::Relaxed),
      c.bad.load(Ordering::Relaxed),
      c.stalls.load(Ordering::Relaxed),
    );
    emit(
      Line {
        kind: "steady",
        name: label.into(),
        pass: stalls == 0 && bad == 0,
        detail: format!(
          "{ok} ok, {bad} failed, {stalls} stalls, max rtt {} us",
          c.max_rtt_us.load(Ordering::Relaxed)
        ),
        rss_peak_kib: None,
      },
      &mut fails,
    );
  }

  for line in lines {
    emit(line, &mut fails);
  }

  let wall = run_begin.elapsed();
  eprintln!(
    "h3 soak: wall {:.0}s, plateau main/idle {plateau_main}/{plateau_idle} KiB, {} workers, memlock {}",
    wall.as_secs_f64(),
    cfg.main_workers,
    cfg.memlock_kib.map_or("unlimited".into(), |el| format!("{el} KiB"))
  );
  H3Report { pass: fails == 0, fails, wall_s: wall.as_secs_f64(), results }
}

/// What an HTTP/3 soak found.
#[derive(Clone, Debug, serde::Serialize)]
pub struct H3Report {
  pub pass: bool,
  pub fails: u32,
  pub wall_s: f64,
  /// The RSS checks, the steady clients, then every scenario, in that order.
  pub results: Vec<Line>,
}
