//! The HTTP/3 soak against the reference server of `support/h3server.rs` (`quinn` and `h3`).
//!
//! The scenarios whose limits RFC 9000, 9114 and 9204 leave to the server (rate budgets that close
//! with H3_EXCESSIVE_LOAD, a CRYPTO buffer of exactly 4,096 bytes, a cap on out-of-order stream
//! ranges, closing on a retired connection ID, three times the bytes received per address even
//! once validated) test a policy quinn does not have, so they are shown to fail here, which is
//! what the oracle should say of a server without the limit.

#[path = "support/h3server.rs"]
mod h3server;

use h3server::{BIG_LEN, H3Opts, spawn_h3};
use nyseion_soak::{
  quic::{
    driver::{H3Config, H3Policy, H3Report, run},
    onertt::OneRttClient,
  },
  scenario::Routes,
};
use std::{net::SocketAddr, time::Duration};

fn policy(names: &[&str]) -> H3Policy {
  H3Policy {
    routes: Routes { big_len: BIG_LEN, ..Routes::default() },
    idle_timeout: Duration::from_secs(3),
    // quinn validates addresses only when told to.
    expect_retry: false,
    scenarios: Some(names.iter().map(|el| (*el).to_owned()).collect()),
    ..H3Policy::default()
  }
}

fn config(main_addr: SocketAddr, policy: H3Policy) -> H3Config {
  H3Config {
    main_addr,
    main_pid: None,
    idle_addr: None,
    idle_pid: None,
    duration: Duration::from_secs(300),
    warmup: Duration::from_millis(500),
    conns: 2,
    streams: 2,
    main_workers: 1,
    memlock_kib: None,
    policy,
    hold: false,
  }
}

fn line<'r>(report: &'r H3Report, name: &str) -> &'r nyseion_soak::quic::driver::Line {
  report.results.iter().find(|el| el.name == name).unwrap_or_else(|| panic!("no {name}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn rfc_scenarios_pass_a_quinn_server() {
  let names = [
    "initial_flood",
    "forged_short_header",
    "credit_starved",
    "window_starved",
    "oversized_heads",
    "slow_reader",
    "never_read",
    "rebind",
    "never_ack",
    "raw_flapper",
    "onertt_ack_flood",
    "onertt_empty_packet",
    "onertt_stream_past_window",
    "onertt_empty_frames_flood",
  ];
  let addr = spawn_h3(H3Opts::default());
  let mut out = Vec::new();
  let report = run(config(addr, policy(&names)), &mut out).await;
  for name in names {
    let got = line(&report, name);
    assert!(got.pass, "{name}: {}", got.detail);
  }
  assert!(line(&report, "steady_main").pass, "{}", line(&report, "steady_main").detail);
  assert!(report.pass, "{:?}", report.results);
  // Every result is a JSON line of `--out`.
  let text = String::from_utf8(out).unwrap();
  assert_eq!(text.lines().count(), report.results.len());
  assert!(text.lines().all(|el| serde_json::from_str::<serde_json::Value>(el).is_ok()));
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_scenarios_fail_a_server_without_budgets() {
  let names = ["reset_churn", "qpack_backlog", "onertt_ping_flood", "onertt_new_cid_flood"];
  let addr = spawn_h3(H3Opts::default());
  let report = run(config(addr, policy(&names)), &mut Vec::new()).await;
  for name in names {
    let got = line(&report, name);
    assert!(!got.pass, "{name}: {}", got.detail);
    assert!(got.detail.contains("0x0107") || got.detail.contains("App(263)"), "{}", got.detail);
  }
  assert!(!report.pass);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stricter_server_window_fails_stream_past_window() {
  // The server grants 1 MiB; a policy that believes it grants 64 KiB sends at 128 KiB, inside the
  // window, and draws no close.
  let addr = spawn_h3(H3Opts::default());
  let mut small = policy(&["onertt_stream_past_window"]);
  small.stream_window = 64 << 10;
  let report = run(config(addr, small), &mut Vec::new()).await;
  assert!(!line(&report, "onertt_stream_past_window").pass);
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_cap_fills_a_one_worker_server() {
  let cap = 64;
  let main = spawn_h3(H3Opts::default());
  let idle =
    spawn_h3(H3Opts { idle: Duration::from_secs(30), max_conns: Some(cap), ..H3Opts::default() });
  let mut policy = policy(&["idle_cap"]);
  policy.conns_per_worker = cap as u32;
  let mut cfg = config(main, policy);
  cfg.idle_addr = Some(idle);
  // The server runs in this process.
  cfg.idle_pid = Some(std::process::id());
  let report = run(cfg, &mut Vec::new()).await;
  let got = line(&report, "idle_cap");
  assert!(got.pass, "{}", got.detail);
  assert!(line(&report, "steady_idle").pass, "{}", line(&report, "steady_idle").detail);
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_handshakes_complete_back_to_back() {
  let addr = spawn_h3(H3Opts::default());
  for _ in 0..5 {
    OneRttClient::connect(addr, "localhost").await.unwrap();
  }
}
