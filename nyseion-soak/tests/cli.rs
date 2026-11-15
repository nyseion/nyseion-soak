//! The `nyseion-soak` binary: exit codes, `--json`, `--out` and `list`, against the reference servers.

#[path = "support/h2server.rs"]
mod h2server;
mod support;

use std::process::{Command, Output};
use support::{Faults, spawn_fake};

fn nyseion_soak(args: &[&str]) -> Output {
  Command::new(env!("CARGO_BIN_EXE_nyseion-soak")).args(args).output().unwrap()
}

/// A short run's arguments: one cycle of `duration`, no warmup or drain, and no latency probes
/// (without a warmup they would have no baseline).
fn short(url: &str, duration: &str) -> Vec<String> {
  let args = ["run", "--url", url, "--slots", "8", "--duration", duration, "--warmup", "0s"];
  let more = ["--drain", "0s", "--probes", "0", "--json"];
  args.iter().chain(&more).map(|el| (*el).to_owned()).collect()
}

fn summary(out: &Output) -> serde_json::Value {
  let text = String::from_utf8_lossy(&out.stdout);
  serde_json::from_str(text.lines().last().unwrap_or_default())
    .unwrap_or_else(|err| panic!("{err}: {text}"))
}

#[test]
fn list_names_every_scenario_and_profile() {
  let out = nyseion_soak(&["list"]);
  assert!(out.status.success());
  let text = String::from_utf8(out.stdout).unwrap();
  for name in ["echo", "huge_len", "h2_rapid_reset", "onertt_ping_flood", "idle_cap", "hostile:"] {
    assert!(text.contains(name), "{name}: {text}");
  }
}

#[test]
fn bad_arguments_exit_3() {
  assert_eq!(nyseion_soak(&["run", "--nope"]).status.code(), Some(3));
  assert_eq!(nyseion_soak(&["run", "--url", "http://x"]).status.code(), Some(3));
  assert_eq!(nyseion_soak(&["run", "--only", "nope"]).status.code(), Some(3));
  assert_eq!(nyseion_soak(&["h3", "--scenarios", "nope"]).status.code(), Some(3));
  let missing = nyseion_soak(&["run", "--process-name", "no-such-process-name-at-all"]);
  assert_eq!(missing.status.code(), Some(3));
  assert!(String::from_utf8_lossy(&missing.stderr).contains("no process named"));
  assert_eq!(nyseion_soak(&["--help"]).status.code(), Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_correct_server_passes_with_json_and_jsonl() {
  let addr = spawn_fake(Faults::default()).await;
  let dir = std::env::temp_dir().join(format!("nyseion-soak-cli-{}", std::process::id()));
  let jsonl = dir.join("run.jsonl");
  let mut args = short(&format!("ws://{addr}/"), "2s");
  args.extend(
    ["--only", "echo,invalid,bad_upgrade", "--out", jsonl.to_str().unwrap()].map(String::from),
  );
  let out = tokio::task::spawn_blocking(move || {
    Command::new(env!("CARGO_BIN_EXE_nyseion-soak")).args(&args).output().unwrap()
  })
  .await
  .unwrap();
  assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
  let json = summary(&out);
  assert_eq!(json["pass"], true);
  assert!(json["records"].as_u64().unwrap() > 0, "{json}");
  let lines = std::fs::read_to_string(&jsonl).unwrap();
  let _ = std::fs::remove_dir_all(&dir);
  assert!(lines.lines().any(|el| el.contains("\"kind\":\"record\"")));
  assert!(lines.lines().last().unwrap().contains("\"kind\":\"summary\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broken_server_exits_1() {
  let addr = spawn_fake(Faults { corrupt_echo: true, ..Faults::default() }).await;
  let mut args = short(&format!("ws://{addr}/"), "1s");
  args.extend(["--only".to_owned(), "echo".to_owned()]);
  let out = tokio::task::spawn_blocking(move || {
    Command::new(env!("CARGO_BIN_EXE_nyseion-soak")).args(&args).output().unwrap()
  })
  .await
  .unwrap();
  assert_eq!(out.status.code(), Some(1));
  let json = summary(&out);
  assert_eq!(json["pass"], false);
  assert!(json["fails"].as_u64().unwrap() > 0);
  assert!(String::from_utf8_lossy(&out.stderr).contains("FAIL Echo replay="));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_h2_server_passes_its_baseline() {
  let addr = h2server::spawn_h2(h2server::H2Opts::default()).await;
  let mut args = short(&format!("http://{addr}"), "2s");
  let big_len = h2server::BIG_LEN.to_string();
  args.extend(["--proto", "h2", "--profile", "baseline", "--big-len", &big_len].map(String::from));
  let out = tokio::task::spawn_blocking(move || {
    Command::new(env!("CARGO_BIN_EXE_nyseion-soak")).args(&args).output().unwrap()
  })
  .await
  .unwrap();
  assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
  assert_eq!(summary(&out)["pass"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_server_exits_1() {
  // A port nothing listens on.
  let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
  let args = short(&format!("ws://127.0.0.1:{port}/"), "1s");
  let out = tokio::task::spawn_blocking(move || {
    Command::new(env!("CARGO_BIN_EXE_nyseion-soak")).args(&args).output().unwrap()
  })
  .await
  .unwrap();
  assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
  assert_eq!(summary(&out)["pass"], false);
}
