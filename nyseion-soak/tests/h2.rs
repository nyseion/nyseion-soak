//! The HTTP/2 scenarios against reference servers: the `h2` crate server of
//! `support/h2server.rs` for the request scenarios, and a raw stub that enforces control-frame
//! budgets for the flood scenarios (the `h2` crate answers every SETTINGS and PING, which RFC 9113
//! allows, so the flood oracles rightly fail it).

#[path = "support/h2server.rs"]
mod h2server;

use h2server::{BIG_LEN, H2Opts, spawn_h2};
use nyseion_soak::{
  rng::rng,
  scenario::{Ctx, Outcome, Proto, Routes, Scenario, run},
};
use std::{net::SocketAddr, time::Duration};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpListener,
  time::timeout,
};

fn ctx(addr: SocketAddr) -> Ctx {
  let mut ctx = Ctx::new(addr);
  ctx.proto = Proto::H2;
  ctx.limits.idle = Duration::from_millis(500);
  ctx.routes = Routes { big_len: BIG_LEN, ..Routes::default() };
  ctx
}

fn is_fail(outcome: &Outcome) -> bool {
  matches!(outcome, Outcome::Fail { .. })
}

#[tokio::test(flavor = "multi_thread")]
async fn request_scenarios_pass_the_h2_crate_server() {
  let ctx = ctx(spawn_h2(H2Opts::default()).await);
  for scenario in [
    Scenario::H2Steady,
    Scenario::H2RapidReset,
    Scenario::H2ContinuationFlood,
    Scenario::H2SlowReader,
    Scenario::H2NeverRead,
    Scenario::H2WindowStarved,
    Scenario::H2HalfOpen,
    Scenario::H2OversizedHeaders,
    Scenario::H2OversizedBody,
  ] {
    for seed in 0..2 {
      let outcome = run(scenario, &ctx, &mut rng(seed)).await;
      assert_eq!(outcome, Outcome::Pass, "{scenario:?} seed {seed}");
    }
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn routes_are_configurable() {
  let mut ctx = ctx(spawn_h2(H2Opts::default()).await);
  // The server answers `ok`: another expected body fails the steady client.
  ctx.routes.ok_body = "OK".into();
  assert!(is_fail(&run(Scenario::H2Steady, &ctx, &mut rng(1)).await));
  // A missing echo route (404) fails it too.
  ctx.routes = Routes { echo_path: "/nope".into(), big_len: BIG_LEN, ..Routes::default() };
  let outcome = run(Scenario::H2Steady, &ctx, &mut rng(3)).await;
  assert!(is_fail(&outcome), "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_never_stalls_fails_never_read() {
  // An idle timeout far past the scenario's wait: the server keeps the stalled connection.
  let opts = H2Opts { idle: Duration::from_secs(30), ..H2Opts::default() };
  let ctx = ctx(spawn_h2(opts).await);
  assert!(is_fail(&run(Scenario::H2WindowStarved, &ctx, &mut rng(1)).await));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_h2_crate_answers_control_frame_floods_without_limit() {
  // Not a fault of the harness: the oracle reports a server without a control-frame budget.
  let ctx = ctx(spawn_h2(H2Opts::default()).await);
  assert!(is_fail(&run(Scenario::H2SettingsFlood, &ctx, &mut rng(1)).await));
}

/// A raw HTTP/2 stub that acknowledges SETTINGS and answers PINGs until `budget` of them (or of
/// RST_STREAMs) have come, then sends GOAWAY with `code` and closes.
async fn spawn_guard(budget: u32, code: u32) -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let _task = tokio::spawn(async move {
    loop {
      let Ok((mut stream, _)) = listener.accept().await else { return };
      let _conn = tokio::spawn(async move {
        let mut preface = [0; 24];
        if stream.read_exact(&mut preface).await.is_err() {
          return;
        }
        let _ = stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await;
        let (mut control, mut resets) = (0u32, 0u32);
        let mut head = [0u8; 9];
        loop {
          if stream.read_exact(&mut head).await.is_err() {
            return;
          }
          let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
          let (ty, flags) = (head[3], head[4]);
          let mut payload = vec![0; len];
          if stream.read_exact(&mut payload).await.is_err() {
            return;
          }
          match ty {
            4 if flags & 1 == 0 => {
              control += 1;
              let _ = stream.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await;
            }
            6 if flags & 1 == 0 => {
              control += 1;
              let mut ack = vec![0, 0, 8, 6, 1, 0, 0, 0, 0];
              ack.extend_from_slice(&payload);
              let _ = stream.write_all(&ack).await;
            }
            3 => resets += 1,
            _ => {}
          }
          if control > budget || resets > budget {
            let mut go_away = vec![0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            go_away.extend_from_slice(&code.to_be_bytes());
            let _ = stream.write_all(&go_away).await;
            let _ = stream.shutdown().await;
            // Drain the rest of the flood, so the close is a FIN rather than a reset that could
            // discard the GOAWAY on the client's side.
            let mut sink = vec![0; 65536];
            while let Ok(Ok(n)) = timeout(Duration::from_millis(200), stream.read(&mut sink)).await
            {
              if n == 0 {
                break;
              }
            }
            return;
          }
        }
      });
    }
  });
  addr
}

#[tokio::test(flavor = "multi_thread")]
async fn control_frame_floods_pass_a_guarded_server() {
  let ctx = ctx(spawn_guard(100, 11).await);
  for scenario in [Scenario::H2SettingsFlood, Scenario::H2PingFlood, Scenario::H2RapidReset] {
    assert_eq!(run(scenario, &ctx, &mut rng(1)).await, Outcome::Pass, "{scenario:?}");
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_goaway_code_of_a_flood_is_configurable() {
  // INTERNAL_ERROR (2) is not ENHANCE_YOUR_CALM: refused by default, accepted when configured, or
  // with any code allowed.
  let mut ctx = ctx(spawn_guard(100, 2).await);
  let outcome = run(Scenario::H2PingFlood, &ctx, &mut rng(1)).await;
  match &outcome {
    Outcome::Fail { reason, .. } => assert!(reason.contains("[11]"), "{reason}"),
    other => panic!("{other:?}"),
  }
  ctx.expect.h2_calm = vec![2, 11];
  assert_eq!(run(Scenario::H2PingFlood, &ctx, &mut rng(1)).await, Outcome::Pass);
  ctx.expect.h2_calm = Vec::new();
  assert_eq!(run(Scenario::H2PingFlood, &ctx, &mut rng(1)).await, Outcome::Pass);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_echo_route_round_trips_get_the_ok_route() {
  let mut ctx = ctx(spawn_h2(H2Opts::default()).await);
  ctx.routes.echo_path = String::new();
  for scenario in [Scenario::H2Steady, Scenario::H2RapidReset, Scenario::H2OversizedBody] {
    assert_eq!(run(scenario, &ctx, &mut rng(1)).await, Outcome::Pass, "{scenario:?}");
  }
  let mut ready = nyseion_soak::scenario::Ready::open(&ctx, &mut rng(1)).await.unwrap();
  let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
  assert!(ready.round_trip(b"ignored", &mut rng(1), deadline).await);
}
