//! `rimu-soak run ...` soaks a WebSocket or HTTP/2 server; `rimu-soak h3 ...` an HTTP/3 one;
//! `rimu-soak replay SEED:SLOT:GEN ...` reruns one scenario run alone and prints its transcript;
//! `rimu-soak list` prints the scenarios and profiles.

use clap::Parser as _;
use rimu_soak::{
  conn::ConnOpts,
  cycle::{self, CycleConfig, Extended, RecordMode},
  monitor::find_pid,
  quic::driver::{H3Config, H3Policy},
  runner::{RunConfig, parse_replay, replay},
  scenario::{Ctx, Expect, Limits, Proto, Routes, Scenario, Weights, parse_weights, profile},
};
use std::{
  io::Write,
  net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as _},
  path::PathBuf,
  process::ExitCode,
  time::Duration,
};

#[derive(clap::Parser)]
// A later occurrence of an option overrides an earlier one, so a wrapper script's defaults can come
// first.
#[command(
  name = "rimu-soak",
  version,
  about = "Soak and abuse harness for WebSocket, HTTP/2 and HTTP/3 servers",
  args_override_self = true
)]
struct Cli {
  #[command(subcommand)]
  cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
  /// Soaks a WebSocket (`--proto ws`) or cleartext HTTP/2 (`--proto h2`) server: client slots run
  /// weighted scenarios while a monitor and latency probes judge the server.
  Run(Box<RunArgs>),
  /// Reruns one scenario run by its replay id and prints its record and transcript.
  Replay(Box<ReplayArgs>),
  /// Soaks an HTTP/3 server: steady clients beside abusive QUIC/HTTP/3 clients.
  H3(Box<H3Args>),
  /// Lists the scenarios and profiles.
  List,
}

/// Where the server runs and how to find it.
#[derive(clap::Args)]
struct Server {
  /// The server's pid, for the monitor (memory, descriptors, CPU, socket states). Without it or
  /// `--process-name`, the server is not monitored.
  #[arg(long, conflicts_with = "process_name")]
  pid: Option<u32>,
  /// The server's process name (its command name or executable file name), which must match
  /// exactly one process; an alternative to `--pid`.
  #[arg(long)]
  process_name: Option<String>,
}

impl Server {
  fn resolve(&self) -> Result<Option<u32>, String> {
    match (&self.pid, &self.process_name) {
      (Some(pid), _) => Ok(Some(*pid)),
      (None, Some(name)) => find_pid(name).map(Some),
      (None, None) => Ok(None),
    }
  }
}

/// How results are written.
#[derive(clap::Args)]
struct Output {
  /// Writes every sample, record and violation as JSON lines to this file.
  #[arg(long)]
  out: Option<PathBuf>,
  /// Prints the final summary as one JSON object on standard output.
  #[arg(long)]
  json: bool,
}

impl Output {
  fn writer(&self) -> Result<Box<dyn Write>, String> {
    let Some(path) = &self.out else { return Ok(Box::new(std::io::sink())) };
    if let Some(dir) = path.parent().filter(|el| !el.as_os_str().is_empty()) {
      std::fs::create_dir_all(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    }
    let file = std::fs::File::create(path).map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(Box::new(std::io::BufWriter::new(file)))
  }
}

/// The HTTP routes the HTTP/2 and HTTP/3 scenarios use.
#[derive(clap::Args)]
struct RouteArgs {
  /// A route whose `GET` answers 200 with `--ok-body`.
  #[arg(long, default_value = "/baseline2")]
  ok_path: String,
  #[arg(long, default_value = "ok")]
  ok_body: String,
  /// A route whose `POST` answers 200 with the request body (HTTP/2 only).
  #[arg(long, default_value = "/echo")]
  echo_path: String,
  /// A route whose `GET` answers 200 with a large body, for the slow and absent readers.
  #[arg(long, default_value = "/static/big.bin")]
  big_path: String,
  /// The size of the large body in bytes.
  #[arg(long, default_value_t = 10 << 20)]
  big_len: usize,
  /// Whether byte `i` of the large body is `i % 251`, which the slow readers then check.
  #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
  big_pattern: bool,
}

impl RouteArgs {
  fn routes(&self) -> Routes {
    Routes {
      ok_path: self.ok_path.clone(),
      ok_body: self.ok_body.clone(),
      echo_path: self.echo_path.clone(),
      big_path: self.big_path.clone(),
      big_len: self.big_len,
      big_pattern: self.big_pattern,
    }
  }
}

#[derive(clap::Args)]
struct Common {
  /// The server's URL: `ws://HOST:PORT/PATH` for WebSocket (plain, no TLS), `http://HOST:PORT`
  /// with `--proto h2`.
  #[arg(long, default_value = "ws://127.0.0.1:9080/")]
  url: String,
  /// The protocol the server speaks: WebSocket, or HTTP/2 without TLS (prior knowledge).
  #[arg(long, value_enum, default_value_t = Proto::Ws)]
  proto: Proto,
  /// The `Host` header (WebSocket) or `:authority` (HTTP/2); defaults to the URL's authority.
  #[arg(long)]
  host: Option<String>,
  /// Weighted mix: `baseline`, `hostile`, `attack`, `storm`, `untimed`, `drip` (WebSocket), or
  /// `baseline`, `hostile`, `attack`, `storm` (HTTP/2). A comma list (`hostile,storm`) rotates
  /// them by cycle; replay with the failing cycle's profile.
  #[arg(long, default_value = "hostile")]
  profile: String,
  /// Overrides `--profile`, as `echo=40,garbage=4`.
  #[arg(long, conflicts_with = "only")]
  weights: Option<String>,
  /// Overrides `--profile`: these scenarios, equally weighted, as `echo,invalid`.
  #[arg(long, value_delimiter = ',')]
  only: Option<Vec<Scenario>>,
  /// The server's handshake (first write) timeout.
  #[arg(long, default_value = "2s", value_parser = parse_duration)]
  handshake_timeout: Duration,
  /// The server's idle timeout.
  #[arg(long, default_value = "5s", value_parser = parse_duration)]
  idle_timeout: Duration,
  /// The server's close timeout.
  #[arg(long, default_value = "2s", value_parser = parse_duration)]
  close_timeout: Duration,
  /// The server's largest WebSocket message.
  #[arg(long, default_value_t = 1 << 20)]
  max_payload: u64,
  /// The server's SO_SNDBUF (at most 32 KiB), which `close_linger` needs; without it, that
  /// scenario is left out.
  #[arg(long)]
  server_sndbuf: Option<u32>,
  /// WebSocket close codes accepted for a message over the limit (RFC 6455 names 1009).
  #[arg(long, value_delimiter = ',', default_value = "1009")]
  too_big_codes: Vec<u16>,
  /// HTTP/2 GOAWAY codes accepted for the rapid reset, SETTINGS and PING floods (ENHANCE_YOUR_CALM
  /// is 11); `any` accepts every error code.
  #[arg(long, value_delimiter = ',', default_value = "11", value_parser = parse_calm)]
  h2_calm_codes: Vec<Option<u32>>,
  #[command(flatten)]
  routes: RouteArgs,
}

#[derive(clap::Args)]
struct RunArgs {
  #[command(flatten)]
  common: Common,
  #[command(flatten)]
  server: Server,
  #[command(flatten)]
  output: Output,
  #[arg(long, default_value_t = 1)]
  seed: u64,
  /// Concurrent client slots, each running scenario after scenario.
  #[arg(long, default_value_t = 100)]
  slots: u32,
  /// Length of each cycle's mixed load.
  #[arg(long, default_value = "60s", value_parser = parse_duration)]
  duration: Duration,
  #[arg(long, default_value_t = 1)]
  cycles: u32,
  /// Probes only, before each cycle's load: sets its latency and memory baselines.
  #[arg(long, default_value = "30s", value_parser = parse_duration)]
  warmup: Duration,
  /// Idle time after each cycle's load, before the leak check.
  #[arg(long, default_value = "10s", value_parser = parse_duration)]
  drain: Duration,
  /// Latency probe connections, and echoes per second on each.
  #[arg(long, default_value_t = 8)]
  probes: u32,
  #[arg(long, default_value_t = 100)]
  probe_rate: u32,
  /// After each cycle's drain, open this many connections and hold them (needs the monitor).
  #[arg(long)]
  fd_flood: Option<u32>,
  /// Source addresses to spread the slots over, as `a-b` ranges or a comma list.
  #[arg(long)]
  source_ips: Option<String>,
  /// Which scenario runs `--out` keeps: `all`, or `failures` (and harness errors) for long runs.
  #[arg(long, value_enum, default_value_t = Records::All)]
  records: Records,
  /// How often to sum up the run so far, on stderr and as a `heartbeat` line.
  #[arg(long, value_parser = parse_duration)]
  heartbeat: Option<Duration>,
  /// Cycles in a row the memory after the drain, or its peak, may rise (by over 8 MiB and 2% in
  /// all) before that is a violation. 0 turns the check off.
  #[arg(long, default_value_t = 0)]
  trend: u32,
  /// Kills the server past this RSS in MiB (needs the monitor), which ends the run.
  #[arg(long)]
  rss_ceiling: Option<u64>,
  /// Starts no cycle, and stops the load, this long into the run.
  #[arg(long, value_parser = parse_duration)]
  max_time: Option<Duration>,
  /// Ends the run at the first failure or violation.
  #[arg(long)]
  stop_on_first: bool,
  /// After each cycle's recovery check, opens this many connections at once; each must upgrade
  /// and echo within 5 s.
  #[arg(long)]
  burst: Option<u32>,
  /// Memory one connection may cost the server, in KiB, in the RSS limit (default 256 for
  /// WebSocket, 768 for HTTP/2).
  #[arg(long)]
  per_conn_kib: Option<u64>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Records {
  All,
  Failures,
}

#[derive(clap::Args)]
struct ReplayArgs {
  #[command(flatten)]
  common: Common,
  /// `SEED:SLOT:GEN`, as a failure prints it.
  id: String,
}

#[derive(clap::Args)]
struct H3Args {
  /// The (multi-worker) HTTP/3 server, as `https://127.0.0.1:8443`.
  #[arg(long, default_value = "https://127.0.0.1:8443")]
  url: String,
  #[command(flatten)]
  server: Server,
  /// A one-worker instance of the server, as `https://127.0.0.1:8444`, for the per-worker cap
  /// (`idle_cap`) and the CPU-attributed raw floods.
  #[arg(long)]
  idle_url: Option<String>,
  /// The one-worker server's pid.
  #[arg(long, conflicts_with = "idle_process_name")]
  idle_pid: Option<u32>,
  /// The one-worker server's process name.
  #[arg(long)]
  idle_process_name: Option<String>,
  #[command(flatten)]
  output: Output,
  /// The whole run (steady clients plus abusers).
  #[arg(long, default_value = "600s", value_parser = parse_duration)]
  duration: Duration,
  /// Steady-only time at the start that sets the RSS plateau.
  #[arg(long, default_value = "30s", value_parser = parse_duration)]
  warmup: Duration,
  /// Steady connections.
  #[arg(long, default_value_t = 64)]
  conns: u32,
  /// Streams per steady connection.
  #[arg(long, default_value_t = 64)]
  streams: u32,
  /// The main server's worker count, for the report.
  #[arg(long, default_value_t = 4)]
  workers: u32,
  /// SNI and `:authority` (the certificate is not checked).
  #[arg(long, default_value = "localhost")]
  server_name: String,
  #[command(flatten)]
  routes: RouteArgs,
  /// Only these scenarios (see `rimu-soak list`), as `reset_churn,qpack_flood`.
  #[arg(long, value_delimiter = ',', conflicts_with = "skip")]
  scenarios: Option<Vec<String>>,
  /// Every scenario but these.
  #[arg(long, value_delimiter = ',')]
  skip: Option<Vec<String>>,
  /// The application close code for a client over a rate budget (H3_EXCESSIVE_LOAD is 0x0107).
  #[arg(long, default_value = "0x0107", value_parser = parse_u64)]
  excessive_load_code: u64,
  /// The bidirectional streams the server allows a client at once.
  #[arg(long, default_value_t = 256)]
  max_bidi_streams: u32,
  /// Replies the server may send per second to unknown connection IDs (stateless resets).
  #[arg(long, default_value_t = 100)]
  stateless_reset_rate: u32,
  /// The server's idle timeout.
  #[arg(long, default_value = "30s", value_parser = parse_duration)]
  server_idle_timeout: Duration,
  /// The per-stream receive window the server grants, in bytes.
  #[arg(long, default_value_t = 1 << 20)]
  stream_window: u64,
  /// Connections one worker accepts.
  #[arg(long, default_value_t = 4096)]
  conns_per_worker: u32,
  /// Whether `initial_flood` must draw a Retry (address validation is optional in RFC 9000).
  #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
  expect_retry: bool,
  /// A route answering the server's live heap bytes as a decimal number, for `idle_cap`.
  #[arg(long)]
  mem_path: Option<String>,
  /// A route answering the server's own connection report, for `idle_cap`'s detail.
  #[arg(long)]
  stats_path: Option<String>,
}

fn parse_duration(s: &str) -> Result<Duration, String> {
  let (num, unit) = s.find(|el: char| !el.is_ascii_digit()).map_or((s, "s"), |at| s.split_at(at));
  let num: u64 = num.parse().map_err(|_| format!("bad duration `{s}`"))?;
  match unit {
    "ms" => Ok(Duration::from_millis(num)),
    "s" => Ok(Duration::from_secs(num)),
    "m" => Ok(Duration::from_secs(num * 60)),
    "h" => Ok(Duration::from_secs(num * 3600)),
    _ => Err(format!("bad duration unit in `{s}`")),
  }
}

fn parse_u64(s: &str) -> Result<u64, String> {
  match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
    Some(hex) => u64::from_str_radix(hex, 16),
    None => s.parse(),
  }
  .map_err(|_| format!("bad number `{s}`"))
}

fn parse_calm(s: &str) -> Result<Option<u32>, String> {
  if s == "any" {
    return Ok(None);
  }
  parse_u64(s)?.try_into().map(Some).map_err(|_| format!("bad code `{s}`"))
}

fn parse_ips(s: &str) -> Result<Vec<IpAddr>, String> {
  let mut ips = Vec::new();
  for part in s.split(',') {
    if let Some((first, last)) = part.split_once('-') {
      let first: Ipv4Addr = first.parse().map_err(|_| format!("bad address `{first}`"))?;
      let last: Ipv4Addr = last.parse().map_err(|_| format!("bad address `{last}`"))?;
      ips.extend((u32::from(first)..=u32::from(last)).map(|el| IpAddr::V4(el.into())));
    } else {
      ips.push(part.parse().map_err(|_| format!("bad address `{part}`"))?);
    }
  }
  Ok(ips)
}

/// Profiles by name, rotated by cycle.
type Rotation = Vec<(String, Weights)>;

/// The context, the first profile's weights, and every profile when `--profile` lists several.
fn ctx(common: &Common) -> Result<(Ctx, Weights, Rotation), String> {
  let scheme = if common.proto == Proto::H2 { "http://" } else { "ws://" };
  let rest =
    common.url.strip_prefix(scheme).ok_or_else(|| format!("only {scheme} URLs are supported"))?;
  let (authority, path) = rest.find('/').map_or((rest, "/"), |at| rest.split_at(at));
  let addr: SocketAddr = authority
    .to_socket_addrs()
    .map_err(|err| format!("{authority}: {err}"))?
    .next()
    .ok_or_else(|| format!("{authority} resolves to nothing"))?;
  let mut rotation = Vec::new();
  let weights = match (&common.weights, &common.only) {
    (Some(spec), _) => parse_weights(spec)?,
    (None, Some(only)) => {
      if only.is_empty() {
        return Err("--only needs a scenario".into());
      }
      Weights(only.iter().map(|el| (*el, 1)).collect())
    }
    (None, None) => {
      for name in common.profile.split(',').map(str::trim) {
        let weights =
          profile(name, common.proto).ok_or_else(|| format!("unknown profile {name}"))?;
        rotation.push((name.to_owned(), weights));
      }
      let first = rotation.first().map(|el| el.1.clone()).ok_or("no profile")?;
      if rotation.len() == 1 {
        rotation.clear();
      }
      first
    }
  };
  let limits = Limits {
    handshake: common.handshake_timeout,
    idle: common.idle_timeout,
    close: common.close_timeout,
    max_payload: common.max_payload,
    server_sndbuf: common.server_sndbuf,
    ..Limits::default()
  };
  if common.server_sndbuf.is_some_and(|el| el > 32 * 1024) {
    return Err("--server-sndbuf must be at most 32 KiB".into());
  }
  let weights = weights.for_limits(&limits)?;
  let rotation = rotation
    .into_iter()
    .map(|(name, weights)| Ok((name, weights.for_limits(&limits)?)))
    .collect::<Result<Vec<_>, String>>()?;
  let h2_calm = if common.h2_calm_codes.contains(&None) {
    Vec::new()
  } else {
    common.h2_calm_codes.iter().flatten().copied().collect()
  };
  let ctx = Ctx {
    addr,
    host: common.host.clone().unwrap_or_else(|| authority.to_owned()),
    path: path.to_owned(),
    limits,
    opts: ConnOpts::default(),
    proto: common.proto,
    routes: common.routes.routes(),
    expect: Expect { too_big: common.too_big_codes.clone(), h2_calm },
  };
  Ok((ctx, weights, rotation))
}

/// Raises the descriptor limit to its hard limit: every slot holds a socket or two.
fn raise_nofile() {
  let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
  // SAFETY: valid out pointer
  if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
    lim.rlim_cur = lim.rlim_max;
    // SAFETY: valid pointer
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };
  }
}

fn main() -> ExitCode {
  let cli = Cli::parse();
  raise_nofile();
  let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
  let rslt = match cli.cmd {
    Cmd::Run(args) => runtime.block_on(run(*args)),
    Cmd::Replay(args) => runtime.block_on(replay_one(*args)),
    Cmd::H3(args) => runtime.block_on(run_h3(*args)),
    Cmd::List => {
      list();
      Ok(ExitCode::SUCCESS)
    }
  };
  rslt.unwrap_or_else(|err| {
    eprintln!("error: {err}");
    ExitCode::from(3)
  })
}

fn list() {
  use clap::ValueEnum as _;
  let names = |h2: bool| -> Vec<String> {
    Scenario::value_variants()
      .iter()
      .filter_map(|el| el.to_possible_value())
      .map(|el| el.get_name().to_owned())
      .filter(|el| el.starts_with("h2_") == h2)
      .collect()
  };
  println!("WebSocket scenarios (run --proto ws):\n  {}", names(false).join(" "));
  println!("HTTP/2 scenarios (run --proto h2):\n  {}", names(true).join(" "));
  println!("HTTP/3 scenarios (h3):\n  {}", rimu_soak::quic::scenario::ALL.join(" "));
  for (proto, label, profiles) in [
    (Proto::Ws, "WebSocket", &["baseline", "hostile", "attack", "storm", "untimed", "drip"][..]),
    (Proto::H2, "HTTP/2", &["baseline", "hostile", "attack", "storm"][..]),
  ] {
    println!("{label} profiles:");
    for name in profiles {
      let weights = profile(name, proto).map(|el| el.0).unwrap_or_default();
      let spec: Vec<String> = weights
        .iter()
        .filter_map(|(scenario, weight)| {
          Some(format!("{}={weight}", scenario.to_possible_value()?.get_name()))
        })
        .collect();
      println!("  {name}: {}", spec.join(","));
    }
  }
}

async fn run(args: RunArgs) -> Result<ExitCode, String> {
  let (ctx, weights, rotation) = ctx(&args.common)?;
  let pid = args.server.resolve()?;
  let source_ips = args.source_ips.as_deref().map(parse_ips).transpose()?.unwrap_or_default();
  let mut out = args.output.writer()?;
  let port = ctx.addr.port();
  let cfg = CycleConfig {
    run: RunConfig {
      global_seed: args.seed,
      slots: args.slots,
      duration: args.duration,
      weights,
      ctx,
      source_ips,
    },
    pid,
    port,
    cycles: args.cycles,
    warmup: args.warmup,
    drain: args.drain,
    probes: args.probes,
    probe_rate: args.probe_rate,
    fd_flood: args.fd_flood,
    ext: Extended {
      rotation,
      records: match args.records {
        Records::All => RecordMode::All,
        Records::Failures => RecordMode::Failures,
      },
      heartbeat: args.heartbeat,
      trend: args.trend,
      rss_ceiling_kib: args.rss_ceiling.map(|el| el * 1024),
      max_time: args.max_time,
      stop_on_first: args.stop_on_first,
      burst: args.burst,
      per_conn_kib: args.per_conn_kib,
    },
  };
  let summary = cycle::run(cfg, &mut out).await;
  out.flush().map_err(|err| format!("--out: {err}"))?;
  eprintln!(
    "cycles {}, records {}, fails {}, harness errors {}, violations {}, saturated cycles {}; probe p50/p99/p99.9/max {}/{}/{}/{} us{}",
    summary.cycles,
    summary.records,
    summary.fails,
    summary.harness_errors,
    summary.violations.len(),
    summary.client_saturated_cycles,
    summary.latency.p50_us,
    summary.latency.p99_us,
    summary.latency.p999_us,
    summary.latency.max_us,
    summary.stopped.as_deref().map(|el| format!("; stopped: {el}")).unwrap_or_default(),
  );
  let code = if summary.fails > 0 || !summary.violations.is_empty() {
    1
  } else if summary.harness_errors > 0 {
    2
  } else {
    0
  };
  if args.output.json {
    let mut json = serde_json::to_value(&summary).map_err(|err| err.to_string())?;
    if let Some(map) = json.as_object_mut() {
      let _ = map.insert("pass".into(), (code == 0).into());
      let _ = map.insert("exit_code".into(), code.into());
    }
    println!("{json}");
  }
  Ok(ExitCode::from(code))
}

async fn replay_one(args: ReplayArgs) -> Result<ExitCode, String> {
  let (ctx, weights, rotation) = ctx(&args.common)?;
  if !rotation.is_empty() {
    return Err("replay one profile: the one of the failing cycle".into());
  }
  let id = parse_replay(&args.id).ok_or_else(|| format!("bad replay id `{}`", args.id))?;
  let record = replay(&ctx, &weights, id).await;
  println!(
    "{:?} {} {}",
    record.scenario,
    record.outcome,
    record.reason.as_deref().unwrap_or_default()
  );
  if let Some(transcript) = &record.transcript {
    println!("{transcript}");
  }
  Ok(ExitCode::from(u8::from(record.outcome != "pass")))
}

/// Parses an `https://host:port` URL to a socket address (the h3 soak speaks HTTPS only).
fn parse_h3_url(url: &str) -> Result<SocketAddr, String> {
  let rest = url.strip_prefix("https://").ok_or("only https:// URLs are supported")?;
  let authority = rest.split('/').next().unwrap_or(rest);
  authority
    .to_socket_addrs()
    .map_err(|err| format!("{authority}: {err}"))?
    .next()
    .ok_or_else(|| format!("{authority} resolves to nothing"))
}

/// The soft `RLIMIT_MEMLOCK` in KiB, or `None` when it is unlimited, for the report: io_uring
/// servers need locked memory.
fn memlock_kib() -> Option<u64> {
  let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
  // SAFETY: valid out pointer
  if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } != 0 {
    return None;
  }
  if lim.rlim_cur == libc::RLIM_INFINITY { None } else { Some(lim.rlim_cur / 1024) }
}

async fn run_h3(args: H3Args) -> Result<ExitCode, String> {
  let main_addr = parse_h3_url(&args.url)?;
  let idle_addr = args.idle_url.as_deref().map(parse_h3_url).transpose()?;
  let main_pid = args.server.resolve()?;
  let idle_pid =
    Server { pid: args.idle_pid, process_name: args.idle_process_name.clone() }.resolve()?;
  let all = rimu_soak::quic::scenario::ALL;
  let scenarios = match (&args.scenarios, &args.skip) {
    (Some(only), _) => Some(only.clone()),
    (None, Some(skip)) => Some(
      all.iter().filter(|el| !skip.iter().any(|s| s == *el)).map(|el| (*el).to_owned()).collect(),
    ),
    (None, None) => None,
  };
  for name in scenarios.iter().flatten().chain(args.skip.iter().flatten()) {
    if !all.contains(&name.as_str()) {
      return Err(format!("unknown h3 scenario `{name}` (see `rimu-soak list`)"));
    }
  }
  let policy = H3Policy {
    server_name: args.server_name.clone(),
    routes: args.routes.routes(),
    excessive_load: args.excessive_load_code,
    max_bidi_streams: args.max_bidi_streams,
    stateless_reset_per_sec: args.stateless_reset_rate,
    idle_timeout: args.server_idle_timeout,
    stream_window: args.stream_window,
    conns_per_worker: args.conns_per_worker,
    expect_retry: args.expect_retry,
    mem_path: args.mem_path.clone(),
    stats_path: args.stats_path.clone(),
    scenarios,
  };
  let mut out = args.output.writer()?;
  let cfg = H3Config {
    main_addr,
    main_pid,
    idle_addr,
    idle_pid,
    duration: args.duration,
    warmup: args.warmup,
    conns: args.conns,
    streams: args.streams,
    main_workers: args.workers,
    memlock_kib: memlock_kib(),
    policy,
  };
  let report = rimu_soak::quic::driver::run(cfg, &mut out).await;
  out.flush().map_err(|err| format!("--out: {err}"))?;
  eprintln!("h3 soak: {} failures", report.fails);
  if args.output.json {
    println!("{}", serde_json::to_string(&report).map_err(|err| err.to_string())?);
  }
  Ok(ExitCode::from(if report.fails > 0 { 1 } else { 0 }))
}
