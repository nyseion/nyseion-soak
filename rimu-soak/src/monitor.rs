//! The server seen from outside, once a second: memory, descriptors, CPU and its sockets' states,
//! and the invariants a bounded server keeps.

/// Socket states on the server's port (sockets whose local port it is).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct TcpStates {
  pub established: u32,
  pub close_wait: u32,
  pub time_wait: u32,
  pub other: u32,
  pub recv_q: u64,
  pub send_q: u64,
}

/// One look at the server.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct Sample {
  pub rss_kib: u64,
  pub hwm_kib: u64,
  pub fds: u32,
  pub cpu_ticks: u64,
  pub tcp: TcpStates,
}

/// `VmRSS` and `VmHWM` in KiB.
pub fn parse_status(text: &str) -> Option<(u64, u64)> {
  let field = |name: &str| {
    text.lines().find_map(|line| line.strip_prefix(name)?.split_whitespace().next()?.parse().ok())
  };
  Some((field("VmRSS:")?, field("VmHWM:")?))
}

/// The `/proc/net/tcp` format.
pub fn parse_tcp_table(text: &str, port: u16) -> TcpStates {
  let mut states = TcpStates::default();
  for line in text.lines().skip(1) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let (Some(local), Some(state), Some(queues)) = (fields.get(1), fields.get(3), fields.get(4))
    else {
      continue;
    };
    let local_port = local.rsplit(':').next().and_then(|el| u16::from_str_radix(el, 16).ok());
    if local_port != Some(port) {
      continue;
    }
    match *state {
      "01" => states.established += 1,
      "08" => states.close_wait += 1,
      "06" => states.time_wait += 1,
      _ => states.other += 1,
    }
    if let Some((tx, rx)) = queues.split_once(':') {
      states.send_q += u64::from_str_radix(tx, 16).unwrap_or(0);
      states.recv_q += u64::from_str_radix(rx, 16).unwrap_or(0);
    }
  }
  states
}

/// `/proc/<pid>/stat` after the command name (which may hold spaces): the state, then fields 4
/// onwards, so field `n` is `fields[n - 4]`.
fn stat_fields(pid: u32) -> Result<(char, Vec<u64>), MonitorError> {
  let text = read(&format!("/proc/{pid}/stat"))?;
  let rest = text.rsplit_once(')').map(|el| el.1).unwrap_or_default();
  let mut words = rest.split_whitespace();
  let state = words.next().and_then(|el| el.chars().next()).unwrap_or('?');
  Ok((state, words.map(|el| el.parse().unwrap_or(0)).collect()))
}

fn read(path: &str) -> Result<String, MonitorError> {
  std::fs::read_to_string(path).map_err(|err| match err.kind() {
    std::io::ErrorKind::NotFound => MonitorError::PidGone,
    _ => MonitorError::Io(err),
  })
}

/// The pid of the one process named `name`: its command name (`/proc/PID/comm`, which the kernel
/// cuts to 15 bytes) or the file name of its executable (`argv[0]`). Errs when no process, or more
/// than one, matches, naming them. This process never matches.
pub fn find_pid(name: &str) -> Result<u32, String> {
  let own = std::process::id();
  let dir = std::fs::read_dir("/proc").map_err(|err| format!("/proc: {err}"))?;
  let mut found = Vec::new();
  for entry in dir.flatten() {
    let Some(pid) = entry.file_name().to_str().and_then(|el| el.parse::<u32>().ok()) else {
      continue;
    };
    if pid == own {
      continue;
    }
    let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
    let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
    if process_matches(name, comm.trim_end(), &cmdline) {
      found.push(pid);
    }
  }
  found.sort_unstable();
  match found.as_slice() {
    [pid] => Ok(*pid),
    [] => Err(format!("no process named `{name}`")),
    many => Err(format!("{} processes named `{name}` ({many:?}): pass --pid", many.len())),
  }
}

/// Whether a process with command name `comm` and command line `cmdline` (NUL-separated) is named
/// `name`: `comm` is `name` cut to 15 bytes, or `argv[0]`'s file name is `name`.
pub fn process_matches(name: &str, comm: &str, cmdline: &[u8]) -> bool {
  let short = name.get(..name.len().min(15)).unwrap_or(name);
  let argv0 = cmdline.split(|el| *el == 0).next().unwrap_or_default();
  let file = argv0.rsplit(|el| *el == b'/').next().unwrap_or_default();
  !name.is_empty() && (comm == short || file == name.as_bytes())
}

#[derive(Debug)]
pub enum MonitorError {
  /// The process is gone, or another one has its pid.
  PidGone,
  Io(std::io::Error),
}

/// Samples one process, which must stay the same process.
#[derive(Debug)]
pub struct Monitor {
  pid: u32,
  port: u16,
  start_time: u64,
  /// Set once `/proc/PID/fd` turned out unreadable (another user's process): descriptors then
  /// count as 0, which turns their checks off, and the rest is still sampled.
  fds_hidden: bool,
}

impl Monitor {
  pub fn new(pid: u32, port: u16) -> Result<Monitor, MonitorError> {
    let start_time = stat_fields(pid)?.1.get(22 - 4).copied().unwrap_or(0);
    Ok(Monitor { pid, port, start_time, fds_hidden: false })
  }

  pub fn pid(&self) -> u32 {
    self.pid
  }

  pub fn sample(&mut self) -> Result<Sample, MonitorError> {
    let (state, stat) = stat_fields(self.pid)?;
    let field = |n: usize| stat.get(n - 4).copied().unwrap_or(0);
    // A zombie has exited; another start time is another process with the same pid.
    if state == 'Z' || field(22) != self.start_time {
      return Err(MonitorError::PidGone);
    }
    // utime + stime
    let cpu_ticks = field(14) + field(15);
    let (rss_kib, hwm_kib) =
      parse_status(&read(&format!("/proc/{}/status", self.pid))?).unwrap_or((0, 0));
    let fds = match std::fs::read_dir(format!("/proc/{}/fd", self.pid)) {
      Ok(dir) => dir.count() as u32,
      Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Err(MonitorError::PidGone),
      Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
        if !self.fds_hidden {
          self.fds_hidden = true;
          eprintln!(
            "warning: monitor: /proc/{}/fd is not readable (run as the server's user or root): \
             descriptors are not checked",
            self.pid
          );
        }
        0
      }
      Err(err) => return Err(MonitorError::Io(err)),
    };
    let mut tcp = TcpStates::default();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
      if let Ok(text) = std::fs::read_to_string(table) {
        let part = parse_tcp_table(&text, self.port);
        tcp.established += part.established;
        tcp.close_wait += part.close_wait;
        tcp.time_wait += part.time_wait;
        tcp.other += part.other;
        tcp.recv_q += part.recv_q;
        tcp.send_q += part.send_q;
      }
    }
    Ok(Sample { rss_kib, hwm_kib, fds, cpu_ticks, tcp })
  }
}

/// What a sample is checked against: the server after warmup.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Baseline {
  pub rss_kib: u64,
  pub fds: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Budgets {
  pub slots: u32,
  /// Connections holding a message of up to `max_payload` on the server.
  pub large_inflight: u32,
  pub max_payload: u64,
  /// Memory a connection may cost the server, in KiB (0 is 256): by default 256 for WebSocket and
  /// 768 for HTTP/2, whose server streaming a large response holds its send buffers plus the
  /// largest write.
  pub per_slot_kib: u64,
}

/// A broken invariant.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub enum Violation {
  PidGone,
  Fds {
    fds: u32,
    limit: u32,
  },
  Rss {
    rss_kib: u64,
    limit_kib: u64,
  },
  CloseWait {
    count: u32,
  },
  Busy {
    cpu_pct: f64,
  },
  Latency {
    p99_us: u64,
    limit_us: u64,
  },
  /// Probe echoes that never came (or broke their connection) in one second.
  ProbeFailures {
    failures: u64,
    count: u64,
  },
  NoRecovery(String),
  Leak(String),
  /// Memory after the drain, or its peak, rose cycle after cycle.
  Trend(String),
  /// The server passed `--rss-ceiling` and was killed.
  RssCeiling {
    rss_kib: u64,
    ceiling_kib: u64,
  },
  /// Connections of a burst that were never served.
  Burst {
    unserved: u32,
    n: u32,
  },
}

/// While clients are connected.
pub fn check_running(
  base: &Baseline,
  s: &Sample,
  live_conns: u32,
  budgets: &Budgets,
  close_wait_streak: &mut u32,
) -> Vec<Violation> {
  let mut found = Vec::new();
  let fd_limit = base.fds + live_conns + 64;
  if s.fds > fd_limit {
    found.push(Violation::Fds { fds: s.fds, limit: fd_limit });
  }
  // A large message costs the server the message, its buffer's doubling, and the echo.
  let large_kib = u64::from(budgets.large_inflight) * 3 * budgets.max_payload.div_ceil(1024);
  let per_slot_kib = if budgets.per_slot_kib == 0 { 256 } else { budgets.per_slot_kib };
  let rss_limit = base.rss_kib + per_slot_kib * u64::from(budgets.slots) + 65536 + large_kib;
  if s.rss_kib > rss_limit {
    found.push(Violation::Rss { rss_kib: s.rss_kib, limit_kib: rss_limit });
  }
  if s.tcp.close_wait > 64 {
    *close_wait_streak += 1;
    if *close_wait_streak >= 3 {
      found.push(Violation::CloseWait { count: s.tcp.close_wait });
    }
  } else {
    *close_wait_streak = 0;
  }
  found
}

/// After every client has gone.
pub fn check_drained(base: &Baseline, s: &Sample) -> Vec<Violation> {
  let mut found = Vec::new();
  if s.fds > base.fds + 16 {
    found.push(Violation::Leak(format!(
      "{} descriptors after the drain, baseline {}",
      s.fds, base.fds
    )));
  }
  let rss_limit = base.rss_kib * 11 / 10 + 16384;
  if s.rss_kib > rss_limit {
    found.push(Violation::Leak(format!(
      "RSS {} KiB after the drain, limit {rss_limit} KiB",
      s.rss_kib
    )));
  }
  if s.tcp.close_wait > 0 {
    found
      .push(Violation::Leak(format!("{} sockets in CLOSE_WAIT after the drain", s.tcp.close_wait)));
  }
  found
}
