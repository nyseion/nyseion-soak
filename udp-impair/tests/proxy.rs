//! End to end: a UDP echo server behind the proxy, driven by a client on loopback.

use std::{
  collections::BTreeSet,
  io::{BufRead as _, BufReader},
  net::{SocketAddr, UdpSocket},
  process::{Child, Command, Stdio},
  sync::{Arc, Mutex},
  time::Duration,
};

/// Every datagram the echo server got, and where from.
type Seen = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

/// An echo server on 127.0.0.1 that records every datagram and where it came from.
struct Echo {
  port: u16,
  seen: Seen,
}

fn echo_server() -> Echo {
  let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
  let port = sock.local_addr().unwrap().port();
  let seen = Arc::new(Mutex::new(Vec::new()));
  let log = seen.clone();
  let _jh = std::thread::spawn(move || {
    let mut buf = [0u8; 2048];
    while let Ok((len, from)) = sock.recv_from(&mut buf) {
      log.lock().unwrap().push((from, buf[..len].to_vec()));
      let _ = sock.send_to(&buf[..len], from);
    }
  });
  Echo { port, seen }
}

/// The proxy in front of `server_port`, and the port it listens on.
struct Proxy {
  child: Child,
  port: u16,
}

impl Drop for Proxy {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
  }
}

fn proxy(server_port: u16, extra: &[&str]) -> Proxy {
  let mut child = Command::new(env!("CARGO_BIN_EXE_udp-impair"))
    .arg("--server-port")
    .arg(server_port.to_string())
    .args(extra)
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
  let mut line = String::new();
  BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
  let port = line.trim().strip_prefix("listening ").unwrap().parse().unwrap();
  Proxy { child, port }
}

/// Sends `n` numbered datagrams one at a time, waiting up to `wait` for each one's echoes, and
/// returns the numbers of the echoes that came back, in order of arrival.
fn exchange(proxy_port: u16, n: u32, wait: Duration) -> Vec<u32> {
  let client = UdpSocket::bind("127.0.0.1:0").unwrap();
  client.set_read_timeout(Some(wait)).unwrap();
  let mut got = Vec::new();
  let mut buf = [0u8; 64];
  for idx in 0..n {
    client.send_to(&idx.to_be_bytes(), ("127.0.0.1", proxy_port)).unwrap();
    while let Ok(len) = client.recv(&mut buf) {
      got.push(u32::from_be_bytes(buf[..len].try_into().unwrap()));
    }
  }
  got
}

fn numbers(seen: &Seen) -> BTreeSet<u32> {
  seen.lock().unwrap().iter().map(|el| u32::from_be_bytes(el.1[..4].try_into().unwrap())).collect()
}

#[test]
fn unimpaired_echoes_every_datagram_once_and_in_order() {
  let echo = echo_server();
  let proxy = proxy(echo.port, &[]);
  assert_eq!(exchange(proxy.port, 50, Duration::from_millis(100)), (0..50).collect::<Vec<_>>());
}

#[test]
fn total_loss_and_duplication() {
  let echo = echo_server();
  let lossy = proxy(echo.port, &["--drop", "1"]);
  assert!(exchange(lossy.port, 10, Duration::from_millis(50)).is_empty());
  assert!(echo.seen.lock().unwrap().is_empty());
  // Duplicated both ways: two copies reach the server, each echoed twice.
  let dup = proxy(echo.port, &["--dup", "1"]);
  let got = exchange(dup.port, 10, Duration::from_millis(100));
  for idx in 0..10 {
    assert_eq!(got.iter().filter(|el| **el == idx).count(), 4, "{got:?}");
  }
}

#[test]
fn delay_holds_every_datagram_back() {
  let echo = echo_server();
  let proxy = proxy(echo.port, &["--delay-us", "20000"]);
  let client = UdpSocket::bind("127.0.0.1:0").unwrap();
  client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
  let begin = std::time::Instant::now();
  client.send_to(b"ping", ("127.0.0.1", proxy.port)).unwrap();
  let mut buf = [0u8; 16];
  let len = client.recv(&mut buf).unwrap();
  assert_eq!(&buf[..len], b"ping");
  // 20 ms each way.
  assert!(begin.elapsed() >= Duration::from_millis(40), "{:?}", begin.elapsed());
}

#[test]
fn the_seed_decides_which_datagrams_are_lost() {
  let run = |seed: &str| {
    let echo = echo_server();
    let proxy = proxy(echo.port, &["--drop", "0.5", "--seed", seed]);
    let _ = exchange(proxy.port, 200, Duration::from_millis(20));
    numbers(&echo.seen)
  };
  let (a, b, c) = (run("7"), run("7"), run("8"));
  assert!((50..150).contains(&a.len()), "{}", a.len());
  assert_eq!(a, b);
  assert_ne!(a, c);
}

#[test]
fn rebinding_moves_the_flow_to_new_sources() {
  let echo = echo_server();
  let proxy = proxy(echo.port, &["--rebind", "10"]);
  // The echoes of every datagram still come back: each rebinding happens before a datagram
  // leaves, so its echo goes to the new socket.
  assert_eq!(exchange(proxy.port, 35, Duration::from_millis(100)).len(), 35);
  let sources: BTreeSet<SocketAddr> = echo.seen.lock().unwrap().iter().map(|el| el.0).collect();
  // The first socket, then three rebindings (datagrams 10, 20 and 30).
  assert_eq!(sources.len(), 4, "{sources:?}");
  assert!(sources.iter().any(|el| el.ip() == std::net::Ipv4Addr::new(127, 0, 0, 2)), "{sources:?}");
}

#[test]
fn bad_arguments_fail() {
  let out = Command::new(env!("CARGO_BIN_EXE_udp-impair")).arg("--drop").arg("2").output().unwrap();
  assert!(!out.status.success());
}
