//! A soak and abuse harness for WebSocket, HTTP/2 and HTTP/3 (QUIC) servers: thousands of
//! simulated clients mixing verified traffic with hostile behaviour, and a monitor that checks the
//! server stays correct and bounded.
//!
//! It speaks raw bytes through codecs of its own and doesn't depend on any server library, so its
//! clients can misbehave freely and a bug the two shared couldn't hide. Every assumption about the
//! server (routes, limits, the close codes the RFCs leave to it) is configuration:
//! [`scenario::Ctx`] for WebSocket and HTTP/2, [`quic::driver::H3Policy`] for HTTP/3.
//!
//! - [`cycle::run`] soaks a WebSocket or HTTP/2 server in cycles of warmup, load, drain and checks.
//! - [`runner::replay`] reruns one scenario run by its id.
//! - [`quic::driver::run`] soaks an HTTP/3 server.

pub mod burst;
pub mod codec;
pub mod conn;
pub mod cycle;
pub mod fdflood;
pub mod h2codec;
pub mod monitor;
pub mod probe;
pub mod quic;
pub mod rng;
pub mod runner;
pub mod scenario;
