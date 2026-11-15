# nyseion-soak

A soak and abuse harness for WebSocket, HTTP/2 and HTTP/3 (QUIC) servers. Thousands of simulated
clients mix traffic that is checked byte for byte with hostile behaviour, while a monitor watches
the server from outside and fails the run if the server answers wrongly or stops being bounded.
Point it at any server; every assumption about the server is a flag whose default is what
nyseion-ws serves.

The workspace also has `udp-impair`, a seeded UDP proxy that drops, reorders, duplicates, delays
and rebinds datagrams, for running QUIC clients and servers under impairment.

Part of the nyseion family of performance crates, alongside [nyseion-ws](https://github.com/vincentmele/nyseion-ws).


The harness speaks raw bytes through codecs of its own: a WebSocket frame codec, an HTTP/2 frame
codec with a literal-only HPACK encoder, and raw QUIC Initial and 1-RTT packets built with the
RustCrypto crates and rustls's QUIC key schedule. Its clients can therefore misbehave freely, and
it shares no bug with the server under test. The well-behaved HTTP/3 clients use `quinn` and `h3`.

## Quick start

```sh
cargo build --release
B=target/release/nyseion-soak

# WebSocket: 200 clients for 60 s, the server's memory, descriptors and sockets watched.
$B run --url ws://127.0.0.1:8080/ws --process-name my-server --slots 200 --duration 60s

# HTTP/2 cleartext (prior knowledge), with the server's own routes.
$B run --proto h2 --url http://127.0.0.1:8082 --pid 1234 \
   --ok-path /health --ok-body ok --echo-path /echo --big-path /files/10mb.bin --big-len 10485760 --big-pattern false

# HTTP/3: a steady client beside the QUIC abusers; leave out what tests a limit the server lacks.
$B h3 --url https://127.0.0.1:8443 --pid 1234 --skip idle_cap,onertt_stream_gaps --no-hold

# CI: fail the job on any failed check, keep a JSON summary.
$B run --url ws://127.0.0.1:9001/ --profile untimed --duration 30s --json > summary.json

$B list      # every scenario and profile
```

Exit codes: `0` every check passed; `1` a failed scenario or a violated invariant; `2` only
harness errors (the client ran out of ports or descriptors); `3` bad arguments or setup (unknown
scenario, unresolvable URL, no process of that name).

## Commands

| Command | What it does |
|---|---|
| `run` | Soaks a WebSocket (`--proto ws`, default) or cleartext HTTP/2 (`--proto h2`) server in cycles. |
| `replay SEED:SLOT:GEN` | Reruns one scenario run with the same bytes and prints its outcome and transcript. |
| `h3` | Soaks an HTTP/3 server: steady clients for the whole run beside the abusers, in sequence. |
| `list` | Prints every scenario and the weights of every profile. |

### What the server is

| Flag | Default | Meaning |
|---|---|---|
| `--url` | `ws://127.0.0.1:9080/` | `ws://HOST:PORT/PATH` (plain WebSocket) or `http://HOST:PORT` (`--proto h2`); `https://HOST:PORT` for `h3` (default `https://127.0.0.1:8443`). |
| `--host` | the URL's authority | `Host` (WebSocket) or `:authority` (HTTP/2). |
| `--server-name` | `localhost` | SNI and `:authority` for HTTP/3; the certificate is never checked. |
| `--pid` / `--process-name` | none | The process the monitor watches. A name must match exactly one process, by its command name or executable file name. Without either, the server is not monitored: the scenarios and probes still judge it, but memory, descriptors, CPU, leaks and the descriptor flood are not checked. |
| `--handshake-timeout`, `--idle-timeout`, `--close-timeout` | 2 s, 5 s, 2 s | The server's limits, which the timeout oracles allow `limit × 5/4 + 250 ms` for. |
| `--max-payload` | 1 MiB | The server's largest WebSocket message. |
| `--server-sndbuf` | none | The server's `SO_SNDBUF` (≤ 32 KiB); `close_linger` runs only with it. |
| `--too-big-codes` | `1009` | WebSocket close codes accepted for a message over the limit. |
| `--h2-calm-codes` | `11` | HTTP/2 GOAWAY codes accepted for the rapid reset, SETTINGS and PING floods; `any` accepts every error code. |
| `--ok-path`, `--ok-body` | `/baseline2`, `ok` | HTTP/2 and HTTP/3: `GET` answers 200 with this body. |
| `--echo-path` | `/echo` | HTTP/2: `POST` answers 200 with the request body. `''` if the server has none: round trips then `GET` the ok route. |
| `--big-path`, `--big-len`, `--big-pattern` | `/static/big.bin`, 10 MiB, `true` | A large file for the slow and absent readers; with `--big-pattern true`, byte `i` must be `i % 251`. |
| `--per-conn-kib` | 256 (ws), 768 (h2) | Memory one connection may cost the server, in the RSS limit. |

The HTTP/3 limits are `h3` flags, with nyseion-ws's values as defaults:

| Flag | Default | Used by |
|---|---|---|
| `--excessive-load-code` | `0x0107` (H3_EXCESSIVE_LOAD) | every rate-budget scenario but `qpack_backlog` |
| `--qpack-backlog-codes` | `0x0107,0x0201` | `qpack_backlog` |
| `--max-bidi-streams` | 256 | `credit_starved` |
| `--stateless-reset-rate` | 100/s | `forged_short_header` |
| `--server-idle-timeout` | 30 s | `window_starved`, `never_read` |
| `--stream-window` | 1 MiB | `onertt_stream_past_window` |
| `--conns-per-worker` | 4096 | `idle_cap` |
| `--expect-retry` | `true` | `initial_flood` |
| `--mem-path`, `--stats-path` | none | `idle_cap`'s per-connection heap figure and detail |

### How long and how hard

`run`: `--slots` (100), `--duration` per cycle (60 s), `--cycles` (1), `--warmup` (30 s),
`--drain` (10 s), `--probes` and `--probe-rate` (8 connections × 100/s), `--seed` (1),
`--profile` / `--weights` / `--only`, `--fd-flood N`, `--burst N`, `--trend N`,
`--rss-ceiling MiB`, `--max-time`, `--stop-on-first`, `--source-ips a-b`, `--heartbeat`,
`--records all|failures`.

`h3`: `--duration` (600 s), `--warmup` (30 s), `--conns` × `--streams` (64 × 64) for the steady
client, `--idle-url` / `--idle-pid` / `--idle-process-name` for a one-worker instance,
`--scenarios` or `--skip`, `--no-hold` to end once the abusers are done instead of running the
steady client to the end of `--duration`.

### Output

`--out FILE` writes every warmup, sample, scenario record, violation and heartbeat as one JSON
line tagged by `kind`, the summary last; `h3` writes one line per result. `--json` prints the
final summary (with `pass` and `exit_code`) as one JSON object on standard output. Failures also
go to standard error as `FAIL <scenario> replay=<id> — <reason>`, and `replay` reruns them:
give it the same `--profile` or `--weights`, which decide the scenario an id picks.

## What a `run` does

Each cycle runs these phases in order:

1. **Warmup:** the latency probes run alone; this sets the latency and memory baselines. HTTP/2
   first fetches the large file and the ok route over 96 connections, so caches are in the
   baseline.
2. **Mixed load:** every slot runs scenario after scenario for `--duration`, picked by weight
   from a seed derived from the run seed, its slot and its generation. The server is sampled once
   a second: RSS, descriptors, CPU, and the TCP states of sockets on its port.
3. **Drain:** everything idle for `--drain`, then the leak check.
4. **Recovery:** a fresh connection must upgrade and echo (HTTP/2: round trip) within 1 s.
5. **Burst** (`--burst N`): N connections at once; each must be served within 5 s.
6. **Descriptor flood** (`--fd-flood N`, needs the monitor): N connections held for 10 s; the
   server must stay under 20 % of a core and serve again within 2 s once they close.

The monitor and probes judge the server against:

| Check | Limit |
|---|---|
| Descriptors | baseline + live connections + 64 |
| RSS | baseline + `--per-conn-kib` per slot + 64 MiB + 3 × max payload per large message in flight |
| CLOSE_WAIT | at most 64, three samples running |
| After the drain | descriptors within 16 of the first baseline, RSS within 10 % + 16 MiB, no CLOSE_WAIT |
| Probe p99 | 5 × the warmup p99, and at least 1 ms over it |
| Probe failures | none |
| Trend (`--trend N`) | RSS after the drain, or its peak, must not rise N cycles running (by > 8 MiB and 2 %) |

When the probes run more than 1 ms late, the harness is the bottleneck: latency isn't judged for
that second, and failures in it are marked `client_saturated`.

Reading `/proc/PID/fd` needs the server's user or root; without it the monitor warns once and
checks everything but descriptors.

## WebSocket scenarios

Every scenario connects, and most upgrade with a fresh key whose `Sec-WebSocket-Accept` is checked
(RFC 6455 section 4.2.2). Echoed messages must come back byte for byte, in order, with their
opcode; a close the client sends must be answered with the same code, then EOF.

| Scenario | Sends | Passes when |
|---|---|---|
| `echo` | 1-20 text or binary messages (mostly ≤ 125 B, some ≤ 4 KiB, one in ten 70-200 KB), a quarter fragmented, written in random pieces, then close 1000 | every echo identical and in order, close 1000, EOF |
| `split_every_byte` | up to 3 small messages and a close, one byte per write (`TCP_NODELAY`) | as `echo` |
| `ctrl_in_fragments` | a text in 3 fragments with a ping between the first two | the pong comes before the reassembled echo (control frames may be injected mid-message, RFC 6455 5.4/5.5) |
| `never_read` | 64-byte texts with a 4 KiB receive buffer, never reading | a send blocks 500 ms (the server stopped reading) or the server closes, within 10 s |
| `slowloris` | the upgrade request at one byte per 100 ms | closed within the handshake timeout, never answered 101 |
| `idle_pre` | nothing after connecting | closed within the shorter of the handshake and idle timeouts |
| `idle_post` | nothing after the upgrade | closed within the idle timeout |
| `close_in_handshake` | part of the upgrade request, then FIN or a reset | after a FIN, the server closes within 2 s |
| `rst_midframe` | a frame header and part of its payload, then a reset | nothing to judge on the wire; leaks show in the monitor |
| `half_close` | a few messages, a close half of the time, then `shutdown(SHUT_WR)` | every echo, the close if one was sent, then EOF (within the close timeout if not) |
| `ping_flood` | 10,000 pings with random payloads while reading, then a text and a close | every pong answers a ping sent, at least one pong, the text echoed, close 1000, EOF |
| `garbage` | 1-4,096 random bytes after the upgrade | closed within the idle timeout |
| `invalid` | one RFC 6455 violation after 0-3 valid echoes (see below) | close 1002 (1007 for bad UTF-8, `--too-big-codes` for an oversized message), then EOF |
| `huge_len` | a header declaring 2^63-1, 2^32 or max payload + 1 bytes, then trickled payload | within 1 s, close with a `--too-big-codes` code, 1009 or 1002, without waiting for the payload; then EOF |
| `bad_upgrade` | a malformed or unusual upgrade request (see below) | answered or closed within 1 s; requests RFC 6455 4.2.1 says to refuse are not upgraded; an upgrade has the right accept key and echoes |
| `header_flood` | an upgrade request whose last header never ends, at ~3 MB/s | refused, closed, or reading stopped and closed within the handshake timeout, before 1 MiB was read; never 101 |
| `frag_flood` | one 10-40 KB message in one-byte fragments | echoed whole |
| `zero_flood` | 10,000-30,000 empty binary messages | each echoed |
| `frag_drip` | a message of 3/4 of max payload to all of it (or max payload + 1, a quarter of the time) in 16 KiB fragments over ~3 s | echoed whole under the limit; over it, closed with a `--too-big-codes` code. Counts towards the large-message RSS budget |
| `close_linger` | (needs `--server-sndbuf`) messages whose echoes outgrow both sockets, a close, then nothing read for the close timeout | the server dropped the connection and the rest of its reply within its close timeout: the close frame never arrives |
| `ping_no_read` | 125-byte pings, never reading the pongs | as `never_read`: the server stops reading or closes, rather than queueing pongs without bound |
| `slow_reader` | 2-4 messages of 64-200 KB, read 8 KiB per 10 ms through a 16 KiB buffer | every echo whole and in order |

`invalid` cases: invalid UTF-8 in a text (1007, RFC 6455 8.1), reserved opcode 3, RSV1 without an
extension, an unmasked client frame (5.1), a fragmented ping, a 126-byte ping (5.5), close codes
999 or 1005 (7.4), a one-byte close payload (5.5.1), a continuation without a message, a new
message inside a fragmented one (5.4), and a declared length over max payload. All but the first
and last expect 1002.

`bad_upgrade` cases that must be refused: no key, an 8-byte key, version 8, `POST`, `HTTP/1.0`,
no `Upgrade`, no `Connection`. Cases the server may refuse or upgrade, but must answer at once:
bare-LF line endings, a header without a colon, a NUL in a value, an 8 KB path, 100 extra
headers, two keys (either accept key is fine), obs-fold. And a valid request with a frame right
behind it in the same write, which must be upgraded and echoed.

## HTTP/2 scenarios

Cleartext with prior knowledge. The client allows no HPACK dynamic table, no push, and maximum
windows, and decodes `:status` from static, literal and Huffman-coded fields.

| Scenario | Sends | Passes when |
|---|---|---|
| `h2_steady` | one connection, 100 streams in batches of 25: `GET` ok route or `POST` echo route with up to 2 KiB | every response 200, ended, with the expected body |
| `h2_rapid_reset` | 1,000 streams, each opened and reset at once (CVE-2023-44487) | GOAWAY with a `--h2-calm-codes` code, then EOF |
| `h2_continuation_flood` | a header block that never ends: 1,000 CONTINUATION frames | GOAWAY with any error code (RFC 9113 6.10 makes it a connection error), then EOF |
| `h2_settings_flood` | 3,000 SETTINGS, each owed an ACK (CVE-2019-9515) | GOAWAY with a `--h2-calm-codes` code, then EOF |
| `h2_ping_flood` | 3,000 PINGs (CVE-2019-9512) | as `h2_settings_flood` |
| `h2_slow_reader` | `GET` the large file, read 1 KiB a second for 8 s through a 4 KiB buffer | no reset, and the bytes that came are right (with `--big-pattern`) |
| `h2_never_read` | 20 `GET`s of the large file through a 4 KiB buffer, never reading | the server closes within the idle timeout, having sent less than half of what was asked |
| `h2_window_starved` | `GET` the large file with stream windows of 0 for good | no DATA with a payload, and the server closes within its idle timeout |
| `h2_half_open` | FIN right after the preface | the server closes too |
| `h2_oversized_headers` | a 100 KiB header field over HEADERS and CONTINUATIONs | refused (reset, 431 or GOAWAY), never 200; unless the server sent GOAWAY, the connection still serves the ok route |
| `h2_oversized_body` | `content-length: 100000000` and 16 KiB of it | refused (reset, 413 or GOAWAY), never 200; then as above |

An acknowledgement the server no longer takes is not an error: what it sent before closing (a
GOAWAY) is still read.

## HTTP/3 scenarios

`h3` starts a steady client (`--conns` × `--streams` request loops of `GET` ok route, each
bounded by 2 s) and samples the server's RSS during `--warmup` for its plateau. Then the abusers
run one after another, each with its own deadline, while the steady client runs on. The run fails
if any abuser fails, if a steady request fails or stalls, or if RSS ever goes over 1.10 × the
plateau. A one-worker instance (`--idle-url`) gets its own 4 × 4 steady client and takes the
raw floods, the flappers and `idle_cap`, so their cost is attributable.

Scenarios marked *policy* test a limit RFC 9000, 9114 and 9204 leave to the server; skip them for
a server without that limit, or set the flag that names its value.

| Scenario | Sends | Passes when |
|---|---|---|
| `crypto_overflow` | a raw first Initial whose CRYPTO frame starts at offset 5,000 | the server's Initial carries CONNECTION_CLOSE 0x0d CRYPTO_BUFFER_EXCEEDED (RFC 9000 7.5; *policy*: a server may buffer more than 4,096 bytes) |
| `initial_flood` | 150 one-byte-ClientHello Initials from each of 127.0.0.2-5, holding half-open slots | at least one Retry (*policy*, `--expect-retry`), and a well-behaved client still connects and gets 200 |
| `forged_short_header` | 500 1-RTT packets to unknown connection IDs | at most `--stateless-reset-rate` replies per second (*policy*) |
| `reset_churn` | streams opened and reset, 200 times | closed with `--excessive-load-code` (*policy*) |
| `credit_starved` | `--max-bidi-streams` open streams held, then one more | the extra stream gets no credit, and the connection stays up (RFC 9000 4.6) |
| `window_starved` | a request for the large file with every stream window 0 | no body arrives, the server's traffic goes quiet, and it closes between 2/3 and 2 × `--server-idle-timeout` |
| `qpack_flood` | Set Dynamic Table Capacity 4,096 on the encoder stream when the server allowed 0 | closed with QPACK_ENCODER_STREAM_ERROR 0x0201 (RFC 9204 4.3.1) |
| `qpack_backlog` | 4,096 valid no-op capacity instructions, then one that never ends | closed with one of `--qpack-backlog-codes` (default 0x0107 H3_EXCESSIVE_LOAD for a backlog cap, or 0x0201 QPACK_ENCODER_STREAM_ERROR for the integer refused as malformed, RFC 9204 §4.1.1) |
| `oversized_heads` | a request with a 20 KiB field section | a 431 response on the stream (raw or Huffman-coded `:status`), the connection still up (RFC 9114 4.2.2) |
| `slow_reader` | `GET` the large file, read slowly for ~20 reads | bytes right (with `--big-pattern`), some read, the connection still up |
| `never_read` | 20 `GET`s of the large file, never read, held for min(6 s, idle / 2) | the connection still up (the RSS gate bounds the server) |
| `rebind` | requests while the client's port, then its address (127.0.0.2), change | every request answered 200 (RFC 9000 9.3) |
| `never_ack` | `GET` the large file, then a black-holed transmit: no ACK ever leaves | the server goes quiet (bounded by its in-flight data) and the connection closes |
| `flapper` | a quinn connection whose source address alternates every datagram, as fast as requests go for 6 s | the server survives (or closes with a code), and sends each address at most 3 × what it received from it, plus 1,500 bytes (*policy*: stricter than RFC 9000 8, which limits unvalidated addresses only) |
| `raw_flapper` | raw MAX_DATA packets alternating between the handshake address and one never validated, with no PING | at most 3 × to the unvalidated address (RFC 9000 8.1), and with a pid, server CPU per flip ≤ 100 µs over its idle rate |
| `onertt_ack_flood` | ACK frames with as many valid ranges as the server's packet numbers allow, over and over; then on a new connection an ACK reaching below packet 0 | no close for the valid ACKs, with a pid ≤ 50 µs server CPU per packet; FRAME_ENCODING_ERROR 0x07 for the malformed one (RFC 9000 19.3.1) |
| `onertt_ping_flood` | 48,000 PING frames in 40 packets | closed with `--excessive-load-code` (*policy*) |
| `onertt_path_challenge_flood` | 64 PATH_CHALLENGEs in one packet | closed with `--excessive-load-code` (*policy*) |
| `onertt_new_cid_flood` | 20 NEW_CONNECTION_IDs, each retiring the previous | closed with `--excessive-load-code` (*policy*) |
| `onertt_retire_cid` | RETIRE_CONNECTION_ID of the ID the packet is sent to | PROTOCOL_VIOLATION 0x0a (RFC 9000 19.16 allows it: *policy*) |
| `onertt_empty_packet` | a 1-RTT packet with no frames | PROTOCOL_VIOLATION 0x0a (RFC 9000 12.4) |
| `onertt_stream_gaps` | 300 one-byte STREAM frames each leaving a gap | PROTOCOL_VIOLATION 0x0a (*policy*: a cap on out-of-order ranges) |
| `onertt_stream_past_window` | one STREAM byte at twice `--stream-window` | FLOW_CONTROL_ERROR 0x03 (RFC 9000 4.1) |
| `onertt_empty_frames_flood` | 200 PADDING-only packets | no close (PADDING is ignored) |
| `idle_cap` | (needs `--idle-url` and its pid) `--conns-per-worker` idle connections to the one-worker server, twice, then one more | exactly the cap held both times, the extra one dropped (a handshake timeout), the server alive and a held connection answering; RSS (and with `--mem-path`, heap) per connection reported, above 8 KiB as a finding |

The scenarios that send from 127.0.0.2 (`initial_flood`'s sources, `rebind`, `flapper`,
`raw_flapper`) need an IPv4 loopback target; otherwise they send from one address or are skipped
(reported as passed with `skipped:` in the detail). The raw 1-RTT client acknowledges exactly the
packets it received during the handshake and draws fresh connection IDs per connection.

## udp-impair

```text
udp-impair --server-port 8443 [--server-ip IP] [--listen-port 0] [--drop P] [--reorder P]
           [--dup P] [--delay-us N] [--seed S] [--rebind N]
```

The proxy listens on `[::]` (it prints `listening PORT` once bound) and gives each client its own
socket towards the server, on the client's loopback family unless `--server-ip` says otherwise.
Both directions are impaired, each with its own sequence of decisions:

- `--drop`, `--reorder`, `--dup`: probabilities per datagram. A reordered copy is held 1-5 ms
  more; a duplicate takes its own turn. `--delay-us` delays every datagram.
- `--seed`: decisions depend on the seed and the order flows appeared, never on timing, so a run
  repeats.
- `--rebind N`: a NAT rebinding every N datagrams towards the server: a new source port, and on
  loopback from the second rebinding on, 127.0.0.2 (RFC 9000 9.3). Replies to the old mapping are
  lost. Each rebinding is printed to standard error as `rebind CLIENT LOCAL-ADDRESS`.

## Tests

`cargo test` is self-contained. It runs the oracles against reference servers that live in
`nyseion-soak/tests/support`: an in-process WebSocket echo server with fault knobs (each oracle is
shown to pass a correct server and fail a broken one), an HTTP/2 server on the `h2` crate, a raw
HTTP/2 stub that enforces control-frame budgets, and an HTTP/3 server on `quinn` and `h3` with a
self-signed certificate. The HTTP/3 scenarios that test a policy quinn doesn't have are shown to
fail it. The CLI is tested end to end, and `udp-impair` through a UDP echo server.

## License

Copyright 2026 Vincent Mele. Licensed under the [Apache License, version 2.0](LICENSE).
