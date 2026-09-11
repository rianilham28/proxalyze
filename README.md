# proxalyze

Fast proxy **validator & parser** for the rest of your pipeline. Point it at plain
proxy lists; it checks every proxy over raw hyper connections and emits clean,
judged, machine-diffable data. Scraping is deliberately **not** in scope — proxalyze
consumes lists, it does not fetch them.

```
proxalyze -i proxies.txt
proxalyze -i http.lst:http -i socks.lst:socks5 -j 2048
```

## What it does

- **Declared protocols, never guessed.** Each input file declares its scheme
  (`--input FILE:socks5`); inline `socks5://user:pass@ip:port` prefixes win per
  entry. `user:pass@` credentials are exercised per protocol: `Proxy-Authorization`
  (http/https), RFC 1929 (socks5), `USERID` (socks4).
- **Unforgeable checks.** `--check-url` (default `ipv4.icanhazip.com`) is fetched
  *through* the proxy; with an HTTPS target every probe runs through a CONNECT
  tunnel into **certificate-verified** TLS, so a lying proxy cannot fake a pass.
  Both exit-IP body shapes parse: plain `1.2.3.4` and `{"origin": "1.2.3.4"}`.
- **Echo pool with self-tuning budgets.** Probes round-robin over the primary plus
  `--backup-url` echoes, each capped at `concurrency ÷ echo count` in flight —
  a single rate-limited echo would masquerade as dead proxies. Per-echo verdicts
  and startup body-shape verification are reported. `--backup-url ""` isolates
  one echo.
- **Raw output, two files, deterministic order.**
  - `out/proxies.txt` — `scheme://[user:pass@]ip:port`
  - `out/proxies.jsonl` — per survivor: `connect_ms` / `ttfb_ms` / `speed_ms`,
    `anonymity` (elite/anonymous/transparent), `exit_ip`, `asn`, `org`,
    network-class `tags` (hosting/cdn/mobile/vpn/residential-proxy, from an
    optional offline GeoLite2-ASN database auto-detected at
    `geo/GeoLite2-ASN.mmdb`)
  Auth-gated proxies are included and tagged `auth-required`.
- **Honest runtime.** Measured 15k-probe public pool: ~39s (1024 in flight).
  Workers default to 80% of available parallelism; `RLIMIT_NOFILE` is raised
  automatically; per-check budgets with zero retries; integrity counters hard-fail
  on dropped results.

## Example output

`examples/out/` holds a dummy result (RFC 5737 documentation addresses), in
canonical best-first order: anonymity class (elite → anonymous → transparent →
unjudged → auth-required), then check latency, then protocol/address:

```
$ proxalyze -i examples/sample.txt
[parse ] 1 files · 3 unique candidates (0 dupes) in 0.0s · check https://ipv4.icanhazip.com
[check ]       3/3       100%    4/s  done in   0.7s
  ...
[write ] out/proxies.txt (92 bytes) · out/proxies.jsonl (655 bytes) in 0.00s
```

`proxies.txt` — one usable line per survivor (credentials preserved where the
input had them), `proxies.jsonl` — the same proxies in the same order plus
everything the run learned: `connect_ms` / `ttfb_ms` / `speed_ms`, `anonymity`, `exit_ip`, `asn`,
`org`, network-class `tags`.

## Install

Grab a binary from [releases](../../releases) (`proxalyze-<target>.tar.gz`), or:

```
cargo install --path .
```

## Notes from the measurements behind the defaults

`--connect-timeout 2.0`: at 5s, ~76% of dead probes wait the full governor; 2.0s
keeps every observed live dial (max 1.82s) while cutting wall ~35%. 1.0s starts
clipping SYN-retransmit survivors. `-j` scales wall near-linearly until your
carrier's NAT/SYN limits bite (measured safe: 2048; beyond that false-deads).
io_uring was evaluated and rejected for this workload — it is wait-bound, not
syscall-bound (full benchmark arithmetic in the repo history).

## Development

```
cargo test                    # 15 tests, no network
cargo clippy --all-targets -- -D warnings
```

CI runs fmt/clippy/test/release-build on every push; tags `v*` publish binaries
for linux x86_64/aarch64 and macOS x86_64/aarch64.
