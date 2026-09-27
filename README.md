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
  (`--input FILE:socks5`); inline `http://`, `https://`, `socks4://`, or
  `socks5://` prefixes win per entry. `user:pass@` credentials are exercised
  per protocol: `Proxy-Authorization` (http/https), RFC 1929 (socks5), and
  `USERID` (socks4).
- **Checks through the proxy.** `--check-url` (default
  `https://ipv4.icanhazip.com`) is fetched through each proxy. For HTTPS echo
  targets, HTTP and HTTPS proxies use HTTP CONNECT, then certificate-verified
  TLS to the echo origin. SOCKS4 and SOCKS5 instead establish their native
  tunnel first (a SOCKS4 connect request or SOCKS5 CONNECT command, not HTTP
  CONNECT), then run the same verified origin TLS through that tunnel. Thus a
  proxy cannot forge the exit-IP body without a valid origin certificate. Plain
  `1.2.3.4`, `{"origin": "1.2.3.4"}`, and `{"ip": "1.2.3.4"}` echo bodies are
  accepted. Selecting `http://` instead emits a startup warning because the
  response is not certificate-verified.
- **Echo pool with self-tuning budgets.** Probes round-robin over the primary
  and `--backup-url` echoes. Each healthy echo gets a per-target in-flight cap;
  startup verifies every echo's body shape and reports per-echo live, TLS-fail,
  permit-wait, and target-error counts in the summary. `--backup-url ""` selects
  only the primary; when mixed with real URLs, empty values are ignored and the
  real URLs remain active.
- **Raw output, two files, deterministic best-first order.**
  - `out/proxies.txt` — `scheme://[user:pass@]ip:port`
  - `out/proxies.jsonl` — one record per live or auth-required proxy, including
    `last_checked`, `speed_ms`, `connect_ms`, `ttfb_ms`, `anonymity`, `exit_ip`,
    `asn`, `org`, `source`, `country`, and network-class `tags`
    (`hosting`, `cdn`, `mobile`, `vpn`, `residential-proxy`, and
    `auth-required`).
  Records sort by anonymity/rank (elite → anonymous → transparent → live but
  unjudged → auth-required), then `speed_ms`, protocol, and address. Whenever
  outputs are written, each file gets mode `0600` on Unix and is atomically
  replaced via a unique temp file plus rename. A run with zero candidates and no
  carried-forward records skips writing entirely and leaves existing outputs
  untouched, so empty/comment-only/hostname-only input cannot destroy a previous
  good pool.
- **Offline location facts do not affect judgment.** ASN/network tags and the
  optional raw `country` ISO code come from operator-provided GeoLite2 databases.
  ASN lookup is optional; country lookup is emitted only when available. Country
  location never affects anonymity classification, tags, or ranking.
- **Honest runtime.** Measured 15k-probe public pool: ~39s (1024 in flight).
  Workers default to 80% of available parallelism; `RLIMIT_NOFILE` is raised
  automatically; checks have no retries; integrity checks hard-fail if probe or
  output-record counts do not match expectations.

Probe statuses are `live`, `auth-required`, `tls-fail`, `socks-rejected`,
`tcp-alive`, and `dead`. Live anonymity classes are `elite`, `anonymous`, and
`transparent`; a live proxy without a trustworthy exit-IP comparison is counted
and ranked separately as `unjudged`. Auth-required proxies remain in the output
and carry the `auth-required` tag.

## Input behavior

Pass `-i -` to read the list from stdin. A directory input is scanned
non-recursively for `.txt`, `.lst`, and `.csv` extensions, case-insensitively;
matching files are processed in sorted path order. A line whose first
non-whitespace character is `#` or `;` is ignored entirely, so commented-out
proxies are never dialed. These are whole-line comments, not inline-comment
support.

Supported line forms include:

```text
ip:port
ip,port
ip:port:user[:pass]
scheme://ip:port
scheme://user:pass@ip:port
user:pass@ip:port
[ipv6]:port
cidr/16..32:port
```

Zero-padded IPv4 octets are normalized. Hostname lines are counted and reported
separately, but are not dialed by default. Pass `--resolve-hostnames` to resolve
them at load time with one DNS lookup per unique `host:port`; when the flag is
off, each affected input reports how many hostname lines were skipped.

Credential case is preserved, but each input form has its own exact character
set:

- scheme-prefixed and `user:pass@host:port` forms accept ASCII alphanumerics
  plus `. : / @ - _ [ ] + = % ! # $ & * ( ) ~`; and
- bare four-field `ip:port:user:pass` accepts ASCII alphanumerics plus
  `. : / [ ] , - _ + = % ! # $ & * ( ) ~`.

Whitespace, semicolons, and quote characters are unsupported inside credentials
in both forms and must be re-encoded at the proxy. A comma is accepted in the
remainder of a bare four-field password, but not in a scheme-prefixed or `@`
form. Any character outside the applicable set can split the token and silently
rewrite or truncate the credential, so re-encode it at the proxy.

Separate proxy entries with whitespace or newlines. A comma separates the two
parts of a strict `ip,port` pair, but is credential data in a four-field quad:
`1.2.3.4:8080:user:p,ass` keeps `p,ass` intact, and a second proxy glued after
that quad with no whitespace would also be consumed as password data.

## Incremental and CI modes

- `--skip-recent SECONDS` reuses a matching record from the previous
  `<out>/proxies.jsonl` when its `last_checked` is at most `SECONDS` old. Only
  stale candidates are probed. Fresh records are carried forward with their
  original `last_checked`, timings, `source`, `country`, and other data; the
  integrity summary reports `reused {n} fresh · probed {m}`. `0` disables reuse.
- `--min-live N` exits with code 3 after reporting and writing outputs when fewer
  than `N` live proxies were found, including carried-forward live records.
  `N=0` disables the gate.

## Example output

This is a real transcript from:

```
cargo run --quiet -- -i examples/sample.txt
```

The sample contains RFC 5737 documentation addresses, so an honest run probes 3
candidates, finds 0 live, and legitimately rewrites the output files as
0-byte results. This is different from the no-candidates/no-reused-records path,
which skips writing and preserves existing files. Worker counts, GeoLite2
availability, timings, and rates vary by machine and network, so the captured
numbers below are not promises:

```text
proxalyze 1.0.0 · workers 11 (auto 80%) · geo asn+city
[parse ] examples/sample.txt                         3 kept
[parse ] 1 files · 3 unique candidates (0 dupes) in 0.0s · check https://ipv4.icanhazip.com
[check ]       3/3       100%    1.4/s  done in   2.1s
[write ] ./out/proxies.txt (0 bytes) · ./out/proxies.jsonl (0 bytes) in 0.00s
[done  ] 2.7s total (parse 0.00 · check 2.7 · write 0.00)
summary
  verdict   live 0 (elite 0 · anonymous 0 · transparent 0 · unjudged 0) · auth 0 · tls-fail 0 · socks-rejected 0 · tcp-alive 0 · dead 3
  echoes    cap per target
            https://ipv4.icanhazip.com           cap  342 · live     0 · tls-fail     0 · permit-waits 0 · target-err 0
            https://api.ipify.org                cap  342 · live     0 · tls-fail     0 · permit-waits 0 · target-err 0
            https://checkip.amazonaws.com        cap  342 · live     0 · tls-fail     0 · permit-waits 0 · target-err 0
  inputs
            examples/sample.txt                  checked       3 · live     0 (0.0%) · auth-only      0
  integrity 3/3 results ✓ · 0 reportable · 0 records ✓ · reused 0 fresh · probed 3
```

`examples/out/` is a separate **illustrative dummy, not a captured live run**.
Those records use RFC 5737 addresses and dummy timing/metadata to demonstrate
the output shape and best-first ordering; they are not expected from the sample
command above.

Each `proxies.jsonl` line has:

- always-present fields: `proxy`, `type`, `last_checked`, `speed_ms`,
  `connect_ms`, `tags` (an array, possibly empty), and `source` (the input file,
  or `-` for stdin; legacy or foreign prior JSONL rows without `source` decode
  as `"unknown"` and can be carried forward verbatim by `--skip-recent`);
- always-present fields that may be JSON `null`: `ttfb_ms`, `anonymity`, and
  `exit_ip`; and
- fields omitted entirely when unavailable: `asn`, `org`, and `country`. The
  `country` value is an ISO code emitted only as a raw fact when a City database
  and lookup result are available.

## GeoLite2 databases

Databases are optional and detected in this order:

```text
geo/GeoLite2-ASN.mmdb
~/.local/share/proxalyze/GeoLite2-ASN.mmdb

geo/GeoLite2-City.mmdb
~/.local/share/proxalyze/GeoLite2-City.mmdb
```

ASN data supplies `asn`, `org`, and network-class tags. City data supplies only
the raw `country` fact. If City data or a lookup result is unavailable, the
`country` field is absent.

## Install

Grab a binary from [GitHub releases](https://github.com/rianilham28/proxalyze/releases),
or install from a checkout:

```
cargo install --path . --locked
```

License: MIT (see [LICENSE](LICENSE)).

## Notes from the measurements behind the defaults

`--connect-timeout 2.0`: at 5s, ~76% of dead probes wait the full governor; 2.0s
keeps every observed live dial (max 1.82s) while cutting wall time ~35%. 1.0s
starts clipping SYN-retransmit survivors. `-j` scales wall time near-linearly
until carrier NAT/SYN limits bite (measured safe: 2048; beyond that, false-dead
proxies). Values below 16 are honored exactly; the 16-per-target floor applies
only when `-j` is at least 16. io_uring was evaluated and rejected for this
workload — it is wait-bound, not syscall-bound (full benchmark arithmetic is in
the repository history).

`--timeout` and `--connect-timeout` must be finite values greater than zero that
convert to a non-zero `Duration`; invalid values produce a clean configuration
error. `speed_ms` measures proxy dial plus request time and deliberately excludes
time waiting in the echo endpoint's permit queue, so echo throttling is not
misreported as proxy latency.

## Development

```
cargo test --locked             # 118 tests, no network (unit + hermetic localhost-mock e2e)
cargo clippy --all-targets -- -D warnings
```

CI runs formatting, clippy, locked tests, release builds, MSRV checks, and an
additional Linux aarch64 cross-build for pushes to `main` and pull requests.
Tags matching `v*` publish release archives for Linux x86_64/aarch64 and macOS
x86_64/aarch64.
