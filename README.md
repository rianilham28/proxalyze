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
    `asn`, `org`, `source`, `country`, network-class `tags`
    (`hosting`, `cdn`, `mobile`, `vpn`, `residential-proxy`, `auth-required`,
    plus the opt-in `stable`, `keep-alive`, and `chunked-post`).
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
- **Write-stage filtering.** Six flags shape the surviving pool after ranking
  and validation, in this order: `--require-tag` (record must carry ALL of the
  listed tags), `--exclude-tag` (drop on ANY listed tag; exclude wins over
  require), `--max-speed MS`, `--min-anonymity elite|anonymous` (a rank floor:
  `elite` keeps only elite, `anonymous` also keeps anonymous and drops
  transparent/unjudged/auth-required), `--country FR,DE` (case-insensitive ISO
  list — a record with no `country` fact is dropped, unknown is not allowed),
  and `--keep-top N` (truncate the ranked head, so it sees the survivors).
  `--require-tag`/`--exclude-tag` are repeatable and validate against the known
  tag vocabulary, so a typo is a clean config error. Whenever any filter is
  active the summary gains `filters kept N · dropped M`.
- **Output extensions.** `--csv` also writes `out/proxies.csv` (RFC 4180, one
  row per record), `--emit curl|playwright` (repeatable) writes
  `out/proxies.curl` and/or `out/proxies.playwright` renderer files in the same
  best-first order, and `--history` appends a run-stats row to
  `<out>/history.jsonl` — run stats plus the pool delta (`pool_size`, `added`,
  `removed`) against the previous `proxies.jsonl`. History is append-only
  (mode `0600`): a malformed or torn prior line is skipped and counted, never
  rewritten.
- **Stability across runs.** `--stable-after N` (N > 0) chains a `runs_live`
  count off the previous pool and adds the `stable` tag once a record has
  survived N consecutive live runs. A record absent from the previous pool
  resets its chain to 1, and a record carried forward by `--skip-recent`
  increments exactly once. `0` (the default) never tags and strips a carried
  `stable` tag, so the flag can be turned off without leaving stale tags.
- **Throughput sampling.** `--probe-throughput` (which REQUIRES
  `--throughput-url URL`, or the run fails configuration) times a bounded
  sample download through each live proxy and records `kbps` in kilobits per
  second — `bytes × 8 ÷ elapsed_ms`, i.e. `bytes × 8 × 1000 / elapsed_ms` — alongside
  a `speed_tier`: `fast` at ≥ 2048 kbps, `mid` at ≥ 512, `slow` below. The
  sample opens a **second connection through the same proxy** — a SOCKS tunnel
  is one-destination, so the already-open check tunnel cannot carry it — and
  reads at most 256 KiB inside the remaining time budget, so a fast origin
  cannot inflate the figure. Reaching the 256 KiB cap is the normal success
  path, and a body smaller than the cap still measures, so an ordinary
  `speed.bin` is tiered normally. Only a transport error while reading the
  body, or an exhausted time budget, yields no figure: the proxy stays live,
  and the record carries neither `kbps` nor `speed_tier`.
- **Capability probes.** `--probe-capabilities` sends two follow-ups on the
  live connection and tags `keep-alive` (a second plain GET on the same
  socket) and `chunked-post` (a chunked request body the origin did not
  reject). A tag is earned only when the follow-up body reads to completion —
  a socket that closes mid-body never earns `keep-alive`. The probe cost is
  subtracted from the reported timing, and a failure only omits the tags; it
  never changes the verdict.

All of these are **default-off**: a run with no new flags behaves exactly as
before — the same two output files, the same transcript lines, and the same
tags. The one visible change is that every `proxies.jsonl` record now also
carries the `runs_live` key.

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
  than `N` live proxies survive — counted **after** the write-stage filters and
  excluding `auth-required` records, so a filter that empties the pool fails
  the gate rather than passing it. Carried-forward live records count here
  too, alongside freshly probed ones. `N=0` disables the gate.
- `--stable-after N` chains `runs_live` across runs and tags `stable` at N
  consecutive live runs, so `--require-tag stable` can feed a `--min-live`
  CI gate that only accepts proven survivors. `--keep-top N` and the other
  filters are applied first; `--min-live` sees only what survived them.

A typical CI gate, plus the optional output shapes:

```
proxalyze -i proxies.txt --stable-after 3 --require-tag stable --min-live 10
proxalyze -i proxies.txt --csv --emit curl --history --keep-top 500
proxalyze -i proxies.txt --probe-throughput --throughput-url https://host/speed.bin
```

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
  `connect_ms`, `tags` (an array, possibly empty), `runs_live` (consecutive live
  runs observed across the history, including this one; legacy rows without it
  decode as `1`), and `source` (the input file, or `-` for stdin; legacy or
  foreign prior JSONL rows without `source` decode as `"unknown"` and can be
  carried forward verbatim by `--skip-recent`);
- always-present fields that may be JSON `null`: `ttfb_ms`, `anonymity`, and
  `exit_ip`; and
- fields omitted entirely when unavailable: `asn`, `org`, `country`, `kbps`,
  and `speed_tier`. The `country` value is an ISO code emitted only as a raw
  fact when a City database and lookup result are available. `kbps` is the
  measured throughput in kbit/s and `speed_tier` its bucket — `fast` at
  ≥ 2048 kbps, `mid` at ≥ 512, `slow` below — both present only when
  `--probe-throughput` ran and the sample produced a figure. A body smaller
  than the 256 KiB cap is a normal measured sample, not a truncated one; only a
  transport error while reading the body, or an exhausted time budget, leaves
  the record live with neither key. A `speed_tier` outside `fast`/`mid`/`slow` is
  version skew, not a free-form label.

`tags` is a closed vocabulary, interned on decode: `hosting`, `cdn`, `mobile`,
`vpn`, `residential-proxy`, `auth-required`, `stable`, `chunked-post`, and
`keep-alive`. `--require-tag` and `--exclude-tag` validate against it. The
first six come from the run itself; `stable` from `--stable-after`, and
`keep-alive`/`chunked-post` from `--probe-capabilities`.

With `--history`, `<out>/history.jsonl` gains one appended row per run that
actually rewrote the pool: a zero-candidate run with nothing carried forward
skips the append, because the on-disk pool is untouched and a row would read
as "everything removed". Each row carries `run_ts` (epoch seconds), the same
verdict counters the summary prints (`live`, `elite`, `anonymous`,
`transparent`, `unjudged`, `auth`, `tls_fail`, `socks_rejected`, `tcp_alive`,
`dead`, `median_speed_ms`), the filter outcome (`kept`, `dropped`), and the
pool delta against the previous `proxies.jsonl` (`pool_size`, `added`,
`removed`). Every field is always written, so a consumer never has to
distinguish "absent" from "zero".

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
cargo test --locked             # 182 tests (149 unit + 33 hermetic localhost-mock e2e), no network
cargo clippy --all-targets -- -D warnings
```

CI runs formatting, clippy, locked tests, release builds, MSRV checks, and an
additional Linux aarch64 cross-build for pushes to `main` and pull requests.
Tags matching `v*` publish release archives for Linux x86_64/aarch64 and macOS
x86_64/aarch64.
