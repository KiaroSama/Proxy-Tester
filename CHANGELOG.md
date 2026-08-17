# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [17.1.0] - 2026-08-17

### Changed

- Terminal output now follows the same theme as FFmWiz: a leaf
  `proxy_tester/colors.py` holding a `Color` palette of 256-colour and
  truecolour codes with semantic names, and `terminal.py` gaining
  `separator_line`, `print_header` and `print_pair`. Runs are now divided into
  centred `SOURCES` / `TESTING` / `RESULTS` sections with gray labels and
  coloured values, instead of one flat stream of lines.
- Colour is still suppressed when stderr is redirected, so piped output and log
  files stay free of escape codes.

### Added

- 28 tests for the palette and layout helpers, including guards that every
  defined colour is actually referenced, that no two names share one code, and
  that every opened escape sequence is closed. 283 tests total.

### Dependencies

Merged five Dependabot updates after verifying each one:

- `actions/checkout` 5 → 7 and `actions/setup-python` 6 → 7 (both confirmed to
  be the current official releases).
- `aiohttp` floor → 3.14.3 and `pytest` floor → 9.1.1, matching the versions
  the live end-to-end run was verified against.
- `ruff` floor → 0.16.3, verified clean against the project at that exact
  version before merging.

The GitHub Actions bumps could not be exercised, because Actions is blocked on
account billing for this repository — see the note in the README.

## [17.0.0] - 2026-08-17

The single-file script became a package, and the health probe changed.

### Changed

- **Reachability is now the default health probe.** Previously every candidate
  was validated by a full VAT lookup against the EU VIES API. Collecting 15
  proxies took 12.59 s and burned 3,201 candidates; it now takes 1.69 s and 159
  candidates. The VIES behaviour is still available via `--vies-check`.
- Default output moved to `output/working_proxies.txt`; the directory is
  git-ignored.
- Default workers lowered from 3000 to 1000. The old figure aimed 3000
  concurrent TLS connections at one rate-limited government API and throttled
  itself; the current probe endpoints are CDN-backed.
- Default per-proxy timeout lowered from 10 s to 6 s, matching the faster probe.
- Split the 2,795-line `Proxy Tester.py` into a `proxy_tester/` package: `cli`,
  `constants`, `models`, `sources`, `parsing`, `fetching`, `probes`, `runner`,
  `runtime`, `terminal`.
- Upgraded to `aiohttp` 3.14.3 and `python-socks` 3.0.0. The 3.x major was
  verified against the live HTTP, SOCKS4 and SOCKS5 paths before pinning.

### Fixed

- `run.ps1` launched `proxy_tester_V17.py`, which does not exist — the launcher
  could never start. It now runs `main.py`.
- `probe_reachability()` was dead code: `test_candidate()` called the VIES probe
  directly, so `--test-url` silently did nothing and `args.probe_targets` was
  computed and discarded. Both are now wired up and used.
- `worker_loop()` leaked the active-worker count when a probe raised; the
  decrement now happens in a `finally` block, so the `active=` figure no longer
  drifts upward over a long run.
- Removed an unreachable branch in `normalize_host()` that re-checked an IPv4
  pattern already handled above it.

### Added

- Probe endpoints now span more than one provider. Google returns `403` to many
  known proxy IPs, so the previous Google-heavy list rejected proxies that
  actually worked. Enforced by a test.
- 12 new proxy sources, each verified to return HTTP 200 with 300+ parsable
  proxies and to have been pushed within 30 days: noctiro, TuanMinPay,
  hproxy-com, Anonym0usWork1221, dinoz0rg, databay-labs.
- 255 offline tests covering parsing, dedup and queue ordering, probe target
  construction, timeout bounds, and CLI clamping.
- CI across Python 3.9-3.13, Dependabot, issue and pull request templates.
- `LICENSE`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`.
- `--version` flag.

### Removed

- 12 dead sources. HTTP 404: `iplocate_https`, `firmfox_*` (4), `mmpx12_*` (3).
  Stale or near-empty: `roosterkid_socks5` (6 entries), `shiftytr_https` (13),
  `sunny9577_socks4` (18), `prxchk_socks5` (10). A test prevents them from
  silently returning.

### Note

Sources that publish `scheme://IP:PORT` rather than bare `IP:PORT` were checked
and **kept** — the parser handles that shape, and treating them as broken would
have discarded working lists such as proxifly, Argh94, and gfpcom.

---

## Earlier versions

Versions 0 through 16 were developed as single-file scripts between
2026-02-04 and 2026-04-26 and are preserved in this repository's commit history.
Highlights:

- **V16** (2026-04-26) - reachability-only probe variant
- **V15** (2026-04-26) - tail drain handling on early stop
- **V14** (2026-04-26) - stability rounds for more reliable results
- **V13** (2026-04-26) - quieten benign Windows proactor warnings
- **V12** (2026-04-26) - strict IP-change verification mode
- **V11** (2026-04-23) - VIES VAT validation as proxy health probe
- **V10** (2026-04-11) - interleave candidates across sources
- **V9** (2026-04-11) - priority-ordered source batching
- **V8** (2026-03-09) - live progress line with test rate
- **V7** (2026-03-09) - bound per-candidate probe timeouts
- **V6** (2026-03-09) - incremental save of working proxies
- **V5** (2026-03-09) - source health pre-check before download
- **V4** (2026-03-09) - trim source list and probe logic
- **V3** (2026-03-09) - simplify candidate parsing
- **V2** (2026-03-09) - add socks4/socks5 support
- **V1** (2026-03-09) - async testing with multiple proxy sources
- **V0** (2026-02-04) - initial public proxy fetcher and tester
