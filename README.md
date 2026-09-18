# Proxy Tester

Fetch public proxies from 95 curated sources, test them concurrently, and write
the working ones to a single file — typically **15 working proxies in under two
seconds**.

```
Fetched sources: 10/10 | unique candidates: 3,604
Proxy health probe: reachability via 3 endpoint(s).
Tested 159/3604 | working=15 | need=15 | rate=128.8/s | active=0
Saved 15 working proxies to: .../output/working_proxies.txt
tested=159 | workers=1000 | timeout=6.0s | elapsed=1.69s
```

## Requirements

- Python 3.10 or newer (CI covers 3.10-3.13). `aiohttp` 3.14+ requires 3.10,
  and Python 3.9 reached end of life in October 2025.
- `aiohttp` and `python-socks` — installed automatically on first run, or
  manually with `pip install -r requirements.txt`

## Usage

```bash
python main.py
```

It asks how many working proxies you need, then saves them to
`output/working_proxies.txt`. To skip the prompt:

```bash
python main.py --need 100
```

On Windows you can double-click `run.ps1` instead.

### Common options

| Option | Default | What it does |
|---|---|---|
| `--need N` | prompt | How many working proxies to collect |
| `-o, --output PATH` | `output/working_proxies.txt` | Where to write results |
| `--workers N` | `1000` | Concurrent proxy checks |
| `--timeout S` | `6.0` | Per-proxy timeout in seconds |
| `--stability-checks N` | `1` | Probe rounds a proxy must pass to count |
| `--require-different-ip` | off | Keep only proxies that provably change your public IP |
| `--test-url URL` | see below | Custom probe endpoint (repeatable) |
| `--vies-check` | off | Use the EU VIES VAT API as the probe (slow, see below) |
| `--list-sources` | — | Print the source catalog and exit |

Run `python main.py --help` for the full list.

## How a proxy is judged working

By default each candidate must complete one real request through the proxy to
the first of these endpoints that answers:

1. `http://cp.cloudflare.com/generate_204`
2. `http://www.gstatic.com/generate_204`
3. `http://example.com/`

They are tiny, need no TLS, and return almost no body. Provider diversity is
deliberate: Google returns `403` to many known proxy IPs, so a Google-only probe
list would reject proxies that actually work.

### The `--vies-check` mode

`--vies-check` replaces the reachability probe with a full VAT validation
against the EU VIES API. Use it only when a proxy must be proven to work
against VIES specifically — it is dramatically slower and aggressively rate
limited.

Measured on the same machine and source set, collecting 15 proxies:

| Probe | Elapsed | Candidates burned |
|---|---|---|
| Reachability (default) | **1.69 s** | 159 |
| `--vies-check` | 12.59 s | 3,201 |

The VIES path needed ~20x more candidates because the API throttles bulk
requests, so most failures were rate limiting rather than dead proxies.

## Output

Results go to `output/`, which is git-ignored. One proxy per line, written and
flushed the moment it is found, so an interrupted run still leaves usable
results:

```
http://103.21.244.106:80
socks5://192.0.2.10:1080
socks4://198.51.100.7:4145
```

## Sources

95 lists across HTTP, SOCKS4 and SOCKS5, each health-checked before a full
download so a dead source costs one small range request rather than a timeout.
The catalog was verified on 2026-08-17; lists that had 404'd or gone stale were
removed and twelve actively-updated ones added.

`python main.py --list-sources` prints the current catalog.

Some sources publish `scheme://IP:PORT` and some zero-pad their octets
(`001.224.3.122`); both are parsed correctly.

## Project layout

```
main.py                  entry point
proxy_tester/
  cli.py                 argument parsing and program flow
  colors.py              ANSI palette (leaf module, depends on nothing)
  constants.py           tunable defaults and probe endpoints
  models.py              SourceSpec, ProxyCandidate, ProbeTarget, SourceResult
  sources.py             the curated source catalog
  parsing.py             raw text -> validated candidates
  fetching.py            source downloads, dedup, queue ordering
  probes.py              HTTP/SOCKS probes and the VIES check
  runner.py              worker pool, result writer, run orchestration
  runtime.py             dependency loading, fd limits, event-loop filtering
  terminal.py            headers, colour output, live progress line
tests/                   283 tests, no network required
```

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
ruff check .
```

The test suite is offline and runs in well under a second. Live behaviour is
verified by running the tool itself.

## Legal

Proprietary — see [LICENSE](LICENSE). Third-party proxy lists and the proxy
servers they reference are not owned or controlled by this project. You are
responsible for complying with the terms of any proxy or service you use.

## Donate

If this project helps you, donations are appreciated.

| Currency | Network | Address |
| --- | --- | --- |
| Bitcoin (BTC) | Bitcoin | `bc1qmth5m03pu5hujw5xw5jmywam3jj3sqwqupesdt` |
| USDT, BNB, USDC, etc. | BEP20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| USDT, TRX, USDC, etc. | TRC20 | `TWBA3xFTqgZAeAYMxqo85xWnzvty3DcAhw` |
| Ethereum (ETH) | ERC20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| TON | TON | `UQCN8Umo_OfOWqImZetQsrNStPcmLkMAKajFyiCOhso23NDb` |
| Litecoin (LTC) | LTC | `ltc1qntqnnrunadurnw4cshv3qgspywrueyyeyngwuy` |
| Solana (SOL) | Solana | `7B2wkczUjmkDhETwQuknBL8sUsbuV7nErxc317TmQuwR` |
| Polygon (POL) | Polygon | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
