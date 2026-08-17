# Contributing

This is a proprietary project (see [LICENSE](LICENSE)). Contributions are
accepted only from people who have been granted access.

## Setup

```bash
git clone https://github.com/KiaroSama/Proxy-Tester.git
cd Proxy-Tester
python -m venv .venv
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # Linux/macOS
pip install -r requirements-dev.txt
```

## Before opening a pull request

```bash
python -m pytest tests/ -q
ruff check .
python main.py --need 5      # a real run still has to work
```

All three must pass. CI runs the same checks on Python 3.9 through 3.13.

## Ground rules

**Tests are offline.** Nothing in `tests/` may touch the network — the suite
runs in under a second and must stay that way. Live behaviour is verified by
running the tool.

**Every test must be able to fail.** A test that passes without exercising the
code it names is worse than no test.

**Bound everything.** Any new network operation needs a deadline. No unbounded
waits, no blind `sleep` as a substitute for a readiness check.

**Fix causes, not symptoms.** Before patching a call site, check whether the
other callers of that function have the same bug.

## Adding or changing a proxy source

Sources live in `proxy_tester/sources.py`. Do not add one you have not fetched.

A source may be added only if you have personally confirmed:

1. It returns HTTP 200.
2. It yields at least ~100 parsable proxies.
3. The repository was pushed to within the last 30 days.

State the measured proxy count and the last-push date in your pull request.
Give it a `max_items` cap — some lists are over 10 MB.

Remove a source when it 404s or drops below ~20 usable entries. If you remove
one, add its URL fragment to the guard in
`tests/test_fetching.py::test_removed_dead_sources_have_not_crept_back` so it
cannot silently return.

## Changing the health probe

The probe decides what counts as a working proxy, so changes there need
evidence, not reasoning:

- Probe endpoints must span **more than one provider**. Google `403`s many
  proxy IPs; a single-provider list produces false negatives. This is enforced
  by a test.
- A candidate that passes must genuinely **forward** traffic. Confirm against a
  third-party origin's real response body, and check that a bogus `Host` is
  *not* accepted — an endpoint answering for its own hostname will otherwise
  look like a working proxy.
- Report before/after timing and working-proxy counts for any probe change.

## Style

Match the surrounding code. Comments explain *why*, not *what*. Files stay
under ~800 lines; split by responsibility when one grows past that.

Commit messages: one short line, conventional prefix (`feat:`, `fix:`,
`chore:`, `docs:`, `refactor:`, `test:`). The diff carries the detail.

## Security

Do not open a public issue for a security problem — see
[SECURITY.md](SECURITY.md).
