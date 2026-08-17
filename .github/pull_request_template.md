## What this changes

<!-- One or two sentences. -->

## Why

## Verification

<!-- Tick only what you actually ran. -->

- [ ] `python -m pytest tests/ -q`
- [ ] `ruff check .`
- [ ] `python main.py --need 5` (a real run still works)

Paste the relevant output:

```
```

## If this touches proxy sources

- [ ] I fetched every URL I added and it returned HTTP 200
- [ ] Measured proxy count: <!-- N -->
- [ ] Repository last pushed: <!-- YYYY-MM-DD, must be within 30 days -->
- [ ] Removed sources are covered by the guard test so they cannot creep back

## If this touches the health probe

- [ ] Probe endpoints still span more than one provider
- [ ] A passing candidate was confirmed to genuinely forward traffic
      (real third-party body, and a bogus `Host` is rejected)
- [ ] Before/after timing and working-proxy counts:

```
```

## Anything reviewers should know

<!-- Known gaps, follow-ups, things you deliberately left out. -->
