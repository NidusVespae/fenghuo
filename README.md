# 烽火 Fēnghuǒ — a CISA KEV beacon

**烽火** ("beacon fire" — the signal towers that carried warnings along the Great
Wall) is a small, dependency-free early-warning tool. It pulls the [CISA Known
Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
filters it against a watchlist **you** define — the software that actually runs
on your machines — and writes one Markdown threat note per new hit with a
deterministic, evidence-bound assessment.

It's a watcher, not a scanner. It fetches one public JSON file over HTTPS and
writes Markdown. It touches no host, needs no account, no API key, no token.

> **A KEV hit means the bug is being exploited in the wild. It does _not_ mean
> your asset is vulnerable.** Every note ends with a verification step to run on
> the asset. 烽火 never claims patched/unpatched status — that's your call, on
> the box.

---

## Why

The KEV catalog is the "patch this now, it's actually being used" list. But it's
~1,700 entries across every vendor on earth, and almost none of them are yours.
烽火 turns that firehose into a short, prioritized stream of *only the CVEs that
touch software you actually run* — delivered as plain Markdown you can drop in a
notes vault (Obsidian, etc.), a wiki, or a repo.

## Features

- **Watchlist-driven scope.** Your watchlist lives in a Markdown "registry" file.
  It's the authorization boundary, read at runtime — never hard-coded. A missing
  or malformed watchlist aborts with `SCOPE UNCONFIRMED`: a missing reading is
  never an all-clear.
- **Deterministic severity.** P1/P2/P3 is derived from the matched asset's
  exposure and whether the CVE is ransomware-linked — not a guess, and the note
  cites the field it rested on.
- **Operator pause flag.** One line in the registry frontmatter halts runs
  without touching your scheduler. Fail-safe toward *running* — a typo can never
  take the beacon dark. (See below.)
- **Fail loud.** Fetch error, TLS failure, feed schema drift, unreadable scope —
  each is a named, logged failure, never a silent empty result. TLS verification
  is always on.
- **A reading even when quiet.** Every run appends one line to a heartbeat log,
  so "nothing new" is a recorded reading, not silence.
- **Standard library only.** Python 3.8+. No `pip install`. Runs on a server, a
  laptop, or on iOS in [Pythonista](http://omz-software.com/pythonista/).

## Quick start

```bash
git clone https://github.com/NidusVespae/fenghuo.git
cd fenghuo
cp registry.example.md registry.md        # then edit the watchlist to match your kit
python3 fenghuo.py                         # interactive console
```

First run records a **baseline** (everything currently matching is marked seen,
summarized in one backlog note). After that, each run writes notes only for
*new* hits and amends notes whose KEV entry changed (due date, ransomware flag).

### Headless / scheduled

```bash
python3 fenghuo.py --auto     # prints one line, exit code != 0 on failure
```

Point `cron` or a systemd timer at that. Example units are in [`examples/`](examples/).
Weekly is the recommended cadence — KEV due dates commonly run ~3 weeks, so a
monthly pull can surface a hit after its due date has already passed.

### Other commands

```bash
python3 fenghuo.py --pause-state          # print current pause state
python3 fenghuo.py --vendors fortinet     # list live-feed vendor/product strings
python3 fenghuo.py --cve CVE-2024-3400    # re-assess one CVE against your watchlist
```

## The registry

Your watchlist is a Markdown table under a `## KEV watchlist` heading. See
[`registry.example.md`](registry.example.md) for the full format and column
rules. The short version:

| vendor | product | asset | exposure | patch path |
|---|---|---|---|---|
| OpenSSL | OpenSSL | servers | internet-facing | apt + service restart |

- `vendor` — exact match (case-insensitive) on the KEV `vendorProject`.
- `product` — a regex alternation (`Foo\|Bar`) matched against KEV `product`.
- `exposure` — drives severity (`internet-facing`, `lan`, `tunnel`, `outbound`, `local`).

Verify each vendor/product string once against the live feed
(`--vendors <name>`); a wrong string fails silently as zero matches.

## Pausing

Add one line to your registry's YAML frontmatter:

```yaml
---
fenghuo-pause: on      # 'off' or delete the line to resume
---
```

- Read from the **frontmatter only** — a how-to example in the document body
  (like this one) can't arm it.
- **Fail-safe:** missing, unreadable, malformed, or ambiguous all **run** and say
  why. The beacon never goes dark on a typo.
- A paused run no-ops and logs `PAUSED by operator` to the heartbeat log. Your
  scheduler is never touched.

## Configuration

All optional — sane defaults apply:

| env var | default | meaning |
|---|---|---|
| `FENGHUO_REGISTRY` | `~/fenghuo/registry.md` | your watchlist file |
| `FENGHUO_NOTES_DIR` | `~/fenghuo/notes` | where threat notes are written |
| `FENGHUO_STATE` | `~/fenghuo/state.json` | seen-CVE state |
| `FENGHUO_CADENCE` | `weekly` | `weekly` or `monthly` (staleness alarm only) |
| `FENGHUO_AGENT` | `fenghuo` | name stamped into note frontmatter |

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

烽火 is an informational tool. It reports public KEV data against a list you
maintain. It does not determine whether your systems are vulnerable, and it is
not a substitute for patch management, vulnerability scanning, or professional
judgment. Verify every finding on the asset before acting.
