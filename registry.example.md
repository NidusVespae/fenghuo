---
title: Example asset registry
fenghuo-pause: off
---

# Example Asset Registry

> This is a **sample** registry for 烽火. Copy it to `registry.md` (or point
> `FENGHUO_REGISTRY` at your own file) and edit the watchlist below to match the
> software that actually runs on *your* machines.
>
> The watchlist is the scope. 烽火 reads the first Markdown table under the
> `## KEV watchlist` heading and nothing else. Keep that heading exact.

## KEV watchlist

> **Columns.** `vendor` must exactly match the KEV feed's `vendorProject`
> (case-insensitive). `product` is a regex alternation (`|`-separated) matched
> against the KEV `product` field — escape the pipes as `\|` so Markdown keeps
> them in one cell. `asset`, `exposure`, and `patch path` are yours; `exposure`
> drives the P1/P2/P3 severity (use words like `internet-facing`, `lan`,
> `tunnel`, `outbound`, or `local`).
>
> Rows containing `<placeholders>` are skipped and reported, never guessed.
> Verify each vendor/product string once against the live feed with
> `python3 fenghuo.py --vendors <name>`.

| vendor | product | asset | exposure | patch path |
|---|---|---|---|---|
| Apple | iOS\|iPadOS\|WebKit\|Multiple Products | phones / tablets | every network | vendor update |
| Microsoft | Windows\|Windows Server | workstations | lan | Windows Update |
| Linux | Kernel | servers | internet-facing | apt/yum + reboot |
| OpenBSD | OpenSSH | servers | internet-facing | apt/yum |
| OpenSSL | OpenSSL | servers | internet-facing | apt/yum + service restart |
| Google | Chrome\|Chromium | workstations | internet-facing | browser update |
| Mozilla | Firefox | workstations | internet-facing | browser update |
| Fortinet | FortiOS\|FortiGate | edge firewall | internet-facing | vendor firmware |

---

## How to pause

To halt runs without touching your scheduler, set the frontmatter flag at the
top of this file to `on`:

```
fenghuo-pause: on
```

Set it back to `off` (or delete the line) to resume. The flag is read from the
frontmatter only — this example in the body does nothing — and it is fail-safe:
if it is missing, malformed, or ambiguous, 烽火 runs anyway.
