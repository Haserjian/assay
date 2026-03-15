# Passport Referee Gallery

Seeded reference artifacts demonstrating the passport lifecycle.
All artifacts are deterministic and regenerable.

## Regeneration

```bash
python3 docs/passport/generate_gallery.py --output-dir docs/passport/gallery
```

## Artifacts

| File | Purpose |
|------|---------|
| `passport_v1.json` | Signed passport (AcmeSaaS, R0 unsigned draft → signed) |
| `passport_v1.html` | Self-contained HTML render with verification status |
| `xray_v1.html` | X-Ray diagnostic report: grade, findings, improvement path |
| `challenge_*.json` | Signed challenge receipt (coverage gap) |
| `passport_v2.json` | Signed passport v2 (adds admin override coverage claim) |
| `supersession_*.json` | Signed supersession receipt linking v1 → v2 |
| `trust_diff.html` | Trust Diff report showing v1 → v2 changes |

## Lifecycle demonstrated

```
mint v1 → sign → render → xray → challenge → verify (CHALLENGED)
→ mint v2 (address gap) → sign → supersede v1→v2 → diff
```

## What this is

A worked example using seeded, deterministic reference artifacts.
Every artifact is inspectable. Every governance event is signed.
The gallery regenerates cleanly from `generate_gallery.py`.

## What this is not

- Not a scan of arbitrary external trust surfaces
- Not evidence from real third-party systems
- Not a claim about generalized trust analysis

The gallery demonstrates the passport lifecycle on controlled inputs.
Broader ingestion and scanning are future scope.
