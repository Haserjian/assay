# Changelog

All notable changes to Assay are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [1.17.0] - 2026-03

### Added
- Decision Receipt v0.1.0 schema, validator, and CLI (`assay decision-receipt validate`)
- CLI validator and buyer-facing example for Decision Receipts
- Adversarial tests: missing-file and base64 signature mutation
- Release-truth CI workflow (Python 3.9-3.12, ubuntu + macOS)

### Fixed
- Python 3.9 compatibility: future annotations in commands.py
- CI YAML indentation bug in release-truth workflow
- Regulatory wording on landing page (Article 12 characterization)
- Final CTA on landing page aligned with golden path (`assay try`)

### Changed
- README top block rewritten: headline, Run/Prove/Promote, exit codes, scan stat
- Landing page hero: eyebrow/headline/consequence hierarchy
- Browser verifier version updated to v1.17.0
- Scan study stat made precise to sample size

## [1.16.0] - 2026-02

### Added
- Passport lifecycle: mint, sign, verify, render, challenge, supersede, diff, x-ray
- MCP Notary Proxy with policy engine (audit/enforce modes)
- Golden path: `assay try` as 15-second first-contact demo
- CLI authority demotion: 8 visible commands, 31+ hidden
- VendorQ workflow: ingest, compile, verify, export, lock
- Reviewer packet renderer with gallery snapshot tests
- Evidence Readiness Score (`assay score`)
- CI gate generation (`assay ci init github`)

### Fixed
- Windows compatibility for `assay try` and proof pack byte handling
- Demo-challenge directory handling for SHA256SUMS

## [1.15.0] - 2026-01

### Added
- Initial PyPI release (`pip install assay-ai`)
- Core evidence compiler: scan, run, verify-pack
- Ed25519 signing with local keystore
- Five integrations: OpenAI, Anthropic, Google Gemini, LiteLLM, LangChain
- Completeness contracts and coverage checking
- Proof pack format: receipt_pack.jsonl, pack_manifest.json, pack_signature.sig
