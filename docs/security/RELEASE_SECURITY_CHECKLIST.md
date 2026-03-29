# Release Security Checklist

Run before any version bump or PyPI publish.

---

- [ ] **Trust wording audit**: Does any CLI output, badge, or help text
      overstate what the system actually verifies? (See REMEDIATION_DOCTRINE.md
      rule 3.)
      - "VERIFIED" must not imply signer identity unless `--lock` is used.
      - "append-only" must not imply external anchoring unless checkpoint exists.

- [ ] **Capability advertising match**: Does `--help` for every command
      accurately reflect what is implemented? No flags accepted that throw
      `NotImplementedError` at runtime without disclosure in help text.

- [ ] **Verifier parity**: Do Python, TypeScript, and browser verifiers
      agree on the conformance corpus? Run the shared fixture set against
      all three before shipping.

- [ ] **Regression suite green**: Full `pytest` suite passes. Test count
      must not decrease from prior release without explicit justification.

- [ ] **Security findings current**: `SECURITY_FINDINGS.md` reflects the
      latest known state. No "DESIGN ONLY" items silently promoted to
      "closed" without implementation evidence.

- [ ] **Closure tiers accurate**: Each closed finding uses the correct
      closure tier label (EXPLOITED-AND-PATCHED, HARDENED, DOCUMENTED,
      DESIGN-TRACK, NOT-A-BUG). No ambiguous "FIXED."
