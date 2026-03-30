# Governance Tightening Packet

**Status**: Blocked by API rate limit. Execute via GitHub web UI.
**Date**: 2026-03-30
**Triggered by**: 4 direct-push bypass events across 2 repos during adversarial remediation session.

---

## Prior state (receipted 2026-03-29)

| Setting | Haserjian/assay | Haserjian/assay-ledger |
|---------|----------------|----------------------|
| `enforce_admins` | **false** | **false** |
| PR reviews required | yes | yes |
| `required_approving_review_count` | **0** | **0** |
| `require_code_owner_reviews` | **false** | **false** |
| Required status checks | **none** | `validate` (strict) |

Evidence:
- [`evidence/assay.protection.before.json`](evidence/assay.protection.before.json)
- [`evidence/assay-ledger.protection.before.json`](evidence/assay-ledger.protection.before.json)

Reconstructed from `gh api repos/.../branches/main/protection` output
captured 2026-03-29 (API was available at capture time; rate-limited
at mutation time). Both repos use classic branch protection (not rulesets).

## Bypass events

| Repo | Commit | Type | When |
|------|--------|------|------|
| Haserjian/assay-ledger | `4f8819d` | docs-only direct push | 2026-03-29 |
| Haserjian/assay-ledger | `7cea9d9` | docs-only direct push | 2026-03-29 |
| Haserjian/assay | `3d6c8e4` | code+docs direct push | 2026-03-29 |

All pushed by admin, all bypassed PR requirement due to `enforce_admins: false`.

---

## Target state

### Haserjian/assay (assay-toolkit)

| Setting | Target | Rationale |
|---------|--------|-----------|
| `enforce_admins` | **true** | Close admin bypass trapdoor |
| `required_approving_review_count` | **1** | Ensure independent review |
| `require_code_owner_reviews` | **false** (deferred) | No CODEOWNERS file yet; add when OCD-12 lockfile protection is implemented |
| Required status checks | **`cli-smoke`** | Job name from `.github/workflows/cli-smoke.yml`; runs on PR and push to main. **Verify exact check-context label in GitHub UI before saving** — GitHub matches on the status-context string, which may differ from the workflow job name if the workflow uses a matrix or custom check name. |
| Dismiss stale reviews | **true** | New commits should invalidate prior approvals |

### Haserjian/assay-ledger

| Setting | Target | Rationale |
|---------|--------|-----------|
| `enforce_admins` | **true** | Close admin bypass trapdoor |
| `required_approving_review_count` | **1** | Ensure independent review |
| `require_code_owner_reviews` | **false** (deferred) | Add when CODEOWNERS for `ledger.jsonl` is created |
| Required status checks | **`validate`** (already present) | Retain existing check |
| Dismiss stale reviews | **true** | New commits should invalidate prior approvals |

---

## Execution steps

For each repo, in GitHub web UI:

1. Go to Settings → Branches → Edit rule on `main`
2. Check "Do not allow bypassing the above settings"
3. Set "Required number of approvals before merging" to **1**
4. Check "Dismiss stale pull request approvals when new commits are pushed"
5. For assay-toolkit only: Add `cli-smoke` as a required status check
6. Save

## Post-change verification

Run after rate limit resets (or immediately after UI changes):

```bash
gh api repos/Haserjian/assay/branches/main/protection | python3 -c "
import sys, json; d = json.load(sys.stdin)
print(f'enforce_admins: {d[\"enforce_admins\"][\"enabled\"]}')
pr = d.get('required_pull_request_reviews', {})
print(f'required_approvals: {pr.get(\"required_approving_review_count\", \"N/A\")}')
print(f'dismiss_stale: {pr.get(\"dismiss_stale_reviews\", \"N/A\")}')
checks = d.get('required_status_checks', {})
print(f'required_checks: {[c[\"context\"] for c in checks.get(\"checks\", [])]}')
"

gh api repos/Haserjian/assay-ledger/branches/main/protection | python3 -c "
import sys, json; d = json.load(sys.stdin)
print(f'enforce_admins: {d[\"enforce_admins\"][\"enabled\"]}')
pr = d.get('required_pull_request_reviews', {})
print(f'required_approvals: {pr.get(\"required_approving_review_count\", \"N/A\")}')
print(f'dismiss_stale: {pr.get(\"dismiss_stale_reviews\", \"N/A\")}')
checks = d.get('required_status_checks', {})
print(f'required_checks: {[c[\"context\"] for c in checks.get(\"checks\", [])]}')
"
```

Expected output for both:
```
enforce_admins: True
required_approvals: 1
dismiss_stale: True
required_checks: ['cli-smoke']  # or ['validate'] for ledger
```

Store the raw JSON output as the after-state receipt.

---

## Consequence

Once applied, direct pushes to main will be rejected for all actors
including repo owner. All future changes flow through:
branch → PR → CI check → 1 approval → merge.

This is the correct constraint. The organism's control plane will then
match its doctrine.

---

## Deferred items

- CODEOWNERS for `assay.lock` — add when OCD-12 lockfile protection is implemented
- CODEOWNERS for `ledger.jsonl` — add when ledger append semantics need file-level review gating
- Ruleset migration — classic branch protection is adequate for now; rulesets offer more granularity if needed later
