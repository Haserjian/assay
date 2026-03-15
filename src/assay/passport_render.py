"""Render an Assay Passport JSON file as a single self-contained HTML page.

Pure presentation layer. Reads a passport.json and produces HTML.
Optionally accepts pre-computed verification results for the verifier
status strip. Signing and verification belong in passport_sign.py.
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


class PassportRenderError(ValueError):
    """Raised when the passport file is missing or structurally unusable."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_passport_html(
    passport_path: Path,
    *,
    verification_result: Optional[Dict[str, Any]] = None,
) -> str:
    """Render a passport.json as a single self-contained HTML page.

    Args:
        passport_path: Path to the passport JSON file.
        verification_result: Optional dict from verify_passport_signature()
            with keys signature_valid, id_valid, key_id, key_fingerprint, error.
            When provided, the verifier status strip shows cryptographic check
            results. When omitted, freshness/challenge/coverage are still derived
            from the passport data; crypto checks show NOT CHECKED.

    Raises PassportRenderError if the file is missing or not valid JSON.
    """
    passport_path = Path(passport_path)
    if not passport_path.exists():
        raise PassportRenderError(f"Passport file not found: {passport_path}")

    try:
        data = json.loads(passport_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PassportRenderError(f"Malformed JSON in {passport_path}: {exc}") from exc

    return _render(data, verification_result=verification_result)


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def _render(p: dict[str, Any], *, verification_result: Optional[Dict[str, Any]] = None) -> str:
    # Status: support both old flat string and new structured object
    status_obj = p.get("status", {})
    if isinstance(status_obj, str):
        state = status_obj
    else:
        state = status_obj.get("state", "UNKNOWN")

    subject = p.get("subject", {})
    subject_name = subject.get("name", "Unnamed subject")
    subject_desc = subject.get("description", "")
    subject_owner = subject.get("owner", "")
    subject_version = subject.get("version", "")
    system_id = subject.get("system_id", "")
    environment = subject.get("environment", "")

    passport_id = p.get("passport_id", "unknown")
    issued_at = p.get("issued_at", "")
    valid_until = p.get("valid_until", "")
    obs_window = p.get("observation_window", {})

    reliance = p.get("reliance", {})
    trust_posture = p.get("trust_posture", {})
    scope = p.get("scope", {})
    claims = p.get("claims", [])
    coverage = p.get("coverage", {})
    evidence = p.get("evidence_summary", {})
    relationships = p.get("relationships", {})
    verification = p.get("verification", {})
    challenge = p.get("challenge", {})
    chain = p.get("chain", {})
    signature = p.get("signature")

    # --- Build sections ---
    # Band A: Decision-critical
    triad_html = _render_triad_cards(state, reliance, coverage)
    decision_html = _render_decision_summary(p)
    verifier_checks = _compute_verifier_status(p, verification_result)
    verifier_strip_html = _render_verifier_strip(verifier_checks)
    boundaries_html = _render_reliance_boundaries(reliance)

    # Band B: Substantiating evidence
    scope_html = _render_scope(scope)
    claims_html = _render_claims(claims)
    coverage_html = _render_coverage(coverage)
    evidence_html = _render_evidence_summary(evidence)

    # Band C: Verification & forensic reference
    verify_html = _render_verification(verification)
    challenge_html = _render_challenge(challenge)
    relationships_html = _render_relationships(relationships)
    signature_html = _render_signature(signature)
    chain_html = _render_chain(chain)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Assay Passport — {_esc(subject_name)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="state-stripe state-stripe-{state.lower().replace(' ', '-')}"></div>
  <div class="shell">

    <!-- Band A: Decision-critical -->

    <header>
      <p class="eyebrow">Assay Passport</p>
      <h1>{_esc(subject_name)}</h1>
      {f'<p class="subject-desc">{_esc(subject_desc)}</p>' if subject_desc else ''}
      {triad_html}
    </header>

    {decision_html}
    {verifier_strip_html}
    {boundaries_html}

    <section class="meta-strip">
      <div class="meta-cell">
        <span class="label">Passport ID</span>
        <code class="mono-sm">{_esc(passport_id[:32])}{'…' if len(passport_id) > 32 else ''}</code>
      </div>
      {f'<div class="meta-cell"><span class="label">System</span><code class="mono-sm">{_esc(system_id)}</code></div>' if system_id else ''}
      {f'<div class="meta-cell"><span class="label">Owner</span><span>{_esc(subject_owner)}</span></div>' if subject_owner else ''}
      {f'<div class="meta-cell"><span class="label">Version</span><span>{_esc(subject_version)}</span></div>' if subject_version else ''}
      {f'<div class="meta-cell"><span class="label">Environment</span><span>{_esc(environment)}</span></div>' if environment else ''}
      <div class="meta-cell">
        <span class="label">Issued</span>
        <span>{_esc(issued_at[:10] if issued_at else "—")}</span>
      </div>
      <div class="meta-cell">
        <span class="label">Valid until</span>
        <span class="{_validity_tone(state)}">{_esc(valid_until[:10] if valid_until else "—")}</span>
      </div>
      {_render_obs_window_cells(obs_window)}
    </section>

    <!-- Band B: Substantiating evidence -->

    {scope_html}
    {claims_html}
    {coverage_html}
    {evidence_html}

    <!-- Band C: Verification & reference -->

    <details class="verification-details">
      <summary>Verification details</summary>
      <div class="vd-content">
        {verify_html}
        {challenge_html}
        {relationships_html}
        {signature_html}
        {chain_html}
      </div>
    </details>

    <footer>
      <p>Generated by Assay &middot; Passport v{_esc(p.get('passport_version', '?'))}</p>
      <p class="footer-id"><code>{_esc(passport_id)}</code></p>
    </footer>

  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Verifier status strip
# ---------------------------------------------------------------------------

def _compute_verifier_status(
    data: dict[str, Any],
    verification_result: Optional[Dict[str, Any]] = None,
) -> list[tuple[str, str, str]]:
    """Return [(label, value, css_class), ...] for the verifier status strip.

    Crypto checks (passport ID, signature) require a verification_result from
    verify_passport_signature(). Non-crypto checks (freshness, challenge,
    coverage) are derived directly from the passport data.
    """
    checks: list[tuple[str, str, str]] = []

    # 1. Passport ID
    if verification_result:
        if verification_result.get("id_valid"):
            checks.append(("Passport ID", "PASS", "vstrip-pass"))
        else:
            checks.append(("Passport ID", "FAIL", "vstrip-fail"))
    else:
        checks.append(("Passport ID", "NOT CHECKED", "vstrip-unchecked"))

    # 2. Signature
    if verification_result:
        if verification_result.get("signature_valid"):
            checks.append(("Signature", "VALID", "vstrip-pass"))
        else:
            checks.append(("Signature", "INVALID", "vstrip-fail"))
    else:
        sig = data.get("signature")
        if sig and isinstance(sig, dict):
            checks.append(("Signature", "PRESENT", "vstrip-unchecked"))
        else:
            checks.append(("Signature", "UNSIGNED", "vstrip-fail"))

    # 3. Freshness (derived from valid_until)
    valid_until = data.get("valid_until", "")
    if valid_until:
        try:
            exp = datetime.fromisoformat(valid_until)
            now = datetime.now(timezone.utc)
            if now <= exp:
                checks.append(("Freshness", "CURRENT", "vstrip-pass"))
            else:
                checks.append(("Freshness", "EXPIRED", "vstrip-fail"))
        except (ValueError, TypeError):
            checks.append(("Freshness", "UNKNOWN", "vstrip-unchecked"))
    else:
        checks.append(("Freshness", "NO EXPIRY", "vstrip-unchecked"))

    # 4. Challenge (derived from relationships.challenge_refs)
    rels = data.get("relationships", {})
    challenge_refs = rels.get("challenge_refs", [])
    if challenge_refs:
        n = len(challenge_refs)
        checks.append(("Challenge", f"{n} ACTIVE", "vstrip-fail"))
    else:
        checks.append(("Challenge", "NONE", "vstrip-pass"))

    # 5. Coverage (derived from coverage section)
    cov = data.get("coverage", {})
    if cov:
        covered = cov.get("covered_total", 0)
        total = cov.get("identified_total", 0)
        if total > 0 and covered == total:
            checks.append(("Coverage", f"FULL {covered}/{total}", "vstrip-pass"))
        elif covered > 0:
            checks.append(("Coverage", f"PARTIAL {covered}/{total}", "vstrip-warn"))
        elif total > 0:
            checks.append(("Coverage", f"NONE 0/{total}", "vstrip-fail"))

    return checks


def _render_verifier_strip(checks: list[tuple[str, str, str]]) -> str:
    """Render the verifier status strip — operations-log style bar."""
    if not checks:
        return ""

    cells: list[str] = []
    for label, value, tone in checks:
        cells.append(
            f'<div class="vstrip-cell">'
            f'<span class="vstrip-label">{_esc(label)}</span>'
            f'<span class="vstrip-value {tone}">{_esc(value)}</span>'
            f'</div>'
        )

    return (
        '<section class="verifier-strip">'
        f'{"".join(cells)}'
        '</section>'
    )


# ---------------------------------------------------------------------------
# Decision summary (v2)
# ---------------------------------------------------------------------------

def _render_decision_summary(p: dict[str, Any]) -> str:
    """Top-of-page decision summary — 4 lines + synthesis sentence.

    Answers in <10 seconds: What is this? Can I rely on it? For what?
    What is missing?
    """
    reliance = p.get("reliance", {})
    coverage = p.get("coverage", {})
    scope = p.get("scope", {})
    subject = p.get("subject", {})

    r_class = reliance.get("class", "")
    r_label = reliance.get("label", "")
    covered = coverage.get("covered_total", 0)
    total = coverage.get("identified_total", 0)
    environment = subject.get("environment", "")

    # Key gap — find missing call sites
    missing = [s for s in coverage.get("call_sites", []) if s.get("status") == "missing"]
    not_covered = scope.get("not_covered", [])

    gap_text = ""
    if missing:
        n = len(missing)
        gap_text = f"{n} call site{'s' if n != 1 else ''} not instrumented"
    elif not_covered:
        gap_text = not_covered[0]

    # Use meaning by R-class
    use_map = {
        "R0": "informational only, not suitable for reliance decisions",
        "R1": "suitable for internal review where trust is already established",
        "R2": "suitable for scoped review and bounded third-party assessment",
        "R3": "suitable for formal third-party assessment within declared scope",
        "R4": "suitable for regulatory submission and cross-organizational reliance",
    }
    use_text = use_map.get(r_class, "")

    # Build lines
    lines: list[str] = []
    if r_class:
        lines.append(
            f'<div class="ds-line">'
            f'<span class="ds-key">Reliance</span>'
            f'<span class="ds-val"><strong>{_esc(r_class)}</strong> — {_esc(r_label.lower())}</span>'
            f'</div>'
        )
    if total > 0:
        lines.append(
            f'<div class="ds-line">'
            f'<span class="ds-key">Observed scope</span>'
            f'<span class="ds-val">{covered} of {total} identified AI call sites covered</span>'
            f'</div>'
        )
    if gap_text:
        lines.append(
            f'<div class="ds-line">'
            f'<span class="ds-key">Key gap</span>'
            f'<span class="ds-val ds-gap">{_esc(gap_text)}</span>'
            f'</div>'
        )
    if use_text:
        lines.append(
            f'<div class="ds-line">'
            f'<span class="ds-key">Use meaning</span>'
            f'<span class="ds-val">{_esc(use_text)}</span>'
            f'</div>'
        )

    if not lines:
        return ""

    # Synthesis sentence
    env_phrase = f"a {environment}" if environment else "the declared scope"
    coverage_phrase = f"{covered} observed AI call sites" if covered else "the declared scope"
    gap_phrase = ""
    if gap_text:
        gap_phrase = f" {_esc(gap_text)};"

    synthesis = (
        f"This passport supports bounded reliance for {coverage_phrase} "
        f"in {_esc(env_phrase)}.{gap_phrase} "
        f"it is signed, current, and challengeable, "
        f"but does not establish full-system assurance."
    )

    return (
        '<section class="decision-summary">'
        '<h2>Decision summary</h2>'
        f'<div class="ds-lines">{"".join(lines)}</div>'
        f'<p class="ds-synthesis">{synthesis}</p>'
        '</section>'
    )


def _render_triad_cards(state: str, reliance: dict[str, Any], coverage: dict[str, Any]) -> str:
    """Three strong cards: State, Reliance, Coverage."""
    r_class = reliance.get("class", "")
    r_label = reliance.get("label", "")
    covered = coverage.get("covered_total", 0)
    total = coverage.get("identified_total", 0)
    pct = coverage.get("coverage_pct", 0)

    cov_label = "Full" if pct == 100 else ("Partial" if covered > 0 else "None")
    cov_tone = "triad-good" if pct == 100 else ("triad-warn" if covered > 0 else "triad-alert")
    state_tone = _triad_state_tone(state)

    return (
        '<div class="triad">'
        f'<div class="triad-card {state_tone}">'
        f'<span class="triad-label">State</span>'
        f'<span class="triad-value">{_esc(state)}</span>'
        f'</div>'
        f'<div class="triad-card {_triad_reliance_tone(r_class)}">'
        f'<span class="triad-label">Reliance</span>'
        f'<span class="triad-value">{_esc(r_class)}</span>'
        f'<span class="triad-sub">{_esc(r_label)}</span>'
        f'</div>'
        f'<div class="triad-card {cov_tone}">'
        f'<span class="triad-label">Coverage</span>'
        f'<span class="triad-value">{covered}/{total}</span>'
        f'<span class="triad-sub">{_esc(cov_label)}</span>'
        f'</div>'
        '</div>'
    )


def _triad_state_tone(state: str) -> str:
    s = state.upper()
    if s == "FRESH":
        return "triad-good"
    if s in ("STALE", "CHALLENGED"):
        return "triad-warn"
    if s in ("REVOKED", "SUPERSEDED"):
        return "triad-alert"
    return ""


def _triad_reliance_tone(r_class: str) -> str:
    c = r_class.upper()
    if c in ("R3", "R4"):
        return "triad-good"
    if c == "R2":
        return "triad-qualified"
    return ""


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_reliance_boundaries(reliance: dict[str, Any]) -> str:
    """Unified reliance boundaries block — single authoritative source of constraints."""
    if not reliance:
        return ""

    limits = reliance.get("limits", [])
    freshness_note = reliance.get("freshness_note", "")
    current_class = reliance.get("class", "")

    if not limits and not freshness_note:
        return ""

    parts: list[str] = []

    # Consolidated limits
    if limits:
        items = "".join(f"<li>{_esc(l)}</li>" for l in limits)
        parts.append(f'<ul class="rb-limits">{items}</ul>')

    # R-class reference (collapsible)
    if current_class:
        parts.append(_render_reliance_classes(current_class))

    # Freshness clarification
    if freshness_note:
        parts.append(f'<p class="freshness-note">{_esc(freshness_note)}</p>')

    return (
        '<section class="reliance-boundaries">'
        '<h2>Reliance boundaries</h2>'
        f'{"".join(parts)}'
        '</section>'
    )


def _render_reliance(reliance: dict[str, Any]) -> str:
    if not reliance:
        return ""

    verdict = reliance.get("verdict", "")
    limits = reliance.get("limits", [])
    freshness_note = reliance.get("freshness_note", "")
    current_class = reliance.get("class", "")

    parts: list[str] = []

    # Verdict paragraph
    if verdict:
        parts.append(
            '<div class="reliance-verdict">'
            f'<p>{_esc(verdict)}</p>'
            '</div>'
        )

    # Reliance limits panel
    if limits:
        items = "".join(f"<li>{_esc(l)}</li>" for l in limits)
        parts.append(
            '<div class="reliance-limits">'
            '<h3>Reliance limits</h3>'
            f'<ul>{items}</ul>'
            '</div>'
        )

    # R-class reference table (collapsible)
    if current_class:
        parts.append(_render_reliance_classes(current_class))

    # Freshness clarification
    if freshness_note:
        parts.append(
            f'<p class="freshness-note">{_esc(freshness_note)}</p>'
        )

    if not parts:
        return ""

    return (
        '<section class="reliance-block">'
        f'{"".join(parts)}'
        '</section>'
    )


def _render_reliance_classes(current_class: str) -> str:
    """Render the R-class reference table with the current class highlighted."""
    rows: list[str] = []
    for code, label, requirements, suitable_for in _RELIANCE_CLASSES:
        is_current = code.upper() == current_class.upper()
        row_class = "rclass-current" if is_current else ""
        marker = ' <span class="rclass-marker">current</span>' if is_current else ""

        rows.append(
            f'<tr class="{row_class}">'
            f'<td class="rclass-code"><strong>{_esc(code)}</strong>{marker}</td>'
            f'<td>{_esc(label)}</td>'
            f'<td>{_esc(requirements)}</td>'
            f'<td>{_esc(suitable_for)}</td>'
            f'</tr>'
        )

    return (
        '<details class="rclass-details">'
        '<summary>Reliance class reference (R0 — R4)</summary>'
        '<div class="table-wrap">'
        '<table class="rclass-table">'
        '<thead><tr><th>Class</th><th>Label</th><th>Requirements</th><th>Suitable for</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        '</table>'
        '</div>'
        '</details>'
    )


def _render_trust_posture(posture: dict[str, Any], signature: Any) -> str:
    if not posture:
        return ""

    cells: list[str] = []
    # Ordered for reading priority
    field_map = [
        ("freshness", "Freshness"),
        ("signature", "Signature"),
        ("coverage", "Coverage"),
        ("evidence_mix", "Evidence"),
        ("challenges", "Challenges"),
        ("scope_class", "Scope"),
    ]

    for key, label in field_map:
        val = posture.get(key, "")
        if not val:
            continue
        tone = _posture_tone(key, val)
        cells.append(
            f'<div class="posture-cell">'
            f'<span class="posture-label">{_esc(label)}</span>'
            f'<span class="posture-value {tone}">{_esc(val.replace("_", " "))}</span>'
            f'</div>'
        )

    if not cells:
        return ""

    return (
        '<section class="posture-strip">'
        f'{"".join(cells)}'
        '</section>'
    )


def _render_scope(scope: dict[str, Any]) -> str:
    in_scope = scope.get("in_scope", [])
    boundary_notes = scope.get("boundary_notes", [])

    # Structured exclusion categories
    not_covered = scope.get("not_covered", [])
    not_observed = scope.get("not_observed", [])
    not_concluded = scope.get("not_concluded", [])
    # Fallback to flat "excluded" for backwards compat
    flat_excluded = scope.get("excluded", [])

    has_structured_exclusions = not_covered or not_observed or not_concluded

    parts: list[str] = []

    if in_scope:
        items = "".join(f"<li>{_esc(s)}</li>" for s in in_scope)
        parts.append(f'<div class="scope-col"><h3>In scope</h3><ul>{items}</ul></div>')

    if has_structured_exclusions:
        excl_parts: list[str] = []
        if not_covered:
            items = "".join(f"<li>{_esc(s)}</li>" for s in not_covered)
            excl_parts.append(f'<h4 class="excl-cat">Not covered</h4><ul>{items}</ul>')
        if not_observed:
            items = "".join(f"<li>{_esc(s)}</li>" for s in not_observed)
            excl_parts.append(f'<h4 class="excl-cat">Not observed</h4><ul>{items}</ul>')
        if not_concluded:
            items = "".join(f"<li>{_esc(s)}</li>" for s in not_concluded)
            excl_parts.append(f'<h4 class="excl-cat">Not concluded</h4><ul>{items}</ul>')
        parts.append(
            f'<div class="scope-col scope-excluded">'
            f'<h3>Exclusions</h3>'
            f'{"".join(excl_parts)}'
            f'</div>'
        )
    elif flat_excluded:
        items = "".join(f"<li>{_esc(s)}</li>" for s in flat_excluded)
        parts.append(f'<div class="scope-col scope-excluded"><h3>Excluded</h3><ul>{items}</ul></div>')

    notes = ""
    if boundary_notes:
        items = "".join(f"<li>{_esc(n)}</li>" for n in boundary_notes)
        notes = f'<div class="boundary-notes"><h3>Boundary notes</h3><ul>{items}</ul></div>'

    return (
        '<section class="section">'
        '<h2>Scope</h2>'
        '<p class="section-subtitle">What is covered and what is explicitly excluded?</p>'
        f'<div class="scope-grid">{"".join(parts)}</div>'
        f'{notes}'
        '</section>'
    )


def _render_claims(claims: list[dict[str, Any]]) -> str:
    if not claims:
        return ""

    rows: list[str] = []
    for c in claims:
        topic = c.get("topic", "")
        assertion = c.get("assertion", "")
        result = c.get("result", "")
        ev_type = c.get("evidence_type", "")
        tier = c.get("proof_tier", "")
        applies_to = c.get("applies_to", "")
        qualification = c.get("qualification")
        boundary = c.get("boundary")

        result_class = _result_tone(result)
        result_label = result.title() if result else "—"
        impact = _reliance_impact(result, ev_type, tier)

        # Evidence mode + tier as compact badges in the assertion detail
        ev_label = "Machine" if ev_type == "machine_verified" else "Human"
        ev_class = "ev-machine" if ev_type == "machine_verified" else "ev-human"
        tier_label = tier.title() if tier else ""
        mode_badges = (
            f'<span class="claim-mode-badges">'
            f'<span class="{ev_class}">{_esc(ev_label)}</span>'
            f'{f" · <span>{_esc(tier_label)}</span>" if tier_label else ""}'
            f'</span>'
        )

        # Build sub-rows for qualification and boundary
        sub_html = ""
        if qualification:
            sub_html += f'<div class="claim-qualification">{_esc(qualification)}</div>'
        if boundary:
            sub_html += f'<div class="claim-boundary">{_esc(boundary)}</div>'

        # Evidence anchors (collapsible)
        anchors_html = _render_claim_anchors(c)
        if anchors_html:
            sub_html += anchors_html

        applies_html = f'<div class="claim-applies">{_esc(applies_to)}</div>' if applies_to else ""

        rows.append(
            f'<tr>'
            f'<td class="claim-topic"><strong>{_esc(topic)}</strong>{applies_html}{mode_badges}</td>'
            f'<td><span class="result-badge {result_class}">{_esc(result_label)}</span></td>'
            f'<td>{_esc(assertion)}{sub_html}</td>'
            f'<td class="impact-cell">{_esc(impact)}</td>'
            f'</tr>'
        )

    return (
        '<section class="section">'
        '<h2>Claims</h2>'
        '<p class="section-subtitle">What assertions were tested and what result was reached?</p>'
        '<div class="table-wrap">'
        '<table>'
        '<thead><tr><th>Claim</th><th>Result</th><th>Assertion</th><th>Reliance impact</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        '</table>'
        '</div>'
        '</section>'
    )


def _render_obs_window_cells(obs: dict[str, Any]) -> str:
    """Render observation window as meta-strip cells."""
    if not obs:
        return ""

    start = obs.get("start", "")
    end = obs.get("end", "")
    note = obs.get("note", "")

    if not start:
        return ""

    s_date = start[:10]
    e_date = end[:10] if end else ""

    # Single cell with range if dates differ, single date if same
    if e_date and s_date != e_date:
        window_display = f"{_esc(s_date)} — {_esc(e_date)}"
    else:
        window_display = _esc(s_date)

    cells = (
        f'<div class="meta-cell meta-cell-obs">'
        f'<span class="label">Evidence observed</span>'
        f'<span>{window_display}</span>'
        f'</div>'
    )

    if note:
        cells += (
            f'<div class="meta-cell meta-cell-obs">'
            f'<span class="label">Observation note</span>'
            f'<span class="obs-note">{_esc(note)}</span>'
            f'</div>'
        )

    return cells


def _render_claim_anchors(claim: dict[str, Any]) -> str:
    """Render collapsible evidence anchors for a single claim.

    Handles both new plural evidence_refs and old singular evidence_ref
    for backward compatibility.
    """
    # Resolve refs: prefer evidence_refs (array), fall back to evidence_ref (string)
    refs = claim.get("evidence_refs", [])
    if not refs:
        single = claim.get("evidence_ref")
        if single:
            refs = [single]
    if not refs:
        return ""

    receipt_ids = claim.get("receipt_set_ids", [])
    pack_digest = claim.get("proof_pack_digest", "")
    obs_window = claim.get("observation_window", {})

    # Build summary line for <details><summary>
    summary_parts: list[str] = []
    summary_parts.append(f"{len(refs)} ref{'s' if len(refs) != 1 else ''}")
    if receipt_ids:
        summary_parts.append(f"{len(receipt_ids)} receipt{'s' if len(receipt_ids) != 1 else ''}")
    if obs_window:
        start = obs_window.get("start", "")[:10]
        end = obs_window.get("end", "")[:10]
        if start and end and start == end:
            summary_parts.append(f"observed {_esc(start)}")
        elif start and end:
            summary_parts.append(f"observed {_esc(start)} — {_esc(end)}")

    summary_text = " · ".join(summary_parts)

    # Build detail content
    detail_parts: list[str] = []

    # Evidence refs
    ref_items = "".join(
        f'<code class="anchor-ref">{_esc(r)}</code>' for r in refs
    )
    detail_parts.append(f'<div class="anchor-refs">{ref_items}</div>')

    # Receipt set IDs
    if receipt_ids:
        ids_text = ", ".join(f'<code class="anchor-receipt">{_esc(r)}</code>' for r in receipt_ids)
        detail_parts.append(f'<div class="anchor-receipts"><span class="anchor-field">Receipts:</span> {ids_text}</div>')

    # Pack digest
    if pack_digest:
        display = pack_digest[:24] + "…" if len(pack_digest) > 24 else pack_digest
        detail_parts.append(
            f'<div class="anchor-digest"><span class="anchor-field">Pack:</span> '
            f'<code class="anchor-ref">{_esc(display)}</code></div>'
        )

    # Observation window
    if obs_window:
        start = obs_window.get("start", "")
        end = obs_window.get("end", "")
        note = obs_window.get("note", "")
        window_text = ""
        if start and end:
            s_display = start[:19]
            e_display = end[:19]
            if s_display == e_display:
                window_text = s_display
            else:
                window_text = f"{s_display} — {e_display}"
        if note:
            window_text += f" ({_esc(note)})" if window_text else _esc(note)
        if window_text:
            detail_parts.append(
                f'<div class="anchor-window"><span class="anchor-field">Observed:</span> '
                f'<span>{window_text}</span></div>'
            )

    return (
        f'<details class="claim-anchors">'
        f'<summary>{summary_text}</summary>'
        f'<div class="anchor-detail">{"".join(detail_parts)}</div>'
        f'</details>'
    )


def _render_evidence_summary(ev: dict[str, Any]) -> str:
    if not ev:
        return ""

    total = ev.get("total_claims", 0)
    machine = ev.get("machine_verified", 0)
    human = ev.get("human_attested", 0)
    core_passed = ev.get("core_claims_passed", "")
    conditional = ev.get("conditional_claims", "")
    coverage_gaps = ev.get("coverage_gaps", 0)

    # Primary count cards
    cards = (
        '<div class="evidence-grid">'
        f'<div class="ev-card"><span class="ev-number">{total}</span><span class="ev-label">Total claims</span></div>'
        f'<div class="ev-card ev-machine-card"><span class="ev-number">{machine}</span><span class="ev-label">Machine verified</span></div>'
        f'<div class="ev-card ev-human-card"><span class="ev-number">{human}</span><span class="ev-label">Human attested</span></div>'
        '</div>'
    )

    # Secondary detail line
    details: list[str] = []
    if core_passed:
        details.append(f'Core claims passed: <strong>{_esc(str(core_passed))}</strong>')
    if conditional:
        details.append(f'Conditional claims: <strong>{_esc(str(conditional))}</strong>')
    if coverage_gaps:
        details.append(f'Coverage gaps: <strong class="tone-warn">{coverage_gaps}</strong>')

    detail_html = ""
    if details:
        detail_html = '<p class="ev-details">' + " &middot; ".join(details) + '</p>'

    return (
        '<section class="section">'
        '<h2>Evidence summary</h2>'
        '<p class="section-subtitle">How many claims were tested, and by what method?</p>'
        f'{cards}'
        f'{detail_html}'
        '</section>'
    )


def _render_relationships(rels: dict[str, Any]) -> str:
    if not rels:
        return ""

    rows: list[str] = []

    ref_fields = [
        ("proof_pack_ref", "Proof pack"),
        ("reviewer_packet_ref", "Reviewer packet"),
        ("supersedes", "Supersedes"),
        ("superseded_by", "Superseded by"),
        ("revocation_ref", "Revocation"),
    ]

    for key, label in ref_fields:
        val = rels.get(key)
        if val:
            display = _esc(str(val))
            if len(display) > 40:
                display = display[:36] + "…"
            rows.append(
                f'<div class="rel-cell">'
                f'<span class="label">{_esc(label)}</span>'
                f'<code class="mono-sm">{display}</code>'
                f'</div>'
            )

    challenges = rels.get("challenge_refs", [])
    if challenges:
        count = len(challenges)
        rows.append(
            f'<div class="rel-cell rel-challenge">'
            f'<span class="label">Active challenges</span>'
            f'<strong class="tone-warn">{count}</strong>'
            f'</div>'
        )
    else:
        rows.append(
            '<div class="rel-cell">'
            '<span class="label">Active challenges</span>'
            '<span>None</span>'
            '</div>'
        )

    if not rows:
        return ""

    return (
        '<section class="section">'
        '<h2>Lineage</h2>'
        f'<div class="rel-grid">{"".join(rows)}</div>'
        '</section>'
    )


def _render_verification(v: dict[str, Any]) -> str:
    if not v:
        return ""

    cmd = v.get("how_to_verify", "")
    checks = v.get("what_is_checked", [])

    items = "".join(f"<li>{_esc(c)}</li>" for c in checks)

    return (
        '<section class="section">'
        '<h2>How to verify</h2>'
        '<p class="section-subtitle">How can an independent reviewer validate this passport?</p>'
        f'{f"<pre><code>{_esc(cmd)}</code></pre>" if cmd else ""}'
        f'{f"<ul>{items}</ul>" if items else ""}'
        '</section>'
    )


def _render_challenge(ch: dict[str, Any]) -> str:
    if not ch:
        return ""

    cmd = ch.get("how_to_challenge", "")
    steps = ch.get("what_happens", [])

    items = "".join(f"<li>{_esc(s)}</li>" for s in steps)

    return (
        '<section class="section section-challenge">'
        '<h2>How to challenge</h2>'
        '<p class="section-subtitle">How is this artifact disputed, updated, or revoked?</p>'
        f'{f"<pre><code>{_esc(cmd)}</code></pre>" if cmd else ""}'
        f'{f"<ol>{items}</ol>" if items else ""}'
        '</section>'
    )


def _render_chain(chain: dict[str, Any]) -> str:
    if not chain:
        return ""

    issuer = chain.get("issuer", "—")
    fingerprint = chain.get("issuer_fingerprint", "")

    parts: list[str] = [
        f'<div class="meta-cell"><span class="label">Issuer</span><strong>{_esc(issuer)}</strong></div>',
    ]
    if fingerprint:
        parts.append(
            f'<div class="meta-cell"><span class="label">Fingerprint</span>'
            f'<code class="mono-sm">{_esc(fingerprint[:16])}…</code></div>'
        )

    return (
        '<section class="section">'
        '<h2>Issuer</h2>'
        f'<div class="chain-grid">{"".join(parts)}</div>'
        '</section>'
    )


def _render_coverage(cov: dict[str, Any]) -> str:
    if not cov:
        return ""

    total = cov.get("identified_total", 0)
    covered = cov.get("covered_total", 0)
    pct = cov.get("coverage_pct", 0)
    sites = cov.get("call_sites", [])
    discovery_method = cov.get("discovery_method", "")
    discovery_note = cov.get("discovery_note", "")
    provenance = cov.get("provenance", {})

    summary = (
        f'<div class="cov-summary">'
        f'<span class="cov-ratio">{covered} of {total}</span>'
        f'<span class="cov-detail">identified call sites produce receipted evidence</span>'
        f'</div>'
    )

    # Discovery + provenance block
    prov_html = _render_coverage_provenance(discovery_method, discovery_note, provenance)

    if not sites:
        return (
            '<section class="section">'
            '<h2>Coverage map</h2>'
        '<p class="section-subtitle">Which AI call sites were observed, and what is missing?</p>'
            f'{summary}'
            f'{prov_html}'
            '</section>'
        )

    rows: list[str] = []
    for s in sites:
        site_id = s.get("call_site_id", "")
        function = s.get("function", "")
        status = s.get("status", "")
        reason = s.get("reason", "")
        status_class = "cov-covered" if status == "covered" else "cov-missing"
        status_label = status.title()

        detail = ""
        if reason:
            detail = f'<div class="cov-reason">{_esc(reason)}</div>'

        rows.append(
            f'<tr>'
            f'<td><code class="mono-sm">{_esc(site_id)}</code></td>'
            f'<td>{_esc(function)}</td>'
            f'<td class="{status_class}">{_esc(status_label)}{detail}</td>'
            f'</tr>'
        )

    return (
        '<section class="section">'
        '<h2>Coverage map</h2>'
        '<p class="section-subtitle">Which AI call sites were observed, and what is missing?</p>'
        f'{summary}'
        f'{prov_html}'
        '<div class="table-wrap">'
        '<table>'
        '<thead><tr><th>Call site</th><th>Function</th><th>Status</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        '</table>'
        '</div>'
        '</section>'
    )


def _render_coverage_provenance(
    discovery_method: str,
    discovery_note: str,
    provenance: dict[str, Any],
) -> str:
    """Render the coverage discovery method and provenance block."""
    if not discovery_method and not provenance:
        return ""

    parts: list[str] = []

    # Discovery method
    if discovery_method:
        method_label = discovery_method.replace("_", " ").title()
        parts.append(
            f'<div class="prov-cell">'
            f'<span class="prov-label">Discovery</span>'
            f'<strong class="prov-value">{_esc(method_label)}</strong>'
            f'</div>'
        )

    # Provenance fields
    if provenance:
        source = provenance.get("source", "")
        declared_by = provenance.get("declared_by", "")
        verified_by = provenance.get("verified_by", "")
        if source:
            parts.append(
                f'<div class="prov-cell">'
                f'<span class="prov-label">Source</span>'
                f'<code class="mono-sm">{_esc(source)}</code>'
                f'</div>'
            )
        if declared_by:
            parts.append(
                f'<div class="prov-cell">'
                f'<span class="prov-label">Declared by</span>'
                f'<span class="prov-value">{_esc(declared_by.replace("_", " ").title())}</span>'
                f'</div>'
            )
        if verified_by:
            parts.append(
                f'<div class="prov-cell">'
                f'<span class="prov-label">Verified by</span>'
                f'<span class="prov-value">{_esc(verified_by.replace("_", " ").title())}</span>'
                f'</div>'
            )

    cells_html = f'<div class="prov-grid">{"".join(parts)}</div>' if parts else ""

    # Notes
    notes_html = ""
    note_texts: list[str] = []
    if discovery_note:
        note_texts.append(discovery_note)
    verification_note = provenance.get("verification_note", "") if provenance else ""
    if verification_note:
        note_texts.append(verification_note)
    if note_texts:
        items = "".join(f'<li>{_esc(n)}</li>' for n in note_texts)
        notes_html = f'<ul class="prov-notes">{items}</ul>'

    if not cells_html and not notes_html:
        return ""

    return (
        f'<div class="cov-provenance">'
        f'{cells_html}'
        f'{notes_html}'
        f'</div>'
    )


def _render_signature(sig: Any) -> str:
    if not sig or not isinstance(sig, dict):
        return ""

    algo = sig.get("algorithm", "—")
    key_id = sig.get("key_id", "—")
    fingerprint = sig.get("key_fingerprint", "")
    signed_at = sig.get("signed_at", "")
    sig_val = sig.get("signature", "")

    return (
        '<section class="section">'
        '<h2>Signature</h2>'
        '<div class="sig-grid">'
        f'<div class="meta-cell"><span class="label">Algorithm</span><strong>{_esc(algo)}</strong></div>'
        f'<div class="meta-cell"><span class="label">Key ID</span><strong>{_esc(key_id)}</strong></div>'
        f'{f"""<div class="meta-cell"><span class="label">Fingerprint</span><code class="mono-sm">{_esc(fingerprint[:24])}…</code></div>""" if fingerprint else ""}'
        f'{f"""<div class="meta-cell"><span class="label">Signed at</span><span>{_esc(signed_at[:19])}</span></div>""" if signed_at else ""}'
        '</div>'
        f'{f"""<div class="sig-value"><span class="label">Signature value</span><code class="mono-sm">{_esc(sig_val[:48])}…</code></div>""" if sig_val else ""}'
        '</section>'
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _validity_tone(state: str) -> str:
    if state in ("STALE", "CHALLENGED"):
        return "tone-warn"
    if state in ("REVOKED", "SUPERSEDED"):
        return "tone-dim"
    return ""


def _posture_tone(key: str, val: str) -> str:
    v = val.lower()
    if key == "signature" and v in ("missing", "unsigned"):
        return "posture-alert"
    if key == "signature" and v == "signed":
        return "posture-good"
    if key == "freshness" and v == "current":
        return "posture-good"
    if key == "freshness" and v in ("stale", "expired"):
        return "posture-alert"
    if key == "challenges" and v == "none":
        return "posture-good"
    if key == "challenges" and v != "none":
        return "posture-alert"
    return ""


def _reliance_impact(result: str, ev_type: str, tier: str) -> str:
    """Translate evidence result into operational reliance meaning."""
    r = result.lower()
    if r == "pass":
        return "Supports scoped reliance"
    if r == "partial":
        return "Rely with noted limitation"
    if r == "present":
        if ev_type == "human_attested":
            return "Informational, not assurance-bearing"
        return "Present, limited assurance"
    if r == "fail":
        return "Do not rely on this claim"
    return "—"


def _result_tone(result: str) -> str:
    r = result.lower()
    if r == "pass":
        return "result-pass"
    if r == "partial":
        return "result-partial"
    if r == "present":
        return "result-present"
    if r == "fail":
        return "result-fail"
    return ""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STATUS_NEXT_ACTIONS = {
    "FRESH": "May be relied on within declared scope.",
    "STALE": "Validity window has passed. Verify freshness before relying.",
    "CHALLENGED": "Review active challenge receipts before relying.",
    "SUPERSEDED": "Use the successor passport.",
    "REVOKED": "Do not rely on this passport.",
}

# R-class reliance hierarchy — deterministic assignment rules.
# Each tuple: (class_code, label, requirements, suitable_for)
_RELIANCE_CLASSES = [
    (
        "R0",
        "Informational",
        "Passport structure only. No evidence, no signature.",
        "Internal reference. Not suitable for reliance decisions.",
    ),
    (
        "R1",
        "Unsigned evidence",
        "At least one claim with supporting evidence. No cryptographic signature.",
        "Internal review where trust context is already established.",
    ),
    (
        "R2",
        "Signed, partial coverage",
        "Valid Ed25519 signature. At least one core claim passes. Coverage < 100% of identified call sites.",
        "Internal review and bounded third-party assessment within declared scope.",
    ),
    (
        "R3",
        "Signed, full coverage",
        "Valid Ed25519 signature. All core claims pass. 100% coverage of identified call sites.",
        "Third-party assessment. Formal review within declared scope and observation window.",
    ),
    (
        "R4",
        "Externally anchored",
        "All R3 requirements. External timestamp authority or independent third-party attestation.",
        "Regulatory submission. Cross-organizational reliance. Audit trail.",
    ),
]


_CSS = textwrap.dedent("""\
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
        font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        background: #fcfcfb;
        color: #161616;
        line-height: 1.65;
        font-size: 15px;
    }

    /* --- Page-top state stripe --- */

    .state-stripe {
        height: 3px;
        width: 100%;
    }
    .state-stripe-fresh      { background: #1f7a4d; }
    .state-stripe-stale       { background: #a56a00; }
    .state-stripe-challenged  { background: #b42318; }
    .state-stripe-superseded  { background: #8d8d8d; }
    .state-stripe-revoked     { background: #b42318; }
    .state-stripe-unknown     { background: #6b7280; }

    .shell {
        max-width: 860px;
        margin: 0 auto;
        padding: 48px 28px 96px;
    }

    /* --- Triad cards --- */

    .triad {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 10px;
        margin-top: 20px;
    }
    .triad-card {
        text-align: center;
        padding: 14px 12px 10px;
        border: 1.5px solid #d7d9dd;
        border-radius: 8px;
        background: #f6f5f2;
    }
    .triad-label {
        display: block;
        font-size: .6rem;
        text-transform: uppercase;
        letter-spacing: .1em;
        color: #6b7280;
        margin-bottom: 2px;
    }
    .triad-value {
        display: block;
        font-size: 1.3rem;
        font-weight: 700;
        letter-spacing: .02em;
        color: #161616;
    }
    .triad-sub {
        display: block;
        font-size: .72rem;
        color: #6b7280;
        margin-top: 1px;
    }
    .triad-good { border-color: #1f7a4d; }
    .triad-good .triad-value { color: #1f7a4d; }
    .triad-qualified { border-color: #a56a00; }
    .triad-qualified .triad-value { color: #a56a00; }
    .triad-warn { border-color: #a56a00; }
    .triad-warn .triad-value { color: #a56a00; }
    .triad-alert { border-color: #b42318; }
    .triad-alert .triad-value { color: #b42318; }

    /* --- Decision summary --- */

    .decision-summary {
        background: #f6f5f2;
        border: 1.5px solid #161616;
        border-radius: 8px;
        padding: 20px 24px;
        margin-bottom: 20px;
    }
    .decision-summary h2 {
        font-size: .72rem;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: #6b7280;
        font-weight: 600;
        margin-bottom: 12px;
    }
    .ds-lines {
        display: flex;
        flex-direction: column;
        gap: 6px;
        margin-bottom: 14px;
    }
    .ds-line {
        display: flex;
        gap: 10px;
        align-items: baseline;
    }
    .ds-key {
        min-width: 120px;
        font-size: .72rem;
        text-transform: uppercase;
        letter-spacing: .06em;
        color: #6b7280;
        flex-shrink: 0;
    }
    .ds-val {
        font-size: .88rem;
        color: #333;
    }
    .ds-val strong {
        font-weight: 700;
    }
    .ds-gap {
        color: #a56a00;
        font-weight: 600;
    }
    .ds-synthesis {
        font-size: .86rem;
        line-height: 1.65;
        color: #525252;
        padding-top: 10px;
        border-top: 1px solid #d7d9dd;
    }

    /* --- Header --- */

    header { margin-bottom: 20px; }

    .eyebrow {
        font-size: 11px;
        letter-spacing: .16em;
        text-transform: uppercase;
        color: #6b7280;
        margin-bottom: 8px;
    }

    h1 {
        font-size: clamp(1.6rem, 4vw, 2.2rem);
        line-height: 1.2;
        font-weight: 700;
        margin-bottom: 10px;
        letter-spacing: -.02em;
    }

    .subject-desc {
        color: #525252;
        font-size: .92rem;
        margin-bottom: 20px;
        max-width: 620px;
    }

    /* --- Status band (legacy) --- */

    .status-band {
        display: flex;
        flex-wrap: wrap;
        align-items: flex-start;
        gap: 12px;
    }

    .status-badge {
        display: inline-flex;
        flex-direction: column;
        gap: 4px;
        padding: 14px 22px;
        border-radius: 8px;
        color: #fff;
        max-width: 440px;
    }
    .status-badge strong { font-size: 1.1rem; font-weight: 700; letter-spacing: .04em; }
    .next-action { font-size: .85rem; opacity: .92; line-height: 1.5; }

    .status-fresh      { background: #1f7a4d; }
    .status-stale       { background: #a56a00; }
    .status-challenged  { background: #b42318; }
    .status-superseded  { background: #6b7280; }
    .status-revoked     { background: #b42318; }
    .status-unknown     { background: #6b7280; }

    .reliance-class-badge {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        padding: 10px 20px;
        border: 1.5px solid #d7d9dd;
        border-radius: 8px;
        background: #f6f5f2;
    }
    .rc-code {
        font-size: 1.1rem;
        font-weight: 700;
        color: #161616;
        letter-spacing: .04em;
    }
    .rc-label {
        font-size: .88rem;
        color: #6b7280;
    }

    /* --- Reliance boundaries --- */

    .reliance-boundaries {
        background: #fcfcfb;
        border: 1px solid #d7d9dd;
        border-left: 3px solid #a56a00;
        border-radius: 2px 8px 8px 2px;
        padding: 18px 22px;
        margin-bottom: 24px;
    }
    .reliance-boundaries h2 {
        font-size: .72rem;
        text-transform: uppercase;
        letter-spacing: .06em;
        color: #a56a00;
        font-weight: 600;
        margin-bottom: 10px;
        padding-bottom: 0;
        border-bottom: none;
    }
    .rb-limits {
        list-style: none;
        padding: 0;
        margin: 0 0 10px;
    }
    .rb-limits li {
        padding: 5px 0;
        font-size: .86rem;
        color: #525252;
        line-height: 1.6;
        border-bottom: 1px solid #e8e8e8;
    }
    .rb-limits li:last-child { border-bottom: none; }

    /* Legacy reliance block (kept for backward compat) */

    .reliance-block {
        background: #f6f5f2;
        border: 1px solid #d7d9dd;
        border-radius: 8px;
        padding: 20px 24px;
        margin-bottom: 24px;
    }
    .reliance-verdict p {
        font-size: .92rem;
        line-height: 1.75;
        color: #333;
        margin-bottom: 16px;
    }
    .reliance-limits {
        background: #fcfcfb;
        border: 1px solid #d7d9dd;
        border-left: 3px solid #a56a00;
        border-radius: 2px 6px 6px 2px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    .reliance-limits h3 {
        font-size: .72rem;
        text-transform: uppercase;
        letter-spacing: .06em;
        color: #a56a00;
        font-weight: 600;
        margin-bottom: 8px;
    }
    .reliance-limits ul {
        list-style: none;
        padding: 0;
        margin: 0;
    }
    .reliance-limits li {
        padding: 4px 0;
        font-size: .86rem;
        color: #525252;
        line-height: 1.6;
        border-bottom: 1px solid #e8e8e8;
    }
    .reliance-limits li:last-child { border-bottom: none; }
    .freshness-note {
        font-size: .82rem;
        color: #6b7280;
        line-height: 1.6;
        font-style: italic;
    }
    .rclass-details {
        margin-top: 12px;
        border: 1px solid #d7d9dd;
        border-radius: 6px;
        margin-bottom: 10px;
    }
    .rclass-details summary {
        padding: 8px 14px;
        cursor: pointer;
        font-size: .72rem;
        color: #6b7280;
        font-weight: 600;
        letter-spacing: .02em;
        user-select: none;
    }
    .rclass-details summary:hover { color: #161616; }
    .rclass-details[open] summary {
        border-bottom: 1px solid #d7d9dd;
    }
    .rclass-table { font-size: .8rem; }
    .rclass-table th { font-size: .7rem; padding: 8px 10px; }
    .rclass-table td { padding: 8px 10px; font-size: .8rem; line-height: 1.5; }
    .rclass-code { white-space: nowrap; }
    .rclass-current td {
        background: #eef5f0 !important;
        border-left: 3px solid #1f7a4d;
    }
    .rclass-marker {
        display: inline-block;
        font-size: .6rem;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: #fff;
        background: #1f7a4d;
        padding: 1px 5px;
        border-radius: 3px;
        margin-left: 4px;
        vertical-align: middle;
    }

    /* --- Trust posture strip (legacy) --- */

    .posture-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-bottom: 24px;
    }
    .posture-cell {
        display: flex;
        align-items: center;
        gap: 6px;
        background: #f6f5f2;
        border: 1px solid #d7d9dd;
        border-radius: 6px;
        padding: 6px 14px;
    }
    .posture-label {
        font-size: .72rem;
        text-transform: uppercase;
        letter-spacing: .06em;
        color: #6b7280;
    }
    .posture-value {
        font-size: .84rem;
        font-weight: 600;
        color: #525252;
    }
    .posture-good { color: #1f7a4d; }
    .posture-alert { color: #b42318; }

    /* --- Verifier status strip --- */

    .verifier-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 0;
        margin-bottom: 24px;
        border: 1px solid #2a2a2a;
        border-radius: 6px;
        overflow: hidden;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }
    .vstrip-cell {
        flex: 1 1 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
        padding: 10px 14px;
        background: #1e1e1e;
        border-right: 1px solid #2a2a2a;
    }
    .vstrip-cell:last-child { border-right: none; }
    .vstrip-label {
        font-size: .62rem;
        text-transform: uppercase;
        letter-spacing: .1em;
        color: #707070;
    }
    .vstrip-value {
        font-size: .8rem;
        font-weight: 600;
        letter-spacing: .04em;
    }
    .vstrip-pass { color: #5cb87a; }
    .vstrip-warn { color: #d4a244; }
    .vstrip-fail { color: #d06b6b; }
    .vstrip-unchecked { color: #707070; }

    /* --- Meta strip --- */

    .meta-strip {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
        gap: 10px;
        margin: 0 0 40px;
    }

    .meta-cell {
        background: #f6f5f2;
        border: 1px solid #d7d9dd;
        border-radius: 6px;
        padding: 12px 14px;
    }
    .label {
        display: block;
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: .07em;
        color: #6b7280;
        margin-bottom: 4px;
    }
    .meta-cell strong, .meta-cell code, .meta-cell span { display: block; }
    .mono-sm {
        font-size: .78rem;
        word-break: break-all;
        color: #525252;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }
    .meta-cell-obs { border-color: #b8c8d2; }
    .obs-note { font-size: .82rem; color: #6b7280; font-style: italic; }

    /* --- Sections --- */

    .section {
        margin-bottom: 48px;
    }
    .section h2 {
        font-size: 1.05rem;
        font-weight: 700;
        margin-bottom: 4px;
        padding-bottom: 10px;
        border-bottom: 1px solid #d7d9dd;
        letter-spacing: -.01em;
    }
    .section-subtitle {
        font-size: .82rem;
        color: #6b7280;
        margin-bottom: 16px;
        line-height: 1.5;
    }
    .section h3 {
        font-size: .92rem;
        font-weight: 600;
        margin-bottom: 10px;
        color: #525252;
    }
    .section h4 {
        font-size: .84rem;
        font-weight: 600;
        color: #6b7280;
        margin: 12px 0 6px;
    }
    .section ul, .section ol {
        padding-left: 22px;
        margin-bottom: 12px;
    }
    .section li {
        margin-bottom: 6px;
        line-height: 1.6;
        font-size: .92rem;
    }
    .section pre {
        background: #1e1e1e;
        color: #c8d0c8;
        padding: 14px 18px;
        border-radius: 6px;
        overflow-x: auto;
        font-size: .85rem;
        margin-bottom: 14px;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }
    .section code {
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }

    /* --- Scope --- */

    .scope-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 16px;
        margin-bottom: 16px;
    }
    .scope-col {
        background: #f6f5f2;
        border: 1px solid #d7d9dd;
        border-radius: 6px;
        padding: 16px 18px;
    }
    .scope-excluded {
        background: #fcfcfb;
        border-color: #d7d9dd;
        border-left: 3px solid #a56a00;
        border-radius: 2px 6px 6px 2px;
    }
    .scope-excluded h3 { color: #a56a00; }
    .excl-cat {
        font-size: .72rem;
        text-transform: uppercase;
        letter-spacing: .05em;
        color: #a56a00;
        margin: 14px 0 6px;
        padding-bottom: 3px;
        border-bottom: 1px solid #e8e8e8;
    }
    .excl-cat:first-child { margin-top: 0; }
    .scope-col ul { list-style: none; padding-left: 0; }
    .scope-col li {
        padding: 5px 0;
        border-bottom: 1px solid #e8e8e8;
        font-size: .88rem;
    }
    .scope-col li:last-child { border-bottom: none; }
    .boundary-notes {
        background: #f6f5f2;
        border: 1px dashed #d7d9dd;
        border-radius: 6px;
        padding: 14px 18px;
        margin-top: 4px;
    }
    .boundary-notes h3 { font-size: .82rem; color: #6b7280; text-transform: uppercase; letter-spacing: .06em; }
    .boundary-notes li { font-size: .86rem; color: #6b7280; }

    /* --- Claims table --- */

    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: .88rem; }
    thead tr { background: #161616; }
    th {
        color: #d7d9dd;
        padding: 10px 14px;
        text-align: left;
        font-weight: 600;
        font-size: .72rem;
        letter-spacing: .06em;
        text-transform: uppercase;
        white-space: nowrap;
    }
    td { padding: 12px 14px; border-bottom: 1px solid #d7d9dd; vertical-align: top; }
    tr:nth-child(even) td { background: #f6f5f2; }
    .claim-topic { white-space: nowrap; }
    .claim-applies {
        font-size: .72rem;
        color: #6b7280;
        margin-top: 3px;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }
    .impact-cell {
        font-size: .82rem;
        color: #525252;
        font-style: italic;
        min-width: 140px;
    }
    .claim-mode-badges {
        display: block;
        font-size: .7rem;
        color: #6b7280;
        margin-top: 3px;
    }
    .claim-qualification {
        margin-top: 6px;
        padding: 5px 10px;
        background: #f6f5f2;
        border-left: 3px solid #d7d9dd;
        border-radius: 0 4px 4px 0;
        font-size: .82rem;
        color: #6b7280;
        line-height: 1.5;
    }
    .claim-boundary {
        margin-top: 4px;
        padding: 5px 10px;
        background: #fcfcfb;
        border-left: 3px solid #a56a00;
        border-radius: 0 4px 4px 0;
        font-size: .82rem;
        color: #a56a00;
        line-height: 1.5;
    }
    /* --- Claim evidence anchors --- */

    .claim-anchors {
        margin-top: 8px;
        border: 1px solid #d7d9dd;
        border-radius: 4px;
        font-size: .78rem;
        background: #f6f5f2;
    }
    .claim-anchors summary {
        padding: 5px 10px;
        cursor: pointer;
        color: #6b7280;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
        font-size: .72rem;
        letter-spacing: .02em;
        user-select: none;
    }
    .claim-anchors summary:hover { color: #161616; }
    .claim-anchors[open] summary {
        border-bottom: 1px solid #d7d9dd;
        color: #525252;
    }
    .anchor-detail {
        padding: 8px 10px;
        display: flex;
        flex-direction: column;
        gap: 5px;
    }
    .anchor-refs {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .anchor-ref {
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
        font-size: .72rem;
        color: #525252;
        word-break: break-all;
        padding: 1px 4px;
        background: #e8e8e8;
        border-radius: 2px;
        display: inline-block;
    }
    .anchor-receipt {
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
        font-size: .72rem;
        color: #1f7a4d;
        padding: 1px 4px;
        background: #eef5f0;
        border-radius: 2px;
    }
    .anchor-field {
        font-size: .68rem;
        text-transform: uppercase;
        letter-spacing: .06em;
        color: #6b7280;
        margin-right: 4px;
    }
    .anchor-digest, .anchor-window, .anchor-receipts {
        font-size: .74rem;
        color: #6b7280;
    }

    .result-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 10px;
        font-size: .72rem;
        font-weight: 600;
        letter-spacing: .03em;
        text-transform: uppercase;
        white-space: nowrap;
    }
    .result-pass { color: #1f7a4d; background: #eef5f0; }
    .result-partial { color: #a56a00; background: #faf3e8; }
    .result-present { color: #355c7d; background: #edf2f7; }
    .result-fail { color: #b42318; background: #faeae8; }
    .ev-machine { color: #1f7a4d; font-weight: 600; }
    .ev-human { color: #355c7d; font-weight: 600; }
    .tier-core { font-weight: 600; }
    .tier-claim { color: #6b7280; }
    .tier-court { color: #5a2d7a; font-weight: 600; }

    /* --- Evidence summary --- */

    .evidence-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 12px;
        margin-bottom: 14px;
    }
    .ev-card {
        text-align: center;
        padding: 18px 12px;
        background: #f6f5f2;
        border: 1px solid #d7d9dd;
        border-radius: 8px;
    }
    .ev-number {
        display: block;
        font-size: 1.8rem;
        font-weight: 700;
        line-height: 1.1;
        margin-bottom: 4px;
        color: #161616;
    }
    .ev-label {
        display: block;
        font-size: .72rem;
        text-transform: uppercase;
        letter-spacing: .06em;
        color: #6b7280;
    }
    .ev-machine-card { border-color: #c0d8c8; }
    .ev-machine-card .ev-number { color: #1f7a4d; }
    .ev-human-card { border-color: #b8c8d8; }
    .ev-human-card .ev-number { color: #355c7d; }
    .ev-details {
        font-size: .84rem;
        color: #6b7280;
        margin-top: 8px;
    }
    .ev-details strong { color: #161616; }

    /* --- Coverage map --- */

    .cov-summary {
        display: flex;
        align-items: baseline;
        gap: 10px;
        margin-bottom: 16px;
    }
    .cov-ratio {
        font-size: 1.6rem;
        font-weight: 700;
        color: #161616;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }
    .cov-pct {
        font-size: 1.6rem;
        font-weight: 700;
        color: #161616;
    }
    .cov-detail {
        font-size: .88rem;
        color: #6b7280;
    }
    .cov-covered { color: #1f7a4d; font-weight: 600; }
    .cov-missing { color: #b42318; font-weight: 600; }
    .cov-reason {
        font-size: .78rem;
        color: #a56a00;
        font-weight: 400;
        margin-top: 2px;
    }
    .cov-provenance {
        background: #f6f5f2;
        border: 1px solid #d7d9dd;
        border-radius: 6px;
        padding: 14px 16px;
        margin-bottom: 16px;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }
    .prov-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        margin-bottom: 8px;
    }
    .prov-cell {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .prov-label {
        font-size: .6rem;
        text-transform: uppercase;
        letter-spacing: .1em;
        color: #6b7280;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }
    .prov-value {
        font-size: .82rem;
        color: #525252;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }
    .prov-notes {
        list-style: none;
        padding: 0;
        margin: 0;
    }
    .prov-notes li {
        font-size: .78rem;
        color: #6b7280;
        line-height: 1.5;
        padding: 3px 0;
        border-top: 1px solid #e8e8e8;
        font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    .prov-notes li:first-child { border-top: none; }

    /* --- Signature --- */

    .sig-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
        gap: 10px;
        margin-bottom: 10px;
    }
    .sig-value {
        margin-top: 6px;
        padding: 10px 14px;
        background: #f6f5f2;
        border: 1px solid #d7d9dd;
        border-radius: 6px;
    }
    .sig-value .label { margin-bottom: 6px; }

    /* --- Relationships / Lineage --- */

    .rel-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
        gap: 10px;
    }
    .rel-cell {
        background: #f6f5f2;
        border: 1px solid #d7d9dd;
        border-radius: 6px;
        padding: 12px 14px;
    }
    .rel-challenge { border-color: #a56a00; border-left: 3px solid #a56a00; background: #fcfcfb; }

    /* --- Challenge section --- */

    .section-challenge {
        background: #f6f5f2;
        border: 1px solid #d7d9dd;
        border-left: 3px solid #a56a00;
        border-radius: 2px 8px 8px 2px;
        padding: 20px 22px;
    }
    .section-challenge h2 { border-bottom-color: #d7d9dd; }
    .section-challenge ol { padding-left: 22px; }
    .section-challenge li { font-size: .9rem; margin-bottom: 8px; }

    /* --- Chain / Issuer --- */

    .chain-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
        gap: 10px;
    }

    /* --- Verification details (collapsible) --- */

    .verification-details {
        margin-bottom: 48px;
        border: 1px solid #d7d9dd;
        border-radius: 8px;
        background: #f6f5f2;
    }
    .verification-details > summary {
        padding: 14px 20px;
        cursor: pointer;
        font-size: .86rem;
        font-weight: 600;
        color: #6b7280;
        letter-spacing: .02em;
        user-select: none;
    }
    .verification-details > summary:hover { color: #161616; }
    .verification-details[open] > summary {
        border-bottom: 1px solid #d7d9dd;
        color: #525252;
    }
    .vd-content {
        padding: 20px;
    }

    /* --- Tones --- */

    .tone-warn { color: #a56a00; font-weight: 600; }
    .tone-dim { color: #6b7280; }

    /* --- Footer --- */

    footer {
        margin-top: 64px;
        padding-top: 18px;
        border-top: 1px solid #d7d9dd;
        color: #6b7280;
        font-size: .82rem;
    }
    .footer-id { margin-top: 4px; }
    .footer-id code {
        background: #f6f5f2;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: .72rem;
        word-break: break-all;
        font-family: 'IBM Plex Mono', 'SFMono-Regular', Consolas, monospace;
    }

    /* --- Responsive --- */

    @media (max-width: 600px) {
        .meta-strip { grid-template-columns: repeat(2, 1fr); }
        .scope-grid { grid-template-columns: 1fr; }
        .evidence-grid { grid-template-columns: 1fr; }
        .rel-grid { grid-template-columns: 1fr; }
        .triad { grid-template-columns: 1fr; }
        .ds-line { flex-direction: column; gap: 2px; }
        .ds-key { min-width: auto; }
        .posture-strip { flex-direction: column; }
        .verifier-strip { flex-direction: column; }
        .vstrip-cell { flex-direction: row; justify-content: space-between; border-right: none; border-bottom: 1px solid #2a2a2a; }
        .vstrip-cell:last-child { border-bottom: none; }
        h1 { font-size: 1.4rem; }
    }
""")

