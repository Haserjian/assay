#!/usr/bin/env python3
"""The Byte-Flip Demo -- tamper detection that refuses to over-speak.

Proves, end to end, that an Assay Proof Pack is tamper-evident AND that the
verifier states its own boundary: when one byte of evidence changes, the
verdict does not merely turn red -- the machine-readable `scope` object
collapses to claiming only that tampering was detected, and moves every
integrity fact into `does_not_prove`. A broken evidence object cannot vouch
for anything except the fact that it is broken.

Sequence (real captured output, no hand-written results):
  1. Build a small signed Proof Pack from synthetic receipts (tmp keystore).
  2. verify-pack  -> exit 0, overall PASS, scope.proves lists integrity facts.
  3. Flip exactly one byte in receipt_pack.jsonl (deterministic; offset and
     before/after byte are recorded).
  4. verify-pack  -> exit 2, overall TAMPERED, scope.proves collapses to
     ["tamper_evidence_detected"]; integrity facts move to does_not_prove.
  5. Restore the byte, verify-pack -> exit 0 again. Detection is real and the
     evidence object is recoverable.

What this demo PROVES:
  - The pack is tamper-evident: a single-byte change is detected (exit 2).
  - The verifier reports its own boundary: on tamper, scope.proves ==
    ["tamper_evidence_detected"] and integrity facts move to does_not_prove.

What this demo does NOT prove:
  - instrumentation completeness, output correctness/safety, business-policy
    fitness, legal compliance, or anything about a real agent workload. The
    pack here is synthetic. This demo exercises the integrity + scope channels
    only; claim/replay/trust are not evaluated.

Machine-state independence (hard requirement):
  Every operation runs under an isolated temporary HOME with a throwaway
  keystore. The verifier resolves its store from Path.home()/.assay via a
  process-level singleton (assay.store._default_store); we point HOME at a tmp
  dir before first use and reset that singleton, so the operator's real
  ~/.assay is never read or written and the verdicts are identical on a clean
  machine and on a host with a populated legacy store.

Run:
    python examples/byte_flip_demo.py                  # run the demo
    python examples/byte_flip_demo.py --transcript out.md   # also write transcript
    python examples/byte_flip_demo.py --self-check     # assert acceptance, exit 0/1
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

_SRC = str(Path(__file__).resolve().parent.parent / "src")

# Deterministic synthetic receipts -- fixed content so offsets are stable and
# runs are reproducible. One carries model_id "gpt-4o": the byte we flip.
_RECEIPTS = [
    {"receipt_id": "r_0", "type": "model_call", "schema_version": "3.0", "seq": 0,
     "timestamp": "2026-06-10T00:00:00+00:00", "model_id": "gpt-4o", "total_tokens": 57},
    {"receipt_id": "r_1", "type": "model_call", "schema_version": "3.0", "seq": 1,
     "timestamp": "2026-06-10T00:00:01+00:00", "model_id": "gpt-4o", "total_tokens": 99},
    {"receipt_id": "r_2", "type": "guardian_verdict", "schema_version": "3.0", "seq": 2,
     "timestamp": "2026-06-10T00:00:02+00:00", "verdict": "allow", "tool": "web_search"},
]


def _isolate_home(root: Path) -> str:
    """Point HOME at a tmp dir and reset the store singleton, before any store use."""
    home = root / "home"
    home.mkdir(exist_ok=True)
    os.environ["HOME"] = str(home)
    os.environ["USERPROFILE"] = str(home)  # Path.home() on Windows
    try:
        import assay.store as _store
        _store._default_store = None  # rebuild against isolated HOME on next use
    except Exception:
        pass
    return str(home)


def build_pack(root: Path) -> Path:
    """Build a signed Proof Pack from synthetic receipts using a throwaway keystore."""
    if _SRC not in sys.path:
        sys.path.insert(0, _SRC)
    from assay.keystore import AssayKeyStore
    from assay.proof_pack import ProofPack

    ks = AssayKeyStore(keys_dir=root / "keys")
    ks.generate_key("demo-signer")
    pack_dir = root / "pack"
    return ProofPack(
        run_id="byte-flip-demo-001",
        entries=_RECEIPTS,
        signer_id="demo-signer",
        mode="shadow",
    ).build(pack_dir, keystore=ks)


def verify(pack_dir: Path, report_path: Path, home: str) -> Tuple[int, Dict[str, Any]]:
    """Run `assay verify-pack` as an isolated subprocess; return (exit_code, report)."""
    env = {**os.environ, "HOME": home, "USERPROFILE": home, "PYTHONPATH": _SRC}
    proc = subprocess.run(
        [sys.executable, "-m", "assay", "verify-pack", str(pack_dir),
         "--json", "--out", str(report_path)],
        capture_output=True, text=True, env=env,
    )
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    return proc.returncode, report


def flip_one_byte(path: Path) -> Tuple[int, int, int]:
    """Flip exactly one content byte (inside the first model_id value). Returns
    (offset, before, after). Deterministic and reversible."""
    raw = bytearray(path.read_bytes())
    marker = b"gpt-4o"
    idx = raw.find(marker)
    offset = idx + len(marker) - 1 if idx != -1 else len(raw) // 2  # the 'o'
    before = raw[offset]
    raw[offset] = before ^ 0x01
    path.write_bytes(raw)
    return offset, before, raw[offset]


def restore_byte(path: Path, offset: int, before: int) -> None:
    raw = bytearray(path.read_bytes())
    raw[offset] = before
    path.write_bytes(raw)


def _scope(report: Dict[str, Any]) -> Dict[str, Any]:
    return report.get("scope", {})


def run_demo() -> Tuple[List[str], Dict[str, Any]]:
    """Execute steps 1-5, capturing real output. Returns (transcript_lines, results)."""
    out: List[str] = []
    p = out.append
    results: Dict[str, Any] = {}

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        home = _isolate_home(root)

        p("# The Byte-Flip Demo")
        p("")
        p(f"Isolated HOME: {home}  (real ~/.assay never touched)")
        p("")

        # --- Step 1: build ---
        pack = build_pack(root)
        receipt_file = pack / "receipt_pack.jsonl"
        p("## 1. Build Proof Pack (synthetic receipts, throwaway keystore)")
        p(f"    pack: {pack}")
        p(f"    files: {', '.join(sorted(f.name for f in pack.iterdir()))}")
        p("")

        # --- Step 2: verify clean ---
        code, rep = verify(pack, root / "report_clean.json", home)
        sc = _scope(rep)
        results["clean"] = {"exit": code, "verdict": rep.get("overall_verdict"),
                            "proves": sc.get("proves")}
        p("## 2. Verify (intact)")
        p(f"    $ python -m assay verify-pack {pack.name} --json --out report_clean.json")
        p(f"    exit: {code}    overall_verdict: {rep.get('overall_verdict')}")
        p(f"    scope.proves:        {sc.get('proves')}")
        p(f"    scope.does_not_prove: {sc.get('does_not_prove')}")
        p(f"    scope.channels:      {sc.get('channels')}")
        p("")

        # --- Step 3: flip one byte ---
        offset, before, after = flip_one_byte(receipt_file)
        results["flip"] = {"offset": offset, "before": before, "after": after}
        p("## 3. Flip exactly one byte in receipt_pack.jsonl")
        p(f"    offset {offset}: byte {before} (0x{before:02x} {chr(before)!r}) "
          f"-> {after} (0x{after:02x} {chr(after)!r})")
        p("")

        # --- Step 4: verify tampered ---
        code, rep = verify(pack, root / "report_tamper.json", home)
        sc = _scope(rep)
        results["tamper"] = {"exit": code, "verdict": rep.get("overall_verdict"),
                             "proves": sc.get("proves")}
        p("## 4. Verify (tampered)")
        p(f"    exit: {code}    overall_verdict: {rep.get('overall_verdict')}")
        p(f"    scope.proves:        {sc.get('proves')}    <-- collapsed")
        p(f"    scope.does_not_prove: {sc.get('does_not_prove')}")
        p(f"    scope.note:          {sc.get('note')}")
        p("")

        # --- Step 5: restore, verify clean again ---
        restore_byte(receipt_file, offset, before)
        code, rep = verify(pack, root / "report_restored.json", home)
        sc = _scope(rep)
        results["restored"] = {"exit": code, "verdict": rep.get("overall_verdict"),
                               "proves": sc.get("proves")}
        p("## 5. Restore the byte, verify again")
        p(f"    exit: {code}    overall_verdict: {rep.get('overall_verdict')}")
        p(f"    scope.proves:        {sc.get('proves')}")
        p("")
        p("Detection is real and the evidence object is recoverable.")

    return out, results


def self_check() -> int:
    """Assert the acceptance conditions. Exit 0 if all hold, 1 otherwise."""
    _, r = run_demo()
    checks = [
        ("step 2 exits 0", r["clean"]["exit"] == 0),
        ("step 2 scope present", bool(r["clean"]["proves"])),
        ("step 4 exits nonzero", r["tamper"]["exit"] != 0),
        ("step 4 scope.proves == ['tamper_evidence_detected']",
         r["tamper"]["proves"] == ["tamper_evidence_detected"]),
        ("step 5 exits 0", r["restored"]["exit"] == 0),
    ]
    print("SELF-CHECK")
    ok = True
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="The Byte-Flip Demo")
    ap.add_argument("--self-check", action="store_true",
                    help="Assert acceptance conditions; exit 0/1.")
    ap.add_argument("--transcript", metavar="PATH",
                    help="Also write the captured transcript to this file.")
    args = ap.parse_args()

    if args.self_check:
        return self_check()

    lines, _ = run_demo()
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if args.transcript:
        Path(args.transcript).write_text(text)
        print(f"\n[transcript written to {args.transcript}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
