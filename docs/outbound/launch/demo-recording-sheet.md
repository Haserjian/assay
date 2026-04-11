# Demo Recording Sheet

## Capture Settings

- Shell: `zsh`
- Font size: `15`
- Window size: `920 x 580`
- Theme: `Catppuccin Mocha`
- Padding: `20`
- Typing speed if scripted: `40ms`
- Keep one terminal visible. No split panes.

## File Tabs To Keep Open

- Start with no extra tabs visible.
- First file tab: `challenge_pack/good/receipt_pack.jsonl`
- Second file tab: `challenge_pack/edited/receipt_pack.jsonl` only after the copy step creates it.
- Close or hide unrelated repo tabs before recording.

## Off-Camera Pre-Run Commands

```bash
cd /Users/timmybhaserjian/assay
export PATH="/Users/timmybhaserjian/assay/.venv/bin:$PATH"
export ASSAY_FEEDBACK_URL="https://short.example/assay-feedback"
rm -rf challenge_pack challenge_pack/edited
assay version >/dev/null
```

## Cleanup After A Failed Take

```bash
rm -rf challenge_pack challenge_pack/edited
```

## Preflight Checklist

- Clear the edited directory: `rm -rf challenge_pack/edited`
- Use `/bin/cp`, not `cp`
- Confirm the field is `model_id` in `challenge_pack/good/receipt_pack.jsonl`
- Confirm the stable pass strings: `VERIFICATION PASSED`, `Integrity: PASS`, `Claims: PASS`
- Confirm the stable fail strings: `VERIFICATION FAILED`, `E_MANIFEST_TAMPER`
- Confirm whether the standalone pass view also shows the trust warning below the panel; keep the frame on the PASS block unless you want to explain lock-based trust pinning on screen
- If using a short feedback URL, export `ASSAY_FEEDBACK_URL` before recording
- Confirm the footer URL is the intended shortlink or accept the Discussions fallback

## Exact Commands

```bash
assay demo-challenge
assay verify-pack challenge_pack/good/
/bin/cp -R challenge_pack/good challenge_pack/edited
perl -0pi -e 's/gpt-4/gpt-5/' challenge_pack/edited/receipt_pack.jsonl
assay verify-pack challenge_pack/edited/
```

## Exact File Opens

- Open [challenge_pack/good/receipt_pack.jsonl](challenge_pack/good/receipt_pack.jsonl#L1)
- Highlight line 1 field `"model_id":"gpt-4"`
- Open `challenge_pack/edited/receipt_pack.jsonl`
- Highlight line 1 field `"model_id":"gpt-5"`

## Stable Strings To Zoom On

- `VERIFICATION PASSED`
- `Integrity:  PASS`
- `Claims:     PASS`
- `VERIFICATION FAILED`
- `E_MANIFEST_TAMPER`

## 60-Second Timing Table

| Time | Action | Pause | Zoom | Narration |
|---|---|---:|---|---|
| 0:00-0:02 | Title card: `Change one field. Verification fails.` | 2.0s | None | Most AI systems can show logs. Fewer can hand another team evidence they can verify offline. |
| 0:02-0:07 | Run `assay demo-challenge` | 4.0s | Terminal center at 110% | Assay creates a good pack and a tamper path you can inspect. |
| 0:07-0:13 | Run `assay verify-pack challenge_pack/good/` | 4.0s | `VERIFICATION PASSED`, `Integrity: PASS`, `Claims: PASS` at 155% | First, verify the good pack. |
| 0:13-0:18 | Open `challenge_pack/good/receipt_pack.jsonl` | 2.0s | Line 1 at 200% | This is the receipt stream. Highlight `model_id: gpt-4` on line one. |
| 0:18-0:22 | Run `/bin/cp -R challenge_pack/good challenge_pack/edited` | 1.0s | Command line at 115% | Copy the good pack. |
| 0:22-0:27 | Run the `perl` mutation | 1.5s | Command line at 135% | Now change one meaningful field after the run: gpt-4 becomes gpt-5. |
| 0:27-0:32 | Open `challenge_pack/edited/receipt_pack.jsonl` | 2.0s | Line 1 at 200% | Reopen the copied receipt stream and highlight `model_id: gpt-5` on line one. |
| 0:32-0:40 | Run `assay verify-pack challenge_pack/edited/` | 4.5s | `VERIFICATION FAILED` and `E_MANIFEST_TAMPER` at 165% | Verify again. No rerun. No resigning. Just a post-run edit. |
| 0:40-0:52 | Hold on failure block | 2.5s | Mismatch line at 150% | The verifier catches it immediately: hash mismatch for the receipt stream. No server call. Just math. |
| 0:52-1:00 | End card: `Logs explain. Proof transfers.` | 8.0s | Slow push from 105% to 120% | A signed failure is better than an unverifiable success claim. |

## 30-Second Timing Table

| Time | Action | Pause | Zoom | Narration |
|---|---|---:|---|---|
| 0:00-0:02 | Title card: `Signed proof pack -> semantic tamper -> fail` | 2.0s | None | This is a signed proof pack for an AI run. |
| 0:02-0:06 | Run `assay verify-pack challenge_pack/good/` | 2.5s | `VERIFICATION PASSED` at 155% | The good pack passes. |
| 0:06-0:09 | Open `challenge_pack/good/receipt_pack.jsonl` line 1 | 1.5s | `"model_id":"gpt-4"` at 200% | The receipt says gpt-4. |
| 0:09-0:14 | Run copy and edit commands | 1.0s between commands | Terminal at 135% | Now change gpt-4 to gpt-5 after the run. |
| 0:14-0:21 | Run `assay verify-pack challenge_pack/edited/` | 3.5s | `VERIFICATION FAILED` and `E_MANIFEST_TAMPER` at 170% | Verify again. No server call. Just math. |
| 0:21-0:30 | End card: `Logs explain. Proof transfers.` | 9.0s | Slow push | That is the difference between logs and proof. |
