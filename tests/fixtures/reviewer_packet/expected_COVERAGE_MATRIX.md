# Coverage Matrix

| Claim / Question | Status | Evidence | Scope | Notes |
| --- | --- | --- | --- | --- |
| Can the reviewer verify the proof artifact offline? | EVIDENCED | proof_pack/verify_report.json#claim_verification.passed | Whole packet | The nested proof pack passes its declared claims and is verifiable offline. |
| Is all identified workflow coverage complete? | PARTIAL | SCOPE_MANIFEST.json#callsites_instrumented and SCOPE_MANIFEST.json#callsites_identified | Support workflow only | Coverage is partial because the sample shows 4 of 5 identified call sites in the packet boundary. |
| Does this packet establish legal or regulatory compliance? | OUT_OF_SCOPE | None | Out of scope for this packet | Packet provides evidence, not legal conclusions. |
