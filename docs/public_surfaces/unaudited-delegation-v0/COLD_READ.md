# Cold Read

Use this checklist with a reader who has not helped write the packet.

The packet passes the cold read only if the reader understands that it is about:

```text
verified change evidence, not verified understanding
```

## Reader Questions

1. Does this packet claim that Assay proves an AI agent understood the codebase?
2. Does a `PASS_WITH_CAVEATS` verdict mean the PR is ready for merge?
3. Why is `NEEDS_SPLIT` a valuable verdict?
4. What evidence would a refactor-only claim need before review can proceed?
5. What should a reviewer refuse to infer from these examples?
6. Did an Assay tool emit these proof-card examples, or did a human write them?

## Expected Answers

1. No. It says Assay checks bounded claims and captured evidence under policy.
2. No. It means review can proceed with named caveats; merge remains outside the verdict.
3. It protects reviewer attention when a delegated change is too broad to approve honestly.
4. At minimum, scoped diff evidence, tests or replay evidence tied to the changed behavior, and a policy reason to believe public behavior did not change.
5. The reviewer should not infer correctness, security, production approval, general agent obedience, or model understanding.
6. A human wrote them as illustrative read models. The current engine does not emit this full verdict vocabulary.

## Failure Modes

The packet fails the cold read if the reader concludes:

- Assay establishes correctness
- Assay proves code security
- Assay proves model understanding
- PR Gate verdicts are merge approvals
- bigger AI diffs are acceptable as long as tests exist
- the proof-card examples are generated verifier output
- `NEEDS_SPLIT` is a failure rather than a review-protection outcome
