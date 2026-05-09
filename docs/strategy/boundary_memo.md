# Assay Boundary Memo

Status: Boundary decision draft
Date: 2026-05-01

## Working Position

Assay becomes the public receipt layer when other systems can emit, attach,
verify, and cite Assay proof packs without adopting the Assay internal runtime.

The public product is not Loom, CCIO, AgentMesh, Guardian, or Execution Spine.
Those can remain internal infrastructure. Public Assay is the evidence
boundary: external workflow evidence in, Assay Proof Pack out, independent
verification after.

## Operational Definition

Assay is boundary-stable when one non-Assay runtime can produce evidence that
Assay converts into an Assay Proof Pack, verifies offline, explains honestly,
and fails correctly under tampering.

Gate sentence:

> Boundary stable = one external evidence source can be bridged into an Assay
> Proof Pack, independently verified, honestly explained, and tamper-failed,
> with no dependency on the internal runtime.

## Pinned Choices

1. Public object: `Assay Proof Pack`

   "Receipt" remains informal language for slogans, docs, and positioning. It
   is not the schema noun for this boundary.

2. Signing scope: bridge v0 is hash-chain integrity only

   Signing is not a bridge-v0 gate condition. The existing proof-pack kernel has
   signing behavior documented in `docs/contracts/PACK_CONTRACT.md`, but this
   memo does not use signing as the test for public boundary stability.

   Bridge v0 must prove hash/tamper integrity first. Signature policy for this
   public bridge is deferred until after the v0 schema and verifier contract are
   frozen.

3. First bridge source: CLI command output

   The first external evidence source is command execution output, because it
   exists everywhere and requires no upstream instrumentation.

   Bridge v0 captures:

   - command
   - stdout
   - stderr
   - exit code
   - timestamps
   - working directory
   - evidence hashes

   Environment capture is excluded from v0. If needed later, it must be
   default-deny and explicitly allowlisted per invocation.

   OTel, LangSmith, MCP, GitHub Actions, and model-provider traces are v1+
   adapters after the schema and verifier contract are stable.

4. Independent verification: byte-deterministic offline verification

   The verifier accepts a proof pack as its only input, makes no network calls,
   shares no state with the producer, and returns the same result for the same
   proof-pack kernel file bytes.

5. Schema anchor: frozen proof-pack v0 schema

   The boundary gate requires a frozen `Assay Proof Pack v0` schema with an
   explicit version field. Until that exists, the verifier contract has no stable
   shape to verify against.

   Existing proof-pack behavior is documented in
   `docs/contracts/PACK_CONTRACT.md` as draft and extracted from code. This
   memo does not freeze that contract by declaration.

## Relationship To Output Assay v0

`output-assay` v0, landed on 2026-04-30, is not greenfield work to replace. It
is the nearest existing sibling of the bridge strategy.

What it already proves:

- observation is not assertion;
- local deterministic stamping is possible;
- artifact hashes can anchor evidence;
- draft schemas and fixture contracts can fail closed;
- Guardian-level outcomes can distinguish pass, warn, and block;
- truth-verification humility can be explicit: internal support is not external
  truth.

What it does not yet prove for this boundary:

- command output can be converted into an Assay Proof Pack;
- the public proof-pack schema is frozen;
- `assay verify-pack` can treat the proof pack as its only input and return a
  byte-deterministic result;
- `assay explain` emits the required proven / not-proven / unsupported split;
- tamper cases for the public bridge are all exercised as boundary tests.

Therefore the next strike should extend the Output Assay pattern, not fork it:

```text
external command output -> bridge -> Assay Proof Pack -> offline verifier -> honest explain output
```

Output Assay remains the observation-layer reference pattern. The bridge is the
public proof-pack boundary test.

## Target Public Surface

The boundary target has three public surfaces:

1. Format: the Assay Proof Pack schema.
2. Verifier: `assay verify-pack` and `assay explain`.
3. Bridge: command output to Assay Proof Pack.

Agent interfaces, examples, demos, docs, and MCP tools are delivery channels.
They do not become new product surfaces until the boundary is stable.

## Verifier Semantics

Verification failure and epistemic honesty are separate.

`FAIL` is reserved for structural or integrity failure:

- malformed proof pack;
- missing evidence reference;
- modified evidence hash;
- hash-chain or tamper mismatch.

Unsupported claims are not verification failures. They populate `not_proven` or
`unsupported_claims` in the explanation output.

Every verification result must return:

```text
PASS/FAIL
proven claims
not_proven claims
unsupported claims
evidence refs
hash/tamper status
verifier version
schema version
```

The verifier must be honest even when it passes. A passing proof pack can still
contain claims Assay does not prove.

## Boundary Gate

Assay is boundary-stable when all structural conditions pass:

1. One public object

   The public artifact is `Assay Proof Pack`.

2. One frozen schema

   `Assay Proof Pack v0` has an explicit version field and a frozen shape for
   the bridge/verifier contract.

3. One adapter works

   CLI command output can be converted into a proof pack.

   ```text
   command output -> assay bridge -> proof pack -> assay verify-pack -> assay explain
   ```

4. Verifier contract is stable

   The verifier returns the required result fields, including `not_proven`,
   `unsupported_claims`, `schema version`, and `verifier version`.

5. Negative cases pass

   The verifier correctly fails on:

   - modified evidence hash;
   - missing evidence ref;
   - malformed proof pack;
   - hash-chain or tamper mismatch.

   Unsupported claims do not fail verification. They must be surfaced as not
   proven.

6. No runtime dependency

   The demo does not require Loom, CCIO, AgentMesh, Guardian, Execution Spine,
   or any internal organism component.

7. Explain output is honest

   `not_proven` is required output, not optional commentary.

## Pre-Public Launch Check

Language stability is not part of the structural boundary gate. It is a
separate launch-readiness check.

Before public launch, Assay must be describable without adding new nouns:

> Assay turns external AI workflow evidence into verifiable proof packs.

Public Assay should always pass this positioning test:

> Can another system produce evidence, hand it to Assay, receive a proof pack,
> and verify that proof pack later without adopting our runtime?

If yes, it belongs in public Assay.

If no, it is internal infrastructure.

## Single Next Strike

Build the v0 bridge over CLI command output.

The smallest proof loop is:

```bash
assay bridge command-output --out .assay/proof_pack/ -- <command>
assay verify-pack .assay/proof_pack/
assay explain .assay/proof_pack/
```

Then mutate the proof pack or evidence and confirm verification fails for
structural/tamper reasons while unsupported claims remain honest non-failures.

## Deferred Bucket

Do not start these until the boundary gate passes:

- PR Receipts
- MCP Server Auditor
- OTel bridge
- LangSmith bridge
- hosted ledger
- scorecard
- Agent Passport
- AdOps decision packets
- Break the Claim
- public reputation network

These are downstream applications of the boundary, not ways to discover it.
