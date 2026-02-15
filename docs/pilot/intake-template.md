# Pilot Intake Form

Send this to prospects before the kickoff call. Filling it out before the
call means we spend the hour on scoping and decisions, not data collection.

---

## Company / Project

- **Company name**:
- **Project / product name**:
- **Team size** (engineers who touch AI code):
- **Your role**:

## AI System

- **What does it do?**
  <!-- RAG pipeline, autonomous agent, chatbot with tool use, multi-agent orchestration, etc. -->

- **LLM providers in use**:
  - [ ] OpenAI
  - [ ] Anthropic
  - [ ] LangChain
  - [ ] LiteLLM
  - [ ] Self-hosted (Ollama, vLLM, etc.)
  - [ ] Other: ___

- **Languages / frameworks**:
  <!-- e.g., Python 3.11, FastAPI, LangGraph -->

- **Approximate number of LLM call sites**:
  <!-- If you've run `assay scan .`, paste the summary line below -->

- **Number of repos with LLM calls**:

- **CI/CD system**:
  - [ ] GitHub Actions
  - [ ] GitLab CI
  - [ ] Jenkins
  - [ ] CircleCI
  - [ ] Other: ___

## Compliance Context

- **Current or upcoming compliance requirements**:
  - [ ] SOC 2
  - [ ] HIPAA
  - [ ] EU AI Act (Articles 12 & 19)
  - [ ] ISO 42001
  - [ ] Internal audit policy
  - [ ] None yet (being proactive)
  - [ ] Other: ___

- **Is this driven by a specific audit or deadline?**
  <!-- e.g., "SOC 2 audit scheduled for Q3 2026" or "Proactive, no deadline" -->

- **Who reviews compliance evidence today?**
  <!-- Security team, external auditor, legal, nobody yet -->

## Desired Outcome

- **What outcome matters most?**
  - [ ] CI gate preventing unverified deployments
  - [ ] Audit trail for compliance reviews
  - [ ] Evidence of AI system behavior for stakeholders
  - [ ] Regression detection (cost / latency / error drift)
  - [ ] Other: ___

- **What does success look like for this pilot?**
  <!-- e.g., "proof packs generated on every merge, verifiable offline by our security team" -->

## Access

- **Repository access**: Can you grant read-only access to the repo(s) in scope?
  - [ ] Yes
  - [ ] Need to check with security

- **CI/CD access**: Can you grant access to add a pipeline step?
  - [ ] Yes
  - [ ] Need to check with DevOps

- **Point of contact** (name + preferred async channel):

## Scan Output (if available)

If you've already run Assay, paste the output here:

```bash
# Install and scan:
pip install assay-ai
assay scan . --report
```

<!-- Paste scan summary or attach the HTML report -->

## Timeline

- **When do you want to start?**
- **Any hard deadlines?** (audit date, board review, compliance filing)
- **Preferred communication**: Slack / email / other

## Anything Else

<!-- Constraints, concerns, questions, prior tools evaluated, etc. -->
