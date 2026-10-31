# Research Imaging Data De-identification System

> A resident daemon turns a batch of imaging studies and reports into a redacted copy that is ready to hand over: one consistent pseudonym per patient across all materials, a per-hit manifest that never stores the matched text, an automatic residual scan, and a platform-side delivery receipt; restoring any case to its original text requires two approvers and leaves a restore receipt.

## What It Is / Who It Is For

The hard part of research imaging data is not *finding* a name — it is finding it and still *recognising* it: the same patient appears in three reports, and a fresh number each time breaks the link; dosages, amounts, and page numbers look like admission numbers, so a blunt filter also strips out disease names and drug names; and after redaction nobody can tell whether anything was missed. This system covers exactly that gap — it turns one batch of material into a copy that can be delivered as-is, and every step leaves a trace.

| Role | When they use it | What they get |
|------|------------------|----------------|
| Research data administrator | After a batch of images and reports is assembled into the delivery directory per the ethics approval | A redacted copy ready to hand over, a per-hit manifest, and a platform-side delivery receipt |
| Ethics office | Reviewing whether a batch stayed within the scope of the ethics approval | An account of every change in the batch plus the residual-scan verdict |
| IT department | Daily check for backed-up or failed batches | Batch timelines, failure reasons, pending-delivery queue length |
| Research data administrator | When ethics or a data audit requires a few cases to be restored to original text | One controlled restore after two-person approval, plus a restore receipt |

Sampling review is optional and is **not** a release gate: as soon as the ethics approval number is present and the residual scan raises no warning, the batch is delivered automatically.

## Core Capabilities

- **One consistent pseudonym per patient across every material** — codes agree across reports and images, because the code is derived from a keyed patient master key rather than a random number (enable the consistent-code profile with `RESEARCH_POLICY_PROFILE=pseudonym`; the default profile substitutes in-place placeholders).
- **Disease names, drug names, dosages, amounts, and page numbers are never redacted by mistake** — numeric look-alikes are disambiguated by digit count, prefix, and neighbouring words; an allowlist backstops test-item names and department names.
- **Automatic re-scan after redaction**: any identity string that slipped through blocks the batch from being delivered and raises an alert — it is never handed over silently.
- **A missing ethics approval number blocks the batch**, and an unreachable master index suspends it — it never degrades into "hard-redact by name and release".
- **Re-delivering the same batch delivers it once**: an idempotency key prevents duplicate outbound calls, and a restarted process resumes from its checkpoint.
- **Restoring to original text requires two approvers and expires**: expired, out-of-scope, or single-approver requests are refused and leave an access trace.

## Quick Start

Requirements: Python **3.11+**. Runtime dependencies `pyyaml`, `httpx`, `openpyxl`, `pydantic`, `cryptography`; dev dependency `pytest`. No GPU, no model weights — the whole chain is deterministic (no language model is involved).

```bash
cd research-data-redact
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env          # fill in endpoints, tokens, HMAC key, WeCom webhook
set -a && . ./.env && set +a
pytest tests -q               # full test suite
```

Start the resident daemon and watch the delivery directory:

```bash
python -m research_redact.daemon              # resident daemon (main entry)
python -m research_redact.daemon --once       # run one cycle then exit (debugging)
python -m research_redact.cli scan            # list pending batches and ledger state
```

The daemon's first screen is a structured run log: a configuration receipt (policy table loaded, which channels are configured, which are suspended), then heartbeat lines; as soon as an application form appears in the delivery directory it prints a `batch_processed` summary (material count / identity hits / residual verdict / elapsed ms).

## Repository Structure

```
research-data-redact/
├── src/research_redact/    # product code: recognizers, policy, audit, daemon, outbound clients, restore
├── policy/research.yaml    # policy table: thresholds, actions, allowlist, context words, conflict priority
├── scripts/                # reproducible corpus generation and benchmark / baseline-comparison scripts
├── tests/                  # unit + contract tests (protocol doubles live in the test layer only)
├── fixtures/               # synthetic Chinese radiology / lab report samples
├── reports/                # baseline-comparison.md / performance.md (reproducible experiment output)
├── docs/                   # concepts/ visual target card, screenshots/ real run captures
└── pyproject.toml          # packaging and dependency manifest (src layout)
```

Full documentation: see README.md (Chinese)

---

## Follow Us

Scan the QR code to follow our official account for updates and community access:

![Follow Us](qrcode.jpg)