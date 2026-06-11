# Corpus

This directory holds redcell's **probe cases** — the defensive benchmark of
behaviors an agent should resist, organized by OWASP Top 10 for Agentic
Applications (2026) category. Cases are data, loaded and validated by
`redcell.corpus_loader`.

The corpus is split by category: `asi01.yaml`, `asi02.yaml`, `asi03.yaml`,
`asi05.yaml`, and `asi06.yaml` — the five MVP categories whose behavior a
single-target, black-box harness can score soundly. Nothing here is a turnkey
exploit: each case describes a behavior to *test for* — paired with a
deterministic oracle that detects whether the target exhibited it — so you can
confirm your own agent handles it safely.

## How the cases are generated (and what the count means)

The ~146 cases are **template × delivery-vector expansions**, not 146 unrelated
payloads. A handful of probe *templates* per category (e.g. "goal hijack →
canary exfiltration", "external-recipient email", "code-into-exec-tool") are
expanded systematically across the five delivery vectors (`user_message`,
`tool_result`, `retrieved_document`, `memory`, `system_prompt`) and minor
wording variants. That is deliberate: it isolates the *delivery channel* as a
variable while holding the probed behavior fixed, which is what makes the
hardening-delta comparison clean. The trade-off is that the headcount reflects
breadth across channels more than across distinct phrasings — extend a template
by hand, or add new templates in `scripts/gen_corpus.py`, to deepen coverage.

Regenerate the YAML after editing the templates:

```bash
python scripts/gen_corpus.py        # rewrites corpus/asi0*.yaml
```

## Case schema

```yaml
- id: short-stable-id                 # [A-Za-z0-9._-]
  asi_category: ASI01                 # OWASP Agentic category
  severity: critical                  # low | medium | high | critical
  delivery_vector: tool_result        # where the payload is planted
  title: ...                          # optional human label
  description: ...                    # optional: what it probes
  payload_template: "... $canary ..." # $placeholders rendered per run
  tags: [prompt-injection]            # optional
  oracle:
    type: canary_exfiltration         # canary_exfiltration | forbidden_tool | predicate
    params: { canary: "$canary", severity: critical }
```

`delivery_vector` ∈ `system_prompt | user_message | tool_result | memory |
retrieved_document`. The `$canary` placeholder (and any other `$name`) is
substituted with a freshly-generated value at run time.

> ETHICS / SCOPE: For authorized testing of systems you own or are permitted to test.
