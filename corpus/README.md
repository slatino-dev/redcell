# Corpus

This directory holds redcell's **probe cases** — the defensive benchmark of
behaviors an agent should resist, organized by OWASP Top 10 for Agentic
Applications (2026) category. Cases are data, loaded and validated by
`redcell.corpus_loader`.

`mvp.yaml` is the seed corpus covering the five MVP categories (ASI01, ASI02,
ASI03, ASI05, ASI06). Nothing here is a turnkey exploit: each case describes a
behavior to *test for* — paired with a deterministic oracle that detects whether
the target exhibited it — so you can confirm your own agent handles it safely.

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
