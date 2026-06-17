# Build notes & decisions

Running log for anyone (human or AI) continuing this project.

## Status — v1 complete

Definition-of-done met: `analyze`/`report` run end-to-end on `data/mock_account.json`
producing classified identities, severity-ranked findings, before/after escalation paths,
and tightened policy JSON. `ingest` parses a real `get-account-authorization-details`
export (redacted sample in `ingest/`). 19 tests pass; CI + lint wired.

## Key design decisions

- **Action matching is wildcard-aware** (`classifier._action_matches`): `iam:*` satisfies
  `iam:PassRole`, `*` satisfies anything. Used everywhere a held action is checked against a
  pattern, so rule authors can write either form.
- **Group permissions are inherited at read-time** via `effective_permissions`, not copied
  onto users — keeps the inventory normalised and the mock honest (`dev-user` gets
  `sts:AssumeRole` from the `developers` group).
- **Escalation graph keys on actions, but PassRole and AssumeRole are resource-aware**
  (`_can_pass_role`, `_assume_targets`). This is what lets remediation *scope* a grant
  (not just delete it) and still visibly cut the edge in the after-graph.
- **Admin-tier identities don't emit `dangerous-combo` findings.** An admin trivially holds
  every escalation primitive; listing each is noise. They're flagged once as
  `standing-admin` (users) / `wildcard` (roles). Avoids crying wolf — a deliberate,
  defensible call.
- **Remediation strips self-escalation verbs from non-admins, scopes PassRole/AssumeRole,
  drops unused services, and downscopes remaining wildcards to reads.** Admin *roles* keep
  their wildcards (the demo leaves `lambda-exec-role` privileged but unreachable, which
  makes the "path cut by scoping the caller" story sharper than zeroing everything out).
- **Risk score** = Σ severity weights + min(reach×10, 30), capped 100. Multiple maxed-out
  identities is expected for a deliberately-vulnerable account.

## Heuristics live in YAML

`data/sensitive_actions.yaml` (sensitivity weights, tier thresholds) and
`data/escalation_rules.yaml` (priv-esc techniques). Tune these, not the Python.

## Possible next steps

- Wire real `last_used` enrichment in `ingestion.inventory_from_live` via
  `GenerateServiceLastAccessedDetails` (async; currently a documented extension point).
- Add condition-key awareness (e.g. MFA / `aws:SourceIp`) to soften findings on
  well-conditioned grants.
- Permissions-boundary modelling — recognise when a boundary already caps a self-escalation
  primitive.
- Graphviz/PNG export alongside the Mermaid diagram for slide decks.
- `git init` and adopt Conventional Commits (`feat:`, `test:`, `docs:`, `chore:`) before
  pushing to GitHub.
