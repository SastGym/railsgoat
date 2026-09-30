# RailsGoat ground-truth pilot

This is an **authoring dataset**, not a vulnerability fix or a blind benchmark export.
It preserves the intentionally vulnerable application at upstream commit
[`f5951f13089d85c979de09e7da3c8c0fb982f94a`](https://github.com/OWASP/railsgoat/tree/f5951f13089d85c979de09e7da3c8c0fb982f94a).
The MIT-licensed upstream application is unchanged.

## What is included

`ground-truth.json` contains one manifest and six independent positive labels:

| ID | Root cause | CWE | Primary region |
| --- | --- | --- | --- |
| RAILSGOAT-001 | Other employee's work information selected without ownership check | 639 | `app/controllers/work_info_controller.rb:3–8` |
| RAILSGOAT-002 | Public signup permits the administrator role | 915 | `app/controllers/users_controller.rb:49–51` |
| RAILSGOAT-003 | Request parameter disables administrative authorization | 863 | `app/controllers/admin_controller.rb:3` |
| RAILSGOAT-004 | Account-update identity is interpolated into SQL | 89 | `app/controllers/users_controller.rb:29` |
| RAILSGOAT-005 | Upload filename is interpolated into a shell command | 78 | `app/models/benefits.rb:15` |
| RAILSGOAT-006 | Download path is not confined to approved documents | 73 | `app/controllers/benefit_forms_controller.rb:11–13` |

**Evidence count: 6 source-reviewed, 0 runtime-reproduced, 0 verified negatives.**
Each record includes a reachable entry point, preconditions, violated invariant,
source/control/sink trace, precise locations, upstream spec provenance and
limitations. This is deliberately partial: unannotated code is not safe by default.

## Evidence levels

- **Documented:** upstream material identifies the issue. That alone is not proof
- **Source-reviewed:** the route, guards, flow and root cause were checked at the
  exact pin. This does not imply the application or exploit was run
- **Reproduced:** an isolated behavioral oracle actually ran against the exact
  snapshot with recorded environment and results

All six current records are source-reviewed. Pilot v1 explicitly rejects runtime
`passed`/`reproduced` claims; a reviewed schema revision with a run-artifact and
provenance contract is required before promoting them. This prevents a status edit
from masquerading as execution evidence.

Important upstream test limitations:

- `spec/support/capybara_shared.rb:11–35` returns false when
  `RAILSGOAT_MAINTAINER` is set to *any* value. The vulnerability specs use
  `skip unless verifying_fixed?`. Green maintainer CI does not prove that attacks
  ran or vulnerabilities remain reachable
- Training tests generally assert repaired behavior, so a failure alone is not an
  exploit oracle: a stale selector, exception, or setup failure can also fail
- The command-injection spec's filename has no currently allowed extension, so
  upload validation rejects it before the shell sink. Its button selector is
  stale too. Its destructive payload must not be used for the new oracle
- The download spec's `.widget-body a` selector is stale against the redesigned
  benefit page. Test the authorized direct route with a harmless fixture instead
- The SQL-injection example's SQL syntax and generated predicate shape need
  rechecking against Rails 8.0.4 and the selected SQLite adapter

## Files and validation

- `ground-truth.json`: source/environment manifest and positive labels
- `schema.json`: strict JSON Schema Draft 2020-12 for the complete dataset
- `validate.py`: schema, unique IDs/root regions, path confinement, line bounds,
  excerpt SHA-256, dependency pins, every upstream tracked file's Git blob hash/
  executable bit and an allowlist for added authoring files
- `tests/test_validate.py`: positive and adversarial contract tests
- `REPRODUCTION.md`: isolated runtime validation plan, **not executed**
- `CHECKS.md`: actual executed checks and remaining limits

Run from the repository root with Python 3.12 and Git installed:

```sh
python -m pip install -r sastgym/requirements.txt
PYTHONDONTWRITEBYTECODE=1 python sastgym/validate.py
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s sastgym/tests -v
```

`jsonschema` is the only Python dependency, pinned in `requirements.txt`. Validation
reads source and Git objects; it never starts Rails, sends a request or executes a
payload. A Git checkout containing the pinned commit is required. GitHub Actions
must fetch enough history to contain that pin (the annotation workflow fetches all
history). The snapshot check includes tracked and untracked additions (including
ignored files); use a clean checkout. Runtime/build artifacts outside the fixed
authoring paths are deliberately rejected rather than silently trusted.

Locations use repository-relative POSIX paths and **1-based inclusive** line ranges.
Excerpt hashes cover the original bytes, preserving line terminators, from
`start_line` through `end_line`. Symbols are descriptive human-reviewed identifiers;
the validator verifies bytes and ranges, not a Ruby AST or a security proof. A
source reference can be opened as:

```text
https://github.com/OWASP/railsgoat/blob/<manifest.source.commit>/<path>#L<start_line>-L<end_line>
```

The manifest records upstream commit/tree, Ruby 3.4.1, Rails 8.0.4, lockfile SHA-256
and the upstream SQLite test configuration. Do not silently move the source pin.
An upstream update is a new corpus revision requiring renewed source review and
rerun behavioral oracles where available.

## Matching and coverage

The unit is a **root cause**, not an attack, sink hit or upstream challenge count.
Match mechanism plus the primary region or a decisive related control. A correct
RAILSGOAT-003 report anchored at `admin_param` line 76 is eligible even if it does not
name callback line 3. Use manual adjudication for equivalent anchors; related
locations do not become additional positives. CWE similarity or line overlap alone is insufficient. Multiple reports for
one mechanism are duplicates; a report identifying a different missing control at
the same line needs separate adjudication. In particular:

- Signup `permit!` and account-update `permit(:admin)` are distinct boundaries;
  only signup is counted here
- SQL injection and missing ownership checks in `UsersController#update` are
  distinct causes. An IDOR-only report does not match RAILSGOAT-004
- The admin callback bypass is one root cause. `get_user`'s explicit callback
  exception is separate and currently unannotated
- Command injection and filename traversal in upload handling are separate
- Unmatched findings are **needs-adjudication**, not automatically false positives

No severity scores, recall denominator for the whole app, precision estimates,
verified negatives, fixed variants or exhaustive scan claims are supplied.

## Preventing evaluation leakage

Do not give scanners this authoring branch as an allegedly blind benchmark.
Withhold `sastgym/`, specs, docs and tutorial/readme answers. Even that is
insufficient: upstream application code/templates contain explicit vulnerability
comments and tutorials, and public training repositories may have appeared in model
training data. `manifest.evaluation.blind_ready` is therefore false.

A future blind export needs a reviewed, deterministic transformation and a
reversible source-line map, with the manifest/labels held externally by the scorer.
Do not remove behavior or “fix” source while preparing that export. No blind export
was produced in this pilot.
