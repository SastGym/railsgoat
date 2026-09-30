# Pilot check record

Date: 2026-09-30 (UTC)
Source: `f5951f13089d85c979de09e7da3c8c0fb982f94a`
Annotation workspace: isolated cloud workspace; no vulnerable service exposed

## Passed

- `git ls-remote origin refs/heads/main` confirmed the upstream main pin
- Inspected upstream README, contribution guidance, dependency files, routes,
  callbacks, source/sink locations, model/schema context and vulnerability specs
- Independent second source review checked the selected mechanisms and stale tests
- `python sastgym/validate.py`: strict schema, six unique root-cause labels,
  precise line bounds/SHA-256 excerpt hashes, lockfile/environment pins and all
  276 original tracked files' Git blob hashes and executable bits match the upstream
  snapshot; tracked/untracked/ignored extra files outside the fixed authoring
  allowlist are rejected
- `python -m unittest discover -s sastgym/tests -v`: 22/22 passed
- `git diff --cached --check`: no whitespace errors

Python: 3.12.14. JSON Schema library: jsonschema 4.26.0.

## Not run / blocked

- Rails boot, Rails/RSpec suite, request tests, browser tests and exploit oracles:
  not run because Ruby, Bundler and Docker are absent (`command -v` found none)
- No runtime reproduction, repaired variant or negative security label is claimed
- GitHub Actions results are not established by this local report; inspect the
  eventual published commit's checks separately. Publication is currently paused;
  no fork, push or PR is claimed by this artifact
- Blind-export creation and validation: not run; intentionally outside this pilot

No executed check failed. The blocked runtime checks must not be counted as passed.
The integrity suite checks authoring correctness and source preservation; it cannot
prove reachability, exploitability, behavioral security or exhaustive coverage.
