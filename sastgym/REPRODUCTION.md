# Behavioral reproduction plan (not executed)

The current labels are source-reviewed only. No Rails request, browser exploit,
Ruby test suite or payload was run while preparing this pilot. This document is a
plan for the next evidence level, not execution evidence.

## Environment and safety

Use a disposable local sandbox containing the exact manifest commit, Ruby 3.4.1,
the committed Gemfile.lock (Rails 8.0.4), and the upstream SQLite test database
configuration. Install from official Ruby/RubyGems sources as authorized; do not
pipe unreviewed installer scripts into a shell. Use only synthetic users/data.

Prefer Rails integration/controller request tests so no network listener is
needed. If browser verification requires a server, bind only to 127.0.0.1 in the
isolated sandbox. Never publish or externally expose RailsGoat. Keep outbound
network disabled during exploit execution after dependency setup. Use a disposable
working directory and database, do not mount personal files or real credentials,
and discard the environment afterward.

Review Rails initialization, CSRF behavior and fixture creation before running.
A logged-in state-changing request should include any required authenticity token;
do not introduce application code changes merely to make a payload reachable.
Record skipped/pending examples separately. Never present a green maintainer run
as vulnerability reproduction.

## Per-label oracles

1. **RAILSGOAT-001: Work-info IDOR**
   - Create ordinary users A and B with distinct benign employee records
   - As A, request `/users/B_ID/work_info`
   - Assert response success and B's unique information in the raw response body
   - Control: A's own route returns A; unauthenticated access is denied/redirected
   - Verify the target is non-admin and the general `has_info` guard is satisfied

2. **RAILSGOAT-002: Signup role mass assignment**
   - Submit valid signup data, a unique fixture email and `user[admin]=true`
   - Reload the created account and assert its admin flag is true
   - Control: omit the privileged field and verify the account is not admin
   - Assert persisted state rather than just a redirect or session value

3. **RAILSGOAT-003: Admin guard bypass**
   - As an ordinary user, request `/admin/1/get_all_users`
   - Assert another fixture user's otherwise administrative list entry is returned
   - Control: use a non-1 route value and verify the administrative guard rejects it
   - This read-only route avoids destructive administrative operations

4. **RAILSGOAT-004: Account-update SQL injection**
   - Use synthetic accounts with distinct marker attributes
   - Inspect Rails 8's actual generated query in the isolated test environment and
     choose an adapter-compatible predicate-changing value for nested `user[id]`
   - Assert the selected fixture's persisted marker changes; demonstrate the SQL
     predicate was changed, not only ordinary unauthorized numeric-ID substitution
   - Control: the same principal's normal identity value updates its expected row
   - Do not infer success from a SQL exception, any training-spec failure, or an
     assumption that the first result is an administrator. This action updates the
     first selected row, not every matching account

5. **RAILSGOAT-005: Upload-backup command injection**
   - Use a harmless fixture upload no larger than 10 MiB and a filename that both
     ends in an allowed extension and contains controlled shell syntax
   - Verify multipart parsing preserves the characters needed for the test
   - Use a harmless marker-producing command in an isolated disposable directory;
     assert the marker appears only for the selected fixture and `backup="true"`
   - Controls: backup false does not execute; a plain allowed filename only copies
   - Record upload acceptance, written filename, backup invocation and marker
   - Never reuse the upstream `rm -f *` payload. The legacy filename lacks an
     allowed extension and its UI selector is stale

6. **RAILSGOAT-006: Unconfined download**
   - Create a benign readable fixture outside `public/data` in the disposable app
     workspace, without using a real system/configuration secret
   - As an ordinary user, call `/download` with `type=File` and that fixture path
   - Assert the exact fixture bytes and download response, not merely status 200
   - Verify File-object coercion by `send_file` on Rails 8.0.4; a rescued exception
     or redirect is not reproduction and must trigger label re-adjudication
   - Control: a normal benefit file still works; a missing file follows error flow

## Promotion requirements

For each case record the source SHA, dependency lock hash, runtime and OS versions,
database adapter, test command, fixture setup, assertion output and timestamps.
Retain complete reproducible test code and a hash-addressed run log outside scanner
inputs. Add a reviewed schema revision supporting those artifact links before
changing `evidence.level` to `reproduced`. An attempt blocked by framework/API drift
stays source-reviewed or is downgraded/rejected after investigation; do not relabel
it on the basis of expected behavior alone.
