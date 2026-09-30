#!/usr/bin/env python3
"""Validate authoring data and pinned source integrity; never execute Rails/attacks."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys

from jsonschema import Draft202012Validator, FormatChecker

HERE = Path(__file__).resolve().parent
AUTHORING_PATHS = ("sastgym/", ".github/workflows/sastgym-ground-truth.yml")


def load_json(path: Path):
    def no_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_keys)


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def safe_path(root: Path, value: str) -> Path:
    relative = PurePosixPath(value)
    if (relative.is_absolute() or ".." in relative.parts or "\\" in value
            or ":" in value or value != relative.as_posix()):
        raise ValueError(f"unsafe/noncanonical repository path: {value}")
    path = root.joinpath(*relative.parts)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"path escapes repository: {value}")
    if path.is_symlink():
        raise ValueError(f"symlink is not an annotation source: {value}")
    return path


def snapshot_errors(root: Path, commit: str, tree: str) -> list[str]:
    """Require every original tracked file, including binary files, to remain unchanged."""
    errors = []
    try:
        actual_tree = git(root, "rev-parse", f"{commit}^{{tree}}").decode().strip()
        if actual_tree != tree:
            errors.append("manifest source tree does not match the pinned commit")
        records = git(root, "ls-tree", "-r", "-z", commit).split(b"\0")
        source_paths = set()
        for record in filter(None, records):
            metadata, path_bytes = record.split(b"\t", 1)
            mode, kind, expected = metadata.decode().split()
            relative = path_bytes.decode()
            source_paths.add(relative)
            path = safe_path(root, relative)
            if kind != "blob" or mode not in ("100644", "100755"):
                errors.append(f"unsupported source tree entry: {relative} ({mode}/{kind})")
                continue
            executable = bool(path.stat().st_mode & 0o111)
            if executable != (mode == "100755"):
                errors.append(f"pinned source executable mode changed: {relative}")
            raw = path.read_bytes()
            actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            if actual != expected:
                errors.append(f"pinned source changed: {relative}")
        # Include ignored files too: an ignored new initializer can still change the app.
        current_paths = git(root, "ls-files", "--cached", "--others", "-z").split(b"\0")
        for path_bytes in filter(None, current_paths):
            relative = path_bytes.decode()
            if relative not in source_paths and not any(
                relative.startswith(allowed) if allowed.endswith("/") else relative == allowed
                for allowed in AUTHORING_PATHS
            ):
                errors.append(f"unexpected file outside authoring paths: {relative}")
    except (subprocess.CalledProcessError, OSError, ValueError) as exc:
        errors.append(f"could not verify pinned source snapshot: {exc}")
    return errors


def validate(data: dict, root: Path, schema: dict, check_snapshot: bool = True) -> list[str]:
    errors = []
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(data), key=lambda e: str(list(e.path))):
        errors.append(f"schema {'.'.join(map(str, error.path))}: {error.message}")
    if errors:
        return errors

    manifest = data["manifest"]
    source = manifest["source"]
    if tuple(manifest["evaluation"]["authoring_paths"]) != AUTHORING_PATHS:
        errors.append("manifest authoring_paths does not match the pilot allowlist")
    if check_snapshot:
        errors.extend(snapshot_errors(root, source["commit"], source["tree"]))
    try:
        lock = (root / "Gemfile.lock").read_bytes()
        if hashlib.sha256(lock).hexdigest() != manifest["environment"]["lockfile_sha256"]:
            errors.append("Gemfile.lock SHA-256 does not match manifest")
        if (root / ".ruby-version").read_text().strip() != manifest["environment"]["ruby"]:
            errors.append("Ruby version does not match .ruby-version")
        if f"    rails ({manifest['environment']['rails']})" not in lock.decode().splitlines():
            errors.append("Rails version does not match Gemfile.lock")
    except OSError as exc:
        errors.append(f"environment pin cannot be read: {exc}")

    ids, roots = set(), set()
    reproduced = []
    for finding in data["findings"]:
        id_ = finding["id"]
        if id_ in ids:
            errors.append(f"duplicate finding ID: {id_}")
        ids.add(id_)
        primary = finding["primary_location"]
        key = (primary["path"], primary["start_line"], primary["end_line"], finding["cwe"])
        if key in roots:
            errors.append(f"duplicate root-cause region and CWE: {id_}")
        roots.add(key)
        if primary["role"] != "root-cause":
            errors.append(f"{id_}: primary location must have root-cause role")
        if finding["evidence"]["upstream_spec"]["role"] != "upstream-spec":
            errors.append(f"{id_}: upstream spec must have upstream-spec role")
        if any(item["role"] == "root-cause" for item in finding["related_locations"]):
            errors.append(f"{id_}: exactly one primary root-cause location is allowed")
        for location in [primary, *finding["related_locations"], finding["evidence"]["upstream_spec"]]:
            description = f"{id_} {location['path']}:{location['start_line']}-{location['end_line']}"
            try:
                path = safe_path(root, location["path"])
                lines = path.read_bytes().splitlines(keepends=True)
                start, end = location["start_line"], location["end_line"]
                if end < start or end > len(lines):
                    errors.append(f"invalid line range: {description}")
                    continue
                digest = hashlib.sha256(b"".join(lines[start - 1:end])).hexdigest()
                if digest != location["excerpt_sha256"]:
                    errors.append(f"excerpt SHA-256 mismatch: {description}")
                # Evidence must originate at the source pin, not newly-added answer files.
                pinned = git(root, "show", f"{source['commit']}:{location['path']}")
                if hashlib.sha256(b"".join(pinned.splitlines(keepends=True)[start - 1:end])).hexdigest() != digest:
                    errors.append(f"location does not match source pin: {description}")
            except (OSError, ValueError, subprocess.CalledProcessError) as exc:
                errors.append(f"unreadable/invalid location {description}: {exc}")

        evidence = finding["evidence"]
        runtime = evidence["runtime"]
        is_reproduced = evidence["level"] == "reproduced"
        reproduced.append(is_reproduced)
        if is_reproduced != (runtime["status"] == "passed"):
            errors.append(f"{id_}: reproduced level and passed runtime status must agree")
        if runtime["status"] == "passed":
            # Pilot v1 intentionally has no unverified runtime-proof format.
            errors.append(f"{id_}: pilot v1 does not accept reproduced claims; add a reviewed run-artifact contract in a schema revision first")
    if manifest["environment"]["runtime_reproduced"] != all(reproduced):
        errors.append("manifest runtime_reproduced must equal whether every finding is reproduced")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=HERE.parent)
    parser.add_argument("--data", type=Path, default=HERE / "ground-truth.json")
    args = parser.parse_args()
    try:
        data = load_json(args.data)
        errors = validate(data, args.repo_root.resolve(), load_json(HERE / "schema.json"))
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("\n".join(f"FAIL: {error}" for error in errors), file=sys.stderr)
        return 1
    count = len(data["findings"])
    print(f"PASS: schema, {count} unique labels, source/line hashes and complete upstream snapshot")
    print("Runtime exploit reproduction: NOT RUN (integrity checks are not exploit tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
