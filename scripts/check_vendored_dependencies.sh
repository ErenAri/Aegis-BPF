#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${1:-config/vendored_deps.json}"

if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "Vendored dependency config not found: ${CONFIG_PATH}" >&2
    exit 2
fi

python3 - "${CONFIG_PATH}" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import sys

cfg_path = pathlib.Path(sys.argv[1])
cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

errors: list[str] = []

entry = cfg.get("tweetnacl")
if not isinstance(entry, dict):
    errors.append("config.vendored_deps: missing 'tweetnacl' object")
else:
    required_keys = (
        "upstream_version",
        "upstream_source",
        "last_reviewed",
        "review_interval_days",
    )
    for key in required_keys:
        if key not in entry:
            errors.append(f"config.vendored_deps.tweetnacl: missing key '{key}'")

if errors:
    for err in errors:
        print(f"ERROR: {err}")
    raise SystemExit(1)

version = str(entry["upstream_version"])
source = str(entry["upstream_source"])
review_interval = int(entry["review_interval_days"])
last_reviewed = dt.date.fromisoformat(str(entry["last_reviewed"]))
today = dt.date.today()
age_days = (today - last_reviewed).days

if age_days > review_interval:
    errors.append(
        f"tweetnacl review is stale: last_reviewed={last_reviewed.isoformat()} "
        f"age={age_days}d limit={review_interval}d"
    )

tweetnacl_path = pathlib.Path("src/tweetnacl.c")
if not tweetnacl_path.exists():
    errors.append("src/tweetnacl.c not found")
else:
    content = tweetnacl_path.read_text(encoding="utf-8", errors="replace")
    version_marker = f"Upstream reference: TweetNaCl {version}"
    if version_marker not in content:
        errors.append(f"missing marker in src/tweetnacl.c: '{version_marker}'")
    source_marker = f"Source: {source}"
    if source_marker not in content:
        errors.append(f"missing marker in src/tweetnacl.c: '{source_marker}'")

    digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    print(f"tweetnacl sha256: {digest}")
    print(f"tweetnacl upstream: {version} ({source})")
    print(f"tweetnacl review age: {age_days} days")

if errors:
    for err in errors:
        print(f"ERROR: {err}")
    raise SystemExit(1)

print("Vendored dependency checks passed.")
PY
