#!/usr/bin/env python3
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    sys.stderr.write(
        "jsonschema is required; install python3-jsonschema or pip install jsonschema\n"
    )
    sys.exit(1)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def build_validator(schema: dict):
    # jsonschema<4 does not expose Draft202012Validator. Use the best available
    # validator for the declared $schema and gracefully fall back if needed.
    if hasattr(jsonschema, "Draft202012Validator"):
        return jsonschema.Draft202012Validator(schema)

    validators_mod = getattr(jsonschema, "validators", None)
    if validators_mod is not None and hasattr(validators_mod, "validator_for"):
        validator_cls = validators_mod.validator_for(schema)
        validator_cls.check_schema(schema)
        if validator_cls.__name__ != "Draft202012Validator":
            sys.stderr.write(
                f"warning: using {validator_cls.__name__}; "
                "Draft 2020-12 validator unavailable in installed jsonschema\n"
            )
        return validator_cls(schema)

    for name in ("Draft7Validator", "Draft6Validator", "Draft4Validator"):
        validator_cls = getattr(jsonschema, name, None)
        if validator_cls is not None:
            sys.stderr.write(
                f"warning: using {name}; "
                "Draft 2020-12 validator unavailable in installed jsonschema\n"
            )
            validator_cls.check_schema(schema)
            return validator_cls(schema)

    raise RuntimeError(
        "No suitable jsonschema validator available; install python3-jsonschema>=3.2"
    )


def validate(schema_path: Path, samples_dir: Path) -> int:
    schema = load_json(schema_path)
    validator = build_validator(schema)

    failures = 0
    sample_paths = sorted(samples_dir.glob("*.json"))
    if not sample_paths:
        sys.stderr.write(f"no samples found: {samples_dir}\n")
        return 1

    for sample_path in sample_paths:
        sample = load_json(sample_path)
        errors = sorted(validator.iter_errors(sample), key=lambda e: e.path)
        if errors:
            failures += 1
            sys.stderr.write(f"Schema validation failed: {sample_path}\n")
            for err in errors:
                loc = "/".join(str(p) for p in err.path) or "<root>"
                sys.stderr.write(f"  - {loc}: {err.message}\n")

    if failures:
        return 1

    print(f"Validated {len(sample_paths)} samples against {schema_path}")
    return 0


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    checks = [
        ("health", root / "config/schemas/health.json", root / "tests/json_samples/health"),
        ("doctor", root / "config/schemas/doctor.json", root / "tests/json_samples/doctor"),
        (
            "emergency_status",
            root / "config/schemas/emergency_status.json",
            root / "tests/json_samples/emergency_status",
        ),
        (
            "capabilities_v1",
            root / "config/schemas/capabilities_v1.json",
            root / "tests/json_samples/capabilities_v1",
        ),
        (
            "perf_baseline_v1",
            root / "config/schemas/perf_baseline_v1.json",
            root / "tests/json_samples/perf_baseline_v1",
        ),
    ]

    failures = 0
    for name, schema_path, samples_dir in checks:
        if not schema_path.exists():
            sys.stderr.write(f"missing schema: {schema_path}\n")
            failures += 1
            continue
        if not samples_dir.exists():
            sys.stderr.write(f"missing samples dir: {samples_dir}\n")
            failures += 1
            continue
        rc = validate(schema_path, samples_dir)
        if rc != 0:
            failures += 1
        else:
            print(f"ok: {name}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
