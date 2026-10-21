"""Verify the frozen F3/S3 CPU samples without running any benchmark.

Only Python's standard library is required. Use --report PATH to save the
machine-readable result; the supplied benchmark files are never changed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import math

ROOT = Path(__file__).resolve().parent
SELECTED = ROOT


def quantile(xs, p):
    """Linear interpolation, matching numpy.quantile's default method."""
    ordered = sorted(xs)
    position = (len(ordered) - 1) * p
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    data = json.loads((SELECTED / "性能统计.json").read_text(encoding="utf-8"))
    checks = []
    seen_files = set()
    for row in data["rows"]:
        operations = {"keygen": [], "sign": [], "verify": []}
        count = 0
        metadata, validation = [], []
        for src in row["raw_files"]:
            path = (SELECTED / src["relative_path"]).resolve()
            assert path.is_relative_to(SELECTED.resolve()), "raw path outside snapshot"
            assert path not in seen_files, f"duplicate raw file: {path.name}"
            seen_files.add(path)
            assert hashlib.sha256(path.read_bytes()).hexdigest() == src["sha256"], path.name
            for line in path.read_text(encoding="utf-8").splitlines():
                sample = json.loads(line)
                if sample["kind"] == "metadata":
                    metadata.append(sample)
                elif sample["kind"] == "validation":
                    validation.append(sample)
                elif sample["kind"] == "sample" and not sample["warmup"]:
                    assert sample["valid"] and sample["signature_bytes"] == row["signature_bytes"]
                    assert all(sample[k] == 0 for k in ("kg_rc", "sign_rc", "verify_rc"))
                    count += 1
                    for operation, key in (("keygen", "kg_ns"), ("sign", "sign_ns"), ("verify", "verify_ns")):
                        operations[operation].append(sample[key])
        assert count == row["samples"] == 1503, row["key"]
        assert len(metadata) == len(validation) == 9, row["key"]
        assert all(item["passed"] for item in validation), row["key"]
        for item in metadata:
            assert item["message_bytes"] == 64 and item["clock"] == "CLOCK_MONOTONIC_RAW"
            assert item["public_key_bytes"] == row["public_key_bytes"]
            assert item["secret_key_bytes"] == row["secret_key_bytes"]
        for operation, samples in operations.items():
            denominator, unit = (1000, "us") if operation == "keygen" else (1000000, "ms")
            for probability, suffix in ((.25, "_q1"), (.5, ""), (.75, "_q3")):
                key = f"{operation}{suffix}_{unit}"
                assert abs(quantile(samples, probability) / denominator - row[key]) < 1e-12, (row["key"], key)
        checks.append({"key": row["key"], "sample_count": count, "source_files": len(row["raw_files"]),
                       "metadata_and_lengths": "PASS", "raw_quartiles_and_median": "PASS",
                       "return_codes_and_validity": "PASS"})
    report = {"status": "PASS", "implementations": len(checks),
              "nonwarmup_samples": sum(item["sample_count"] for item in checks),
              "raw_files": len(seen_files), "checks": checks}
    assert (report["implementations"], report["nonwarmup_samples"], report["raw_files"]) == (38, 57114, 342)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "checks"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
