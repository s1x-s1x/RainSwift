"""Untimed Linux RNG keygen/sign round trip through the public file CLI."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from signing_budget import SigningBudget


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--library", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--backend", choices=("auto", "ref", "avx2", "cuda"), default="auto")
    a = p.parse_args()
    if a.output.exists():
        p.error("choose a fresh output filename")
    source_names = ("tools/check_rng_native.py", "tools/cli.py", "tools/native.py", "tools/signing_budget.py")
    before = {name: sha(ROOT / name) for name in source_names}
    library_hash = sha(a.library)
    rows = []
    common = [sys.executable, str(ROOT / "tools/cli.py"), "--pid", "201", "--backend", a.backend,
              "--library", str(a.library.resolve())]
    with tempfile.TemporaryDirectory(prefix="a15-rng-") as folder:
        w = Path(folder)
        def run(label, arguments):
            result = subprocess.run(common + arguments, text=True, capture_output=True, timeout=60)
            if result.returncode:
                raise RuntimeError(label + ": " + result.stderr)
            row = {"case_id": label, "result": json.loads(result.stdout), "passed": True}
            if a.backend == "cuda" and row["result"]["backend_selected"] != 5:
                raise ValueError("explicit CUDA CLI did not select backend5")
            rows.append(row)
            return row["result"]
        message = w / "message.bin"
        message.write_bytes(b"\0RNG correctness fixture\xff")
        one, two = w / "one", w / "two"
        for prefix in (one, two):
            r = run("rng-keygen-" + prefix.name, ["keygen", str(prefix)])
            require(not r["fixture_seeded"], "RNG keygen used a fixture seed")
        pk1, pk2 = Path(str(one) + ".pk").read_bytes(), Path(str(two) + ".pk").read_bytes()
        rows.append({"case_id": "independent-rng-keys", "passed": pk1 != pk2,
                     "note": "operational sanity check, not a randomness quality proof"})
        signature = w / "signature.bin"
        run("rng-randomized-sign", ["sign", str(message), str(one) + ".sk", str(signature),
            "--randomized", "--budget-db", str(w / "budget.sqlite")])
        r = run("rng-verify", ["verify", str(message), str(one) + ".pk", str(signature)])
        require(r["valid"], "new RNG signature failed verification")
        status = SigningBudget(w / "budget.sqlite").status()
        rows.append({"case_id": "budget", "passed": status[0]["used"] == 1
                     and status[0]["states"] == {"committed": 1}, "status": status})
    source_unchanged = before == {name: sha(ROOT / name) for name in source_names}
    library_unchanged = library_hash == sha(a.library)
    result = {"schema": "a15-native-rng-v1", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
              "passed": all(r["passed"] for r in rows) and source_unchanged and library_unchanged, "results": rows,
              "library_sha256": library_hash, "library_unchanged": library_unchanged,
              "backend_requested": a.backend,
              "sources_sha256": before, "source_unchanged": source_unchanged,
              "formal_performance_started": False, "duration_measured": False}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x", encoding="utf8") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": result["passed"], "checks": len(rows)}))
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
