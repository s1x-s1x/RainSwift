"""Install hash-locked dependencies and optionally run fresh Linux acceptance.

Every verification run owns a new output directory. This is functional
acceptance, not a performance campaign or replay of a historical freeze.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time
import uuid
import venv
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
LOCKS = (ROOT / "base_tls/requirements.lock.txt", ROOT / "reference/requirements.lock.txt")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = set()
    for pattern in ("c/**/*.c", "c/**/*.h", "c/Makefile", "tools/*.py",
                    "reference/*.py", "base_tls/tls/**/*.py", "base_tls/tests/**/*.py",
                    "base_tls/tools/*.py", "third_party/slhdsa-c/**/*.c",
                    "third_party/slhdsa-c/**/*.h", "third_party/py-acvp-pqc/**/*.py",
                    "ops/bootstrap_local_env.py"):
        paths.update(p for p in ROOT.glob(pattern) if p.is_file())
    paths.update(p for p in (*LOCKS, ROOT / "base_tls/requirements-falcon.lock.txt") if p.is_file())
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(paths)}


def tree_hashes(directory):
    return {p.relative_to(directory).as_posix(): sha(p)
            for p in sorted(directory.rglob("*")) if p.is_file()}


def default_runtime(output):
    return output / "runtime"


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def run_step(name, command, output, env, steps, timeout):
    row = {"name": name, "command": [str(x) for x in command], "status": "running"}
    steps.append(row)
    log_path = output / (name + ".log")
    print(f"[{name}] started; log: {log_path}", flush=True)
    started = time.monotonic()
    with log_path.open("xb") as stream:
        process = subprocess.Popen(row["command"], cwd=ROOT, env=env,
                                   stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=os.name != "nt")
        try:
            row["exit_code"] = process.wait(timeout=timeout)
        except BaseException as error:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait()
            row["exit_code"] = 124 if isinstance(error, subprocess.TimeoutExpired) else 130
            row["status"] = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "interrupted"
            row["error"] = str(error)
            if not isinstance(error, subprocess.TimeoutExpired):
                raise
    row["elapsed_seconds"] = round(time.monotonic() - started, 3)
    row["log"] = log_path.name
    row["log_sha256"] = sha(log_path)
    if row["status"] == "running":
        row["status"] = "passed" if row["exit_code"] == 0 else "failed"
    print(f"[{name}] {row['status']} (exit {row['exit_code']})", flush=True)
    if row["exit_code"]:
        raise RuntimeError(f"{name} failed; inspect {log_path}")


def check_existing_falcon(target):
    record = json.loads((target / "installation.json").read_text(encoding="utf-8"))
    lock = ROOT / "base_tls/requirements-falcon.lock.txt"
    if not record.get("passed") or record.get("version") != "0.4.0" or record.get("lock_sha256") != sha(lock):
        raise ValueError("existing Falcon provider has no matching successful locked-install record")
    files = record.get("files_sha256")
    if not isinstance(files, dict) or not files:
        raise ValueError("existing Falcon provider has no recorded file hashes")
    for relative, expected in files.items():
        path = (target / relative).resolve()
        if not path.is_relative_to(target.resolve()) or not path.is_file() or sha(path) != expected:
            raise ValueError(f"existing Falcon provider hash mismatch: {relative}")
    actual = {p.relative_to(target).as_posix() for p in target.rglob("*")
              if p.is_file() and "__pycache__" not in p.parts and p.name != "installation.json"}
    if actual != set(files):
        raise ValueError("existing Falcon provider has missing or additional unrecorded files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--venv", type=Path, help="isolated virtual environment; defaults to the run output")
    parser.add_argument("--output", type=Path, help="new directory for logs, source hashes and fresh native binaries")
    parser.add_argument("--cache", type=Path, help="pip cache; defaults to the new run output directory")
    parser.add_argument("--wheelhouse", type=Path, help="offline wheel directory; disables package-index access")
    parser.add_argument("--skip-install", action="store_true", help="reuse a venv; exact locked versions are still checked")
    parser.add_argument("--verify", action="store_true", help="run the complete Linux functional gate after installation")
    parser.add_argument("--falcon", action="store_true", help="install/validate the separate hash-locked optional Falcon provider")
    parser.add_argument("--fixtures", type=Path, help="complete preissued test-only P0-P4 fixture root; enables native/Python chain verification and E1")
    parser.add_argument("--handshake-signer", help="must match fixture metadata; defaults to the metadata value")
    parser.add_argument("--jobs", type=positive, default=4)
    parser.add_argument("--timeout-seconds", type=positive, default=1800, help="per-command limit; elapsed values are operational logs")
    args = parser.parse_args()
    if args.verify and platform.system() != "Linux":
        parser.error("--verify requires Linux x86-64 (Ubuntu/WSL/container); Windows can prepare dependencies")
    if args.verify and platform.machine().lower() not in ("x86_64", "amd64"):
        parser.error("the REF/AVX2 gate requires Linux x86-64")
    tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = (args.output or ROOT / "build/local-reproduction" / tag).resolve()
    if output.exists():
        parser.error("--output must not exist; use a new directory to prevent stale evidence/binary reuse")
    output.mkdir(parents=True)
    runtime = default_runtime(output)
    cache = (args.cache or runtime / "pip-cache").resolve()
    env_dir = (args.venv or output / "venv").resolve()
    interpreter = env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE", "PYTHONINSPECT",
                "PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                "A15_ALT_FIXTURES", "A15_NATIVE_LIBRARY", "SLHDSA_SM3_LIB"):
        env.pop(key, None)
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "PIP_CACHE_DIR": str(cache),
                "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": str(args.jobs)})
    scratch = runtime / "tmp" / tag
    scratch.mkdir(parents=True, exist_ok=False)
    env.update({"TEMP": str(scratch), "TMP": str(scratch), "TMPDIR": str(scratch)})
    if args.wheelhouse:
        env.update({"PIP_NO_INDEX": "1", "PIP_FIND_LINKS": str(args.wheelhouse.resolve())})
    before = source_hashes()
    record = {"schema": "a15-local-functional-reproduction-v1", "created_utc": tag,
              "passed": False, "requested_verification": args.verify, "output": str(output),
              "venv": str(env_dir), "cache": str(cache), "steps": [], "source_sha256_before": before,
              "formal_performance_samples": 0, "cuda_device_execution": False,
              "historical_freeze_reproduced": False,
              "scope": "Fresh Linux CPU functional regression; CUDA runner uses mock-only checks; model tests are structural, not formal proofs"}
    fixture_before = None
    library = output / "native/libslhdsa_sm3.so"
    try:
        if any(not lock.is_file() for lock in LOCKS):
            raise FileNotFoundError("both base_tls and reference hash locks must be present")
        legacy = ROOT / "base_tls/.deps"
        if legacy.is_dir() and any(legacy.iterdir()):
            raise ValueError("base_tls/.deps can shadow the venv; use a checkout without this legacy dependency directory")
        falcon_target = ROOT / "base_tls/.deps-falcon"
        if falcon_target.exists() and not args.falcon:
            raise ValueError("existing optional Falcon provider found; use --falcon to validate it or a fresh checkout")
        if args.skip_install:
            if not (env_dir / "pyvenv.cfg").is_file() or not interpreter.is_file():
                raise ValueError("--skip-install requires an existing complete virtual environment")
        elif not env_dir.exists():
            venv.EnvBuilder(with_pip=True).create(env_dir)
        elif not (env_dir / "pyvenv.cfg").is_file() or not interpreter.is_file():
            raise ValueError("--venv exists but is not a complete virtual environment; refusing to overwrite")
        cache.mkdir(parents=True, exist_ok=True)
        env["VIRTUAL_ENV"] = str(env_dir)
        env["PATH"] = str(interpreter.parent) + os.pathsep + env.get("PATH", "")
        step = lambda name, command: run_step(name, command, output, env, record["steps"], args.timeout_seconds)
        if not args.skip_install:
            for lock in LOCKS:
                step("install-" + lock.parent.name, [interpreter, "-m", "pip", "install",
                     "--only-binary=:all:", "--require-hashes", "-r", lock])
        expected = {}
        for lock in LOCKS:
            expected.update(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock.read_text(encoding="utf-8"), re.M))
        script = ("import importlib.metadata as m,json,platform,sys\n"
                  "expected=json.loads(sys.argv[1]); actual={k:m.version(k) for k in expected}\n"
                  "print(json.dumps({'python':sys.version,'platform':platform.platform(),'optimize':sys.flags.optimize,'expected':expected,'actual':actual},sort_keys=True))\n"
                  "if sys.flags.optimize != 0: raise RuntimeError('Verification requires Python assertions enabled')\n"
                  "if actual != expected: raise RuntimeError('Installed package versions differ from the locks')\n")
        step("dependency-versions", [interpreter, "-B", "-c", script, json.dumps(expected)])
        if args.falcon:
            if falcon_target.exists():
                check_existing_falcon(falcon_target)
                record["falcon_provider"] = "existing hash-checked locked provider; runtime tests execute it"
            else:
                step("install-falcon", [interpreter, "-B", ROOT / "tools/install_falcon_provider.py", "--python", interpreter])
                check_existing_falcon(falcon_target)
                record["falcon_provider"] = "fresh separately installed hash-locked provider"
        else:
            record["falcon_provider"] = "not enabled; Falcon-dependent pytest cases may skip"
        if args.falcon:
            provider_check = ("import json,sys\n"
                              "sys.path.insert(0,str(sys.argv[1]))\n"
                              "import tls\n"
                              "from tls.pq.signature import available_pq_signers\n"
                              "providers=available_pq_signers(); print(json.dumps(providers,sort_keys=True))\n"
                              "if any(providers.get(name) != 'ok' for name in ('falcon-512','falcon-1024','ml-dsa-44')): raise RuntimeError('Required PQ provider is unavailable')\n")
            step("pq-provider-availability", [interpreter, "-B", "-c", provider_check, ROOT / "base_tls"])
        if args.fixtures:
            fixtures = args.fixtures.resolve()
            if not fixtures.is_dir():
                raise ValueError("--fixtures must be a complete preissued fixture directory")
            signers = {json.loads((fixtures / name / "fixture.json").read_text(encoding="utf-8"))["handshake_signer"]
                       for name in ("slh-dsa-sm3-128-24", "slh-dsa-sm3-128s", "ml-dsa-44")}
            if len(signers) != 1:
                raise ValueError("E1 requires matching handshake signers across all three fixture sets")
            signer = args.handshake_signer or next(iter(signers))
            if signers != {signer}:
                raise ValueError("--handshake-signer differs from the preissued fixture metadata")
            if signer.startswith("falcon-") and not args.falcon:
                raise ValueError("these fixtures require --falcon")
            fixture_before = tree_hashes(fixtures)
            record["fixture_sha256_before"] = fixture_before
            env["A15_ALT_FIXTURES"] = str(fixtures)
        if args.verify:
            native_dir = library.parent
            step("native-build-and-tests", ["make", "-C", "c", "CC=gcc", "CFLAGS=-O3",
                 "OUT=" + str(native_dir), "-j" + str(args.jobs), "all", "test", "review-test", "repair-test",
                 "avx2-test", "wots-test", "verify-scheduling-test", "prehash-test", "fault-test", "guard-test"])
            record["native_library_sha256_before"] = sha(library)
            env.update({"A15_NATIVE_LIBRARY": str(library), "SLHDSA_SM3_LIB": str(library)})
            step("unit-budget-adapter-model", [interpreter, "-B", "-m", "unittest", "tools.test_budget_repair",
                 "tools.test_benchmark_rng_receipts", "tools.test_native_boundaries",
                 "tools.test_native_digest_boundaries", "tools.test_cache_storage_headers",
                 "tools.test_workload_guard", "tools.test_lifecycle_settlement",
                 "tools.test_lifecycle_package_bindings",
                 "tools.test_ca_models_v2", "-v"])
            for backend in ("cpu", "cuda"):
                step("mock-" + backend, [interpreter, "-B", ROOT / ("tools/bench_" + backend + ".py"),
                     "self-test", "--output", output / ("mock-" + backend + ".json")])
            step("parser-fuzz", [interpreter, "-B", ROOT / "tools/fuzz_parsers.py", "--iterations", "5000",
                 "--output", output / "parser-fuzz.json"])
            # WSL DrvFS can fail when truncating the anonymous temporary file
            # used by pytest's default fd capture. Python stream capture keeps
            # its buffers in memory; native/subprocess writes still reach our
            # enclosing step log. No test uses a capfd fixture.
            step("tls-pytest", [interpreter, "-B", "-m", "pytest", "--capture=sys", "-q", "-r", "s", "-p", "no:cacheprovider",
                 "--basetemp", output / "pytest-temp", "--junitxml", output / "tls-pytest.xml", "base_tls/tests"])
            cases = list(ET.parse(output / "tls-pytest.xml").getroot().iter("testcase"))
            totals = {"tests": len(cases), "skipped": sum(c.find("skipped") is not None for c in cases),
                      "failures": sum(c.find("failure") is not None for c in cases),
                      "errors": sum(c.find("error") is not None for c in cases)}
            totals["passed"] = totals["tests"] - sum(totals[k] for k in ("skipped", "failures", "errors"))
            totals["skip_reasons"] = [{"test": c.get("name"), "reason": c.find("skipped").get("message", "")}
                                      for c in cases if c.find("skipped") is not None]
            record["tls_pytest"] = totals
            if totals["passed"] == 0 or totals["failures"] or totals["errors"]:
                raise ValueError("TLS JUnit contains no passing tests or a failure/error")
            step("tls-audit-live", [interpreter, "-B", ROOT / "base_tls/tools/audit_live_checks.py"])
            step("digest-native", [interpreter, "-B", ROOT / "tools/check_digest_native.py", "--library", library,
                 "--output", output / "digest-native.json"])
            if args.fixtures:
                step("fixtures-native-and-python", [interpreter, "-B", ROOT / "tools/alt_chain_fixtures.py", "verify",
                     "--fixtures", fixtures, "--library", library, "--output", output / "fixture-verification.json"])
                step("e1-wire-bytes", [interpreter, "-B", ROOT / "tools/alt_chain_fixtures.py", "e1",
                     "--fixtures", fixtures, "--handshake-signer", signer, "--output", output / "e1-wire-bytes.jsonl"])
                e1_rows = [json.loads(line) for line in (output / "e1-wire-bytes.jsonl").read_text().splitlines()]
                if len(e1_rows) != 5 or not all(row.get("passed") for row in e1_rows):
                    raise ValueError("E1 did not complete five successful profiles")
            else:
                record["preissued_fixture_gate"] = "not run; --fixtures absent; inspect pytest skip reasons"
            record["functional_gate_completed"] = True
        else:
            record["functional_gate_completed"] = False
        record["passed"] = True
    except BaseException as error:
        record["error"] = f"{type(error).__name__}: {error}"
        print(record["error"], file=sys.stderr, flush=True)
    finally:
        after = source_hashes()
        record["source_sha256_after"] = after
        record["source_unchanged"] = before == after
        if not record["source_unchanged"]:
            record["passed"] = False
            record["source_changes"] = [name for name in sorted(set(before) | set(after)) if before.get(name) != after.get(name)]
        if library.is_file():
            record["native_library_sha256_after"] = sha(library)
            record["native_library_unchanged"] = record.get("native_library_sha256_before") == sha(library)
            if not record["native_library_unchanged"]:
                record["passed"] = False
        if fixture_before is not None:
            record["fixture_sha256_after"] = tree_hashes(fixtures)
            record["fixtures_unchanged"] = fixture_before == record["fixture_sha256_after"]
            if not record["fixtures_unchanged"]:
                record["passed"] = False
        with (output / "manifest.json").open("x", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        print(json.dumps({"passed": record["passed"], "functional_gate_completed": record.get("functional_gate_completed", False),
                          "manifest": str(output / "manifest.json")}, ensure_ascii=False), flush=True)
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
