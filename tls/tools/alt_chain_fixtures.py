"""Generate once, verify and measure P0-P4 offline alternative CA fixtures.

Generation is deliberately separate from normal regression/handshake execution.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "base_tls"))
import tls  # initializes the project-local optional dependency paths
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from tls.alt_chain import build_alt_test_chain, verify_alt_chain, get_alt_signer
from tls.der import pre_tbs
from tls.pq.signature import get_pq_signer

ALGORITHMS = ("slh-dsa-sm3-128-24", "slh-dsa-sm3-128s", "ml-dsa-44")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_hashes():
    paths = [ROOT / name for name in ("tools/alt_chain_fixtures.py",
             "tools/native.py", "tools/signing_budget.py")]
    tls_root = ROOT / "base_tls/tls" if (ROOT / "base_tls/tls").is_dir() else ROOT / "tls"
    paths.extend(tls_root.rglob("*.py"))
    paths.extend((ROOT / "reference").glob("*.py"))
    return {p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in sorted(paths)}


def _sync_directory(path):
    # Windows does not expose a portable directory-fsync through os.open. File
    # contents are still synced; do not claim power-loss durability there.
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(path, data, *, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(path.parent)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _replace_json(path, value):
    """Write JSON through a synced sibling temporary file, then replace."""
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    write(temporary, json_bytes(value))
    os.replace(temporary, path)
    _sync_directory(path.parent)


def _validate_fixture(directory, name, campaign, ledger, args, sources, library_hash):
    """Reconcile preserved bytes, live charges and verified certificate edges."""
    if directory.is_symlink():
        raise ValueError("preserved fixture directory must not be a symlink")
    directory = directory.resolve()
    metadata = json.loads((directory / "fixture.json").read_text(encoding="utf-8"))
    expected = {"schema": "a15-alt-fixture-v1", "test_only": True,
        "alt_algorithm": name, "operation_prefix": campaign["operation_prefix"],
        "handshake_signer": args.handshake_signer, "sources_sha256": sources,
        "library_sha256": library_hash,
        "budget_ledger_uuid": ledger.ledger_uuid if ledger is not None else None}
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ValueError("preserved fixture campaign, provenance or ledger UUID differs")
    hashes = metadata["files_sha256"]
    required = {"leaf-test-key.pem", "root-test-key.pem", "intermediate-test-key.pem",
                "handshake-test-key.json", "leaf-pre-tbs.der", "intermediate-pre-tbs.der"}
    for kind in ("alt", "hybrid", "classical"):
        required.update(metadata["chains"][kind][label] for label in ("root", "leaf", "intermediate"))
    if not required.issubset(hashes):
        raise ValueError("preserved fixture lacks required file hashes")
    for filename, digest in hashes.items():
        path = (directory / filename).resolve()
        if not path.is_relative_to(directory) or not path.is_file() or sha(path.read_bytes()) != digest:
            raise ValueError("preserved fixture file missing, outside bundle or hash differs: " + filename)
    records = metadata["signing_records"]
    operations = {f"{campaign['operation_prefix']}:{name}:{label}" for label in ("intermediate", "leaf")}
    if len(records) != 2 or {row.get("operation_id") for row in records} != operations:
        raise ValueError("preserved fixture requires exactly two campaign signing records")
    by_operation = {row["operation_id"]: row for row in records}
    for operation, row in by_operation.items():
        if row.get("algorithm") != name or row.get("edge") != operation:
            raise ValueError("preserved CA signing record algorithm or operation differs")
        if ledger is not None:
            if row.get("ledger_uuid") != ledger.ledger_uuid or row.get("budget_status") != "committed":
                raise ValueError("preserved CA signing record lacks committed live-ledger binding")
            receipt = ledger.validate_receipt(row["budget_receipt"], algorithm=name,
                message_sha256=row["pre_tbs_sha256"], signature_sha256=row["signature_sha256"],
                operation_id=operation, case_identity=operation)
            if receipt["public_key_sha256"] != row["issuer_public_key_sha256"]:
                raise ValueError("preserved CA receipt public key differs")
        elif row.get("budget_receipt") is not None:
            raise ValueError("budgeted fixture cannot resume without its live ledger")
    from tls.alt_fixtures import load_fixture
    handshake = get_pq_signer(args.handshake_signer)
    chain = None
    for kind in ("alt", "hybrid", "classical"):
        loaded, *_ = load_fixture(directory, chain_kind=kind, identity=metadata["identity"],
            pq_signer=None if kind == "classical" else handshake, expected_algorithm=name,
            library=args.library, require_native=name.startswith("slh-"),
            threads=args.threads, backend=args.backend)
        if kind == "alt":
            chain = loaded
    result = verify_alt_chain(chain.chain_der, x509.load_der_x509_certificate(chain.root_der),
        metadata["identity"], require_alt_chain=True, expected_algorithm=name,
        library=args.library, require_native=name.startswith("slh-"),
        threads=args.threads, backend=args.backend)
    if not result.complete or result.checked_edges != 2 or len(result.verifiers) != 2:
        raise ValueError("preserved fixture does not verify both CA edges")
    for evidence in result.verifiers:
        label = {0: "leaf", 1: "intermediate"}[evidence["edge"]]
        row = by_operation[f"{campaign['operation_prefix']}:{name}:{label}"]
        if ledger is not None and (evidence["public_key_sha256"] != row["issuer_public_key_sha256"] or
                evidence["message_sha256"] != row["pre_tbs_sha256"] or
                evidence["signature_sha256"] != row["signature_sha256"]):
            raise ValueError("verified certificate edge differs from preserved CA receipt")
        if sha((directory / (label + "-pre-tbs.der")).read_bytes()) != evidence["message_sha256"]:
            raise ValueError("preserved preTBS differs from verified certificate edge")
    return metadata


def _validate_manifest(path, manifest):
    saved = json.loads(path.read_text(encoding="utf-8"))
    for key in ("schema", "test_only", "fixtures", "sources_sha256", "source_unchanged",
                "library_sha256", "library_unchanged", "operation_prefix", "budget_ledger_uuid"):
        if saved.get(key) != manifest[key]:
            raise ValueError("preserved generation manifest differs: " + key)
    if manifest["budget_ledger_uuid"] is not None:
        reconciliation = saved.get("ledger_reconciliation") or {}
        if reconciliation.get("ledger_uuid") != manifest["budget_ledger_uuid"] or reconciliation.get("reconciled") is not True:
            raise ValueError("preserved generation manifest lacks ledger reconciliation")


def generate(args):
    if args.budget_db is None and not args.test_only_no_budget:
        raise ValueError("fixture generation requires --budget-db; explicit test-only bypass is separate")
    output = args.output.resolve()
    if output.exists() and not args.resume:
        raise ValueError("output directory already exists; refuse to mix generations")
    output.parent.mkdir(parents=True, exist_ok=True)
    algorithms = tuple(args.algorithm or ALGORITHMS)
    if len(set(algorithms)) != len(algorithms) or any(name not in ALGORITHMS for name in algorithms):
        raise ValueError("fixture algorithms must be unique supported names")
    before = source_hashes()
    library_before = sha(Path(args.library).read_bytes())
    now = datetime.now(timezone.utc).replace(microsecond=0)

    finalized = False
    if args.resume:
        requested = Path(args.resume).resolve()
        staging = requested
        if output.exists():
            if requested != output and requested.exists():
                raise ValueError("output and staging both exist; refuse to mix generations")
            staging, finalized = output, True
        campaign_path = staging / "campaign.json"
        if not staging.is_dir() or staging.is_symlink() or not campaign_path.is_file():
            raise ValueError("--resume requires a retained staging or completed generation")
        campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
        if campaign.get("schema") != "a15-fixture-campaign-v1":
            raise ValueError("unrecognised staging campaign schema")
        if finalized and requested != output and campaign.get("staging_path") != str(requested):
            raise ValueError("completed output does not belong to the requested staging directory")
        staged_algorithms = campaign["algorithms"]
        if len(set(staged_algorithms)) != len(staged_algorithms) or set(staged_algorithms) != set(algorithms):
            raise ValueError("--algorithm differs from the staged campaign")
        algorithms = tuple(staged_algorithms)
        done = campaign["completed"]
        if len(set(done)) != len(done) or not set(done).issubset(algorithms):
            raise ValueError("staged completion list is invalid")
        operation_prefix = campaign["operation_prefix"]
        if not isinstance(operation_prefix, str) or not operation_prefix:
            raise ValueError("staged operation prefix is invalid")
        now = datetime.fromisoformat(campaign["started_utc"])
        if now.tzinfo is None:
            raise ValueError("staged campaign time must include a timezone")
    else:
        staging = output.parent / ("." + output.name + ".staging-" + uuid.uuid4().hex)
        staging.mkdir(parents=False, exist_ok=False)
        _sync_directory(output.parent)
        campaign = {"schema": "a15-fixture-campaign-v1",
                    "operation_prefix": uuid.uuid4().hex,
                    "started_utc": now.isoformat(), "algorithms": list(algorithms),
                    "completed": []}

    ledger = None
    if args.budget_db is not None:
        from tools.signing_budget import SigningBudget
        ledger = SigningBudget(args.budget_db)
        ledger.reconcile()
        reserve, finish = ledger.reserve, ledger.finish
    else:
        reserve = finish = None
    binding = {"output_path": str(output), "sources_sha256": before,
               "library_sha256": library_before, "handshake_signer": args.handshake_signer,
               "budget_ledger_uuid": ledger.ledger_uuid if ledger is not None else None}
    if any(key in campaign and campaign[key] != value for key, value in binding.items()):
        raise ValueError("staged campaign provenance, output or ledger UUID differs")
    # Missing legacy bindings are accepted only after each preserved fixture has
    # independently passed the same provenance and live-receipt checks below.
    if not args.resume:
        campaign.update(binding, staging_path=str(staging))
        write(staging / "campaign.json", json_bytes(campaign))

    signer = None
    completed = []
    try:
        for name in algorithms:
            published = staging / name
            metadata = None
            if published.exists():
                metadata = _validate_fixture(published, name, campaign, ledger, args, before, library_before)
            elif name in campaign["completed"] or finalized:
                raise ValueError("completed campaign is missing a preserved fixture")
            else:
                candidates = [p for p in staging.glob("." + name + ".work-*") if (p / "fixture.json").is_file()]
                if len(candidates) > 1:
                    raise ValueError("multiple complete work directories require explicit reconciliation")
                if candidates:
                    work = candidates[0]
                    metadata = _validate_fixture(work, name, campaign, ledger, args, before, library_before)
                    os.replace(work, published)
                    _sync_directory(staging)
            if metadata is not None:
                if name not in campaign["completed"]:
                    campaign["completed"].append(name)
                    _replace_json(staging / "campaign.json", campaign)
                completed.append({"algorithm": name, "fixture_path": str(output / name),
                                  "fixture_sha256": sha(json_bytes(metadata))})
                print(json.dumps({"phase": "fixture-generation", "algorithm": name,
                                  "status": "already-published"}), flush=True)
                continue
            if args.resume and any(key not in campaign for key in binding):
                raise ValueError("legacy campaign lacks durable provenance/ledger binding; refuse new signing")
            if ledger is not None:
                for label in ("intermediate", "leaf"):
                    operation = f"{campaign['operation_prefix']}:{name}:{label}"
                    existing = ledger.operation(operation)
                    if existing is not None:
                        raise RuntimeError(
                            f"operation {operation} was already charged with status "
                            f"{existing['status']} but has no complete preserved fixture; refusing to "
                            "re-sign. Reconcile the ledger and start a new campaign."
                        )
            if signer is None:
                signer = get_pq_signer(args.handshake_signer)
                secret, public = signer.keygen()
                secret_bytes = secret.key if hasattr(secret, "key") else secret
                if not isinstance(secret_bytes, bytes):
                    raise ValueError("fixture handshake signer must have a serializable stateless secret")
                leaf_key, root_key, intermediate_key = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
            print(json.dumps({"phase": "fixture-generation", "algorithm": name}), flush=True)
            work = staging / ("." + name + ".work-" + uuid.uuid4().hex)
            work.mkdir(parents=False, exist_ok=False)
            material = build_alt_test_chain(name, leaf_key=leaf_key, root_key=root_key,
                intermediate_key=intermediate_key, pq_scheme_id=signer.scheme_id,
                pq_public_key=public, threads=args.threads, library=args.library,
                backend=args.backend, before_sign=reserve, after_sign=finish, now=now,
                operation_prefix=f"{campaign['operation_prefix']}:{name}",
                cache_dir=args.ca_cache_dir, cache_level=args.ca_cache_level)
            if ledger is not None:
                for row in material.signing_records:
                    reconciliation_row = ledger.validate_receipt(row["budget_receipt"],
                        algorithm=row["algorithm"], message_sha256=row["pre_tbs_sha256"],
                        signature_sha256=row["signature_sha256"],
                        operation_id=row["operation_id"], case_identity=row["edge"])
                    if reconciliation_row["public_key_sha256"] != row["issuer_public_key_sha256"]:
                        raise ValueError("CA receipt public key differs from issued edge")
                    row["ledger_uuid"] = ledger.ledger_uuid
            files, chains = {}, {}
            for kind, chain, prefix in (("alt", material.chain, ""), ("hybrid", material.baseline_chain, "hybrid-"),
                                        ("classical", material.classical_chain, "classical-")):
                chains[kind] = {}
                for label, data in (("root", chain.root_der), ("leaf", chain.leaf_der), ("intermediate", chain.chain_der[1])):
                    filename = prefix + label + ".der"
                    files[filename] = data
                    chains[kind][label] = filename
            for label, key in (("leaf", leaf_key), ("root", root_key), ("intermediate", intermediate_key)):
                files[label + "-test-key.pem"] = key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            files["handshake-test-key.json"] = json_bytes({"test_only": True, "algorithm": signer.name,
                                                          "public_key": public.hex(), "secret_key": secret_bytes.hex()})
            for label, blob in (("leaf", material.chain.leaf_der), ("intermediate", material.chain.chain_der[1])):
                files[label + "-pre-tbs.der"] = pre_tbs(x509.load_der_x509_certificate(blob).tbs_certificate_bytes)
            for filename, data in files.items():
                write(work / filename, data, private="key" in filename)
            metadata = {"schema": "a15-alt-fixture-v1", "test_only": True, "alt_algorithm": name,
                        "identity": "server.example", "handshake_signer": signer.name,
                        "generated_at_utc": now.isoformat(), "validity": {"not_before": (now.timestamp()-86400), "not_after": now.timestamp()+365*86400},
                        "chains": chains, "files_sha256": {k: sha(v) for k, v in files.items()},
                        "signing_records": material.signing_records,
                        "cache_records": material.cache_records, "sources_sha256": before,
                        "budget_ledger_uuid": ledger.ledger_uuid if ledger is not None else None,
                        "operation_prefix": campaign["operation_prefix"],
                        "library_sha256": library_before, "backend": args.backend,
                        "threads": args.threads,
                        "scope": "offline test-only CA chains; private test keys are fixture credentials, not production keys"}
            # A complete work manifest is an atomic recovery marker, not a claim
            # that budget alone proves the files or certificate signatures.
            _replace_json(work / "fixture.json", metadata)
            _validate_fixture(work, name, campaign, ledger, args, before, library_before)
            os.replace(work, published)
            _sync_directory(staging)
            campaign["completed"].append(name)
            _replace_json(staging / "campaign.json", campaign)
            completed.append({"algorithm": name, "fixture_path": str(output / name),
                              "fixture_sha256": sha(json_bytes(metadata))})
        if before != source_hashes():
            raise ValueError("fixture source changed during generation")
        if library_before != sha(Path(args.library).read_bytes()):
            raise ValueError("fixture native library changed during generation")
        manifest = {"schema": "a15-alt-fixtures-v1", "test_only": True,
            "generated_at_utc": now.isoformat(), "fixtures": completed, "sources_sha256": before,
            "command": sys.argv, "source_unchanged": True,
            "library_sha256": library_before, "library_unchanged": True,
            "operation_prefix": campaign["operation_prefix"],
            "ledger_reconciliation": ledger.reconcile() if ledger is not None else None,
            "budget_ledger_uuid": ledger.ledger_uuid if ledger is not None else None}
        manifest_path = staging / "MANIFEST.json"
        if manifest_path.exists():
            _validate_manifest(manifest_path, manifest)
        elif finalized:
            raise ValueError("published generation has no complete manifest")
        else:
            _replace_json(manifest_path, manifest)
        if not finalized:
            os.replace(staging, output)
            _sync_directory(output.parent)
        print(json.dumps({"completed": completed, "output": str(output),
                          "operation_prefix": campaign["operation_prefix"]}), flush=True)
    except BaseException as error:
        error.add_note(f"staging directory retained for reconciliation: {staging}")
        raise


def verify(args):
    from tls.alt_fixtures import load_fixture
    rows = []
    for name in ALGORITHMS:
        directory = args.fixtures / name
        if not (directory / "fixture.json").is_file():
            # A campaign may intentionally issue only the algorithm it needs (for
            # example the SLH CA chain with a Rain online signer).
            continue
        metadata = json.loads((directory / "fixture.json").read_text())
        signer = get_pq_signer(metadata["handshake_signer"])
        chain, _, _, _ = load_fixture(directory, pq_signer=signer, expected_algorithm=name,
                                       library=args.library, require_native=name.startswith("slh-"),
                                       threads=args.threads, backend=args.backend)
        root = x509.load_der_x509_certificate(chain.root_der)
        for python in ([False, True] if name.startswith("slh-") else [False]):
            result = verify_alt_chain(chain.chain_der, root, "server.example", require_alt_chain=True,
                                      expected_algorithm=name, force_python=python,
                                      require_native=name.startswith("slh-") and not python,
                                      library=args.library, threads=args.threads, backend=args.backend)
            expected_mode = "python" if python else ("native" if name.startswith("slh-") else "provider")
            if any(x["mode"] != expected_mode for x in result.verifiers):
                raise ValueError("fixture verifier did not execute its required backend")
            rows.append({"algorithm": name, "verifier": expected_mode, "verifiers": result.verifiers,
                         "checked_edges": result.checked_edges, "passed": result.complete,
                         "fixture_sha256": sha((directory / "fixture.json").read_bytes())})
    write(args.output, json_bytes({"schema": "a15-alt-fixture-verification-v1", "passed": all(x["passed"] for x in rows),
                                 "rows": rows, "sources_sha256": source_hashes(), "command": sys.argv}))
    print(json.dumps(rows), flush=True)


def e1(args):
    from tls.alt_profiles import profiles, e1_record
    configs = profiles(args.fixtures, handshake_signer=args.handshake_signer)
    with args.output.open("x", encoding="utf-8") as stream:
        for code, config in configs.items():
            record = e1_record(code, config)
            record.update({"generated_at_utc": datetime.now(timezone.utc).isoformat(),
                           "sources_sha256": source_hashes(), "command": sys.argv})
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            print(json.dumps({"profile": code, "passed": record["passed"],
                              "server_flight_bytes": record["server_flight_bytes"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    gen = commands.add_parser("generate")
    gen.add_argument("--output", type=Path, required=True)
    gen.add_argument("--library", type=Path, required=True)
    gen.add_argument("--threads", type=int, default=32)
    gen.add_argument("--backend", type=int, default=0, choices=(0, 1, 2, 5),
                     help="0 auto, 1 reference, 2 AVX2, 5 CUDA")
    gen.add_argument("--handshake-signer", default="falcon-512")
    gen.add_argument("--budget-db", type=Path)
    gen.add_argument("--ca-cache-dir", type=Path,
                     help="explicit offline CA cache directory; builds and saves a cache per CA key")
    gen.add_argument("--ca-cache-level", type=int, default=6,
                     help="subtree level for the explicit offline cache build (costly; not used online)")
    gen.add_argument("--algorithm", action="append", choices=ALGORITHMS,
                     help="repeat to issue only the named algorithm(s); default is all three")
    gen.add_argument("--resume", type=Path,
                     help="resume a retained staging directory; already-charged edges are never re-signed")
    gen.add_argument("--test-only-no-budget", action="store_true")
    for action in ("verify", "e1"):
        sub = commands.add_parser(action)
        sub.add_argument("--fixtures", type=Path, required=True)
        sub.add_argument("--output", type=Path, required=True)
        if action == "e1":
            sub.add_argument("--handshake-signer", default="falcon-512")
        else:
            sub.add_argument("--library", type=Path, required=True,
                             help="explicit native library; both native and independent Python paths are mandatory")
            sub.add_argument("--threads", type=int, default=32)
            sub.add_argument("--backend", type=int, default=0, choices=(0, 1, 2, 5))
    args = parser.parse_args()
    if args.action == "generate":
        generate(args)
    elif args.action == "verify":
        verify(args)
    else:
        e1(args)


if __name__ == "__main__":
    main()
