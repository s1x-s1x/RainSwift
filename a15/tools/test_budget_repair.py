"""SQLite and preserved-evidence checks; no native code or performance samples."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_cpu as cpu
import bench_cuda as cuda
from signing_budget import SigningBudget, BudgetError, canonical_algorithm


class BudgetRepair(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a15-budget-repair-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.path = self.folder / "ledger.sqlite"
        self.public = b"p"*32
        self.message = b"\x00\x01cm"
        self.signature = b"signature"

    def legacy(self, *, corrupt=False, limits=(1, 1)):
        db = sqlite3.connect(self.path)
        db.executescript("""
          CREATE TABLE keys(key_id TEXT PRIMARY KEY,algorithm TEXT NOT NULL,
            public_key BLOB NOT NULL,limit_text TEXT NOT NULL,used_text TEXT NOT NULL,created_utc TEXT NOT NULL);
          CREATE TABLE reservations(receipt TEXT PRIMARY KEY,key_id TEXT NOT NULL REFERENCES keys(key_id),
            ordinal_text TEXT NOT NULL,message_sha256 TEXT NOT NULL,reserved_utc TEXT NOT NULL,
            status TEXT NOT NULL,signature_sha256 TEXT,finished_utc TEXT,UNIQUE(key_id,ordinal_text));
        """)
        for index, algorithm in enumerate(("SLH-DSA-SM3-128-24", "slh-dsa-sm3-128-24")):
            identifier = hashlib.sha256(algorithm.encode()+b"\0"+self.public).hexdigest()
            used = "2" if corrupt and index == 0 else "1"
            db.execute("INSERT INTO keys VALUES(?,?,?,?,?,?)", (identifier, algorithm, self.public, str(limits[index]), used, "2026-01-01"))
            db.execute("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)",
                (f"old-{index}", identifier, "1", cpu.sha(self.message), f"2026-01-0{index+1}",
                 "committed" if index == 0 else "failed", cpu.sha(self.signature) if index == 0 else None, "2026-01-03"))
        db.commit(); db.close()

    def test_aliases_share_one_small_allowance(self):
        budget = SigningBudget(self.path)
        receipt = budget.reserve("SLH-DSA-SM3-128-24", self.public, self.message, limit=1)
        budget.finish(receipt, self.signature)
        with self.assertRaisesRegex(BudgetError, "exhausted"):
            budget.reserve("slh-dsa-sm3-128-24", self.public, self.message, limit=1)
        self.assertEqual(len(budget.status()), 1)
        self.assertEqual(budget.validate_receipt(receipt, algorithm="SLH-DSA-SM3-128-24",
            public_key=self.public, message=self.message, signature=self.signature)["algorithm"], "slh-dsa-sm3-128-24")

    def test_legacy_alias_migration_retains_all_charges_and_receipts(self):
        self.legacy()
        budget = SigningBudget(self.path)
        row = budget.status()[0]
        self.assertEqual((row["used"], row["limit"], row["remaining"]), (2, 1, -1))
        self.assertTrue(row["count_reconciled"])
        self.assertEqual(row["states"], {"committed": 1, "failed": 1})
        budget.validate_receipt("old-0", public_key=self.public, signature=self.signature)
        budget.validate_receipt("old-1", statuses=("failed",))
        self.assertEqual(SigningBudget(self.path).ledger_uuid, budget.ledger_uuid)
        with self.assertRaisesRegex(BudgetError, "exhausted"):
            budget.reserve("SLH-DSA-SM3-128-24", self.public, self.message, limit=1)
        with budget.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM identity_migrations").fetchone()[0], 2)
            self.assertEqual({x[0] for x in db.execute("SELECT ordinal_text FROM reservations")}, {"1", "2"})

    def test_migration_uses_stricter_limit(self):
        self.legacy(limits=(7, 3))
        budget = SigningBudget(self.path)
        self.assertEqual(budget.status()[0]["limit"], 3)
        receipt = budget.reserve("slh-dsa-sm3-128-24", self.public, self.message, limit=3)
        budget.finish(receipt)
        with self.assertRaises(BudgetError):
            budget.reserve("SLH-DSA-SM3-128-24", self.public, self.message, limit=3)

    def test_bad_legacy_count_fails_transactionally(self):
        self.legacy(corrupt=True)
        with self.assertRaisesRegex(BudgetError, "reconciliation"):
            SigningBudget(self.path)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM keys").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ledger_metadata").fetchone()[0], 0)

    def test_parallel_alias_calls_consume_exact_limit_even_on_failure(self):
        budget = SigningBudget(self.path)
        def attempt(index):
            try:
                ledger = SigningBudget(self.path)
                name = "SLH-DSA-SM3-128-24" if index % 2 else "slh-dsa-sm3-128-24"
                receipt = ledger.reserve(name, self.public, str(index).encode(), limit=7)
                ledger.finish(receipt, self.signature if index % 2 else None)
                return True
            except BudgetError:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(32))), 7)
        self.assertEqual(budget.status()[0]["used"], 7)
        self.assertTrue(budget.status()[0]["count_reconciled"])

    def test_allowlist_and_bool_limits(self):
        budget = SigningBudget(self.path)
        for name in ("SLH-DSA-SM3-128-24 ", "invented-128-24", "slh-dsa-sha2-unknown"):
            with self.assertRaises(ValueError): budget.reserve(name, self.public, self.message)
        with self.assertRaises(ValueError): budget.reserve("slh-dsa-sm3-128-24", self.public, self.message, limit=True)
        self.assertEqual(canonical_algorithm("ML-DSA-44"), "ml-dsa-44")
        self.assertEqual(SigningBudget.key_id("ML-DSA-44", self.public), SigningBudget.key_id("ml-dsa-44", self.public))

    def test_receipt_checks_every_bound_field(self):
        budget = SigningBudget(self.path)
        receipt = budget.reserve("slh-dsa-sm3-128-24", self.public, self.message)
        with self.assertRaises(BudgetError): budget.validate_receipt(receipt)
        budget.finish(receipt, self.signature)
        for fields in ({"algorithm": "slh-dsa-sm3-128s"}, {"public_key": b"other"},
                       {"message": b"other"}, {"signature": b"other"}):
            with self.assertRaises(BudgetError): budget.validate_receipt(receipt, **fields)
        with self.assertRaises(BudgetError): budget.finish(receipt, self.signature)

    def evidence(self):
        budget = SigningBudget(self.path)
        case = cpu.case_record(3, "sign", samples=1, family="unit")
        case.update(backend="CUDA", backend_id=5, warmups=0)
        inputs = {"pk": self.public, "message": b"m", "context": b"c"}
        binding = cpu.budget_binding(budget, case, inputs)
        case_key, segment = "c"*64, "1"*32
        operation = cpu.operation_identity(case_key, segment, "sample", 0)
        receipt = budget.reserve(cpu.ALGORITHMS[3], self.public, self.message,
                                 operation_id=operation, case_identity=case_key)
        budget.finish(receipt, self.signature)
        path = self.folder/"p3-fixture.json"
        path.write_text(json.dumps({k: v.hex() for k, v in inputs.items()}))
        input_hashes = {k: cpu.sha(v) for k, v in inputs.items()}
        sample = {"kind": "sample", "sample_index": 0, "passed": True, "duration_ns": 100,
                  "case_key": case_key, "segment_id": segment, "operation_id": operation,
                  "case_id": case["case_id"], "classification": "diagnostic",
                  "receipt": receipt, "budget_evidence": budget.validate_receipt(receipt),
                  "result_sha256": cpu.sha(self.signature), "input_hashes": input_hashes,
                  "actual_backend": 5, "end_to_end_ns": 100, "kernel_ns": 40,
                  "cuda_stats": {"kernel_ns": 40, "timing_enabled": 1, "kernel_launches": 1, "device_hashes": 1}}
        provenance = {"final": False, "classification": "diagnostic", "source_sha256": {},
                      "library_sha256": "mock", "build_record_sha256": None, "freeze_sha256": None}
        files = {str(path): cpu.file_sha(path)}
        complete = {"kind": "case_complete", "ledger_uuid": budget.ledger_uuid,
                    "case_key": case_key, "segment_id": segment, "evidence_version": 2,
                    **cpu.completion_metadata(case, provenance, 5, {}),
                    "input_hashes": input_hashes, "input_files_before": files, "input_files_after": files,
                    "samples": [100], **cpu.summary([100]), "kernel_samples": [40], "kernel_summary": cpu.summary([40])}
        records = [{"kind": "case_start", "ledger_uuid": budget.ledger_uuid,
                    "case_key": case_key, "segment_id": segment, "evidence_version": 2,
                    "case": case, "provenance": provenance, "environment_identity": {}},
                   {"kind": "inputs_ready", "ledger_uuid": budget.ledger_uuid, "budget_binding": binding,
                    "case_key": case_key, "segment_id": segment, "actual_backend": 5,
                    "input_hashes": input_hashes, "input_files": files},
                   {"kind": "segment_warmup_complete", "case_key": case_key, "segment_id": segment,
                    "warmups": 0, "timed": False, "remaining_sample_indices": [0]}, sample, complete]
        return budget, case, records

    def test_complete_cpu_and_cuda_check_live_receipts_before_skip(self):
        budget, case, records = self.evidence()
        self.assertTrue(cpu.validate_completed(records, case, self.folder, budget))
        self.assertTrue(cuda.validate_completed(records, case, self.folder, budget))
        receipt = records[3]["receipt"]
        changed = {**budget.validate_receipt(receipt), "signature_sha256": "0"*64}
        with patch.object(budget, "validate_receipt", return_value=changed):
            for checker in (cpu.validate_completed, cuda.validate_completed):
                with self.assertRaisesRegex(ValueError, "live receipt"):
                    checker(records, case, self.folder, budget)

    def test_new_database_rejects_complete_and_partial_resume(self):
        budget, case, records = self.evidence()
        other = SigningBudget(self.folder/"other.sqlite")
        self.assertNotEqual(other.ledger_uuid, budget.ledger_uuid)
        for evidence in (records, records[:-1]):
            with self.assertRaisesRegex(ValueError, "ledger UUID"):
                cpu.validate_preserved_budget(evidence, case, other)

    def test_sample_digest_and_duplicate_receipt_rejected(self):
        budget, case, records = self.evidence()
        changed = copy.deepcopy(records); changed[3]["result_sha256"] = "0"*64
        with self.assertRaisesRegex(ValueError, "signature differs"):
            cpu.validate_preserved_budget(changed, case, budget)
        changed = records+[dict(records[3])]
        with self.assertRaisesRegex(ValueError, "reused"):
            cpu.validate_preserved_budget(changed, case, budget)

    def test_live_uuid_replacement_rejected(self):
        budget = SigningBudget(self.path)
        with budget.connection() as db: db.execute("UPDATE ledger_metadata SET value=? WHERE name='ledger_uuid'", ("0"*32,))
        with self.assertRaisesRegex(BudgetError, "UUID changed"):
            budget.reserve("slh-dsa-sm3-128-24", self.public, self.message)

    def test_fixture_signature_reconciliation(self):
        budget, case, records = self.evidence()
        receipt = records[3]["receipt"]
        saved = {"receipt": receipt, "ledger_uuid": budget.ledger_uuid, "sig": self.signature.hex(),
                 "fixture_sha256": cpu.file_sha(self.folder/"p3-fixture.json")}
        cpu.atomic_json(self.folder/"p3-signature.json", saved)
        cpu.validate_fixture_receipts(self.folder, 3, budget)
        saved["ledger_uuid"] = "0"*32
        (self.folder/"p3-signature.json").write_text(json.dumps(saved))
        with self.assertRaisesRegex(ValueError, "ledger/input binding"):
            cpu.validate_fixture_receipts(self.folder, 3, budget)

    def test_operation_identity_is_unique_and_case_bound(self):
        budget = SigningBudget(self.path)
        receipt = budget.reserve("ml-dsa-44", self.public, self.message,
                                 operation_id="campaign:case:segment:sample:0", case_identity="case-A")
        budget.finish(receipt, self.signature)
        budget.validate_receipt(receipt, operation_id="campaign:case:segment:sample:0", case_identity="case-A")
        for fields in ({"case_identity": "case-B"}, {"operation_id": "another-operation"}):
            with self.assertRaisesRegex(BudgetError, "identity differs"):
                budget.validate_receipt(receipt, **fields)
        with self.assertRaisesRegex(BudgetError, "already charged"):
            budget.reserve("ml-dsa-44", self.public, self.message,
                           operation_id="campaign:case:segment:sample:0", case_identity="case-B")
        self.assertEqual(budget.status()[0]["used"], 1)
        for fields in ({"operation_id": "op"}, {"case_identity": "case"},
                       {"operation_id": "", "case_identity": "case"}):
            with self.assertRaises(ValueError):
                budget.reserve("ml-dsa-44", self.public, self.message, **fields)

    def test_campaign_rejects_cross_case_receipt_replay_but_allows_references(self):
        budget, case, records = self.evidence()
        operation = records[3]
        copied = {**operation, "case_key": "another-case", "operation_id": "another-operation"}
        with self.assertRaisesRegex(ValueError, "campaign signing receipt reused"):
            cpu.validate_campaign_receipts(records + [copied])
        cpu.validate_campaign_receipts(records + [
            {"kind": "setup_signature", "receipt": operation["receipt"]},
            {"kind": "fixture_reference", "receipt": operation["receipt"]}])
        changed = copy.deepcopy(records)
        for row in changed:
            row["case_key"] = "new-case-key"
        changed[3]["operation_id"] = cpu.operation_identity("new-case-key", changed[3]["segment_id"], "sample", 0)
        with self.assertRaisesRegex(ValueError, "operation/case binding"):
            cpu.validate_preserved_budget(changed, case, budget)

    def test_completion_metadata_is_bound_to_plan_and_starting_provenance(self):
        budget, case, records = self.evidence()
        changes = {"case_id": "wrong-case", "pid": 999, "op": "verify", "backend": "REF",
            "actual_backend": 1, "threads": 4, "cache_t": 3, "requested_cache_t": "3",
            "keygen_mode": "rng", "family": "wrong-family", "final": True,
            "classification": "formal", "source_sha256_before": {"wrong": "source"},
            "source_sha256_after": {"wrong": "source"}, "library_sha256_before": "wrong",
            "library_sha256_after": "wrong", "freeze_sha256": "wrong", "build_record_sha256": "wrong",
            "environment_identity": {"wrong": "host"}, "case_key": "wrong-key"}
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(records); changed[-1][field] = value
                for checker in (cpu.validate_completed, cuda.validate_completed):
                    with self.assertRaisesRegex(ValueError, "completion metadata"):
                        checker(changed, case, self.folder, budget)
        for field in ("input_hashes", "input_files_before", "input_files_after"):
            changed = copy.deepcopy(records); changed[-1][field] = {}
            with self.assertRaisesRegex(ValueError, "completion input metadata"):
                cpu.validate_completed(changed, case, self.folder, budget)

    def test_old_unsegmented_performance_evidence_cannot_resume(self):
        budget, case, records = self.evidence()
        changed = copy.deepcopy(records)
        changed[0].pop("evidence_version")
        with self.assertRaisesRegex(ValueError, "start fresh evidence"):
            cpu.validate_completed(changed, case, self.folder, budget)
        # Existing unbound CA/fixture receipts keep their old API fields.
        receipt = budget.reserve("ml-dsa-44", self.public, self.message)
        budget.finish(receipt, self.signature)
        evidence = budget.validate_receipt(receipt)
        self.assertNotIn("operation_id", evidence)
        self.assertNotIn("case_identity", evidence)

    def test_append_only_and_finalization_guards_reject_sql_mutation(self):
        budget = SigningBudget(self.path)
        receipt = budget.reserve("ml-dsa-44", self.public, self.message)
        budget.finish(receipt, self.signature)
        statements = ["DELETE FROM reservations", "DELETE FROM keys", "DELETE FROM accounting",
            "UPDATE reservations SET ordinal_text='2'", "UPDATE reservations SET message_sha256='changed'",
            "UPDATE reservations SET signature_sha256='" + "0"*64 + "'",
            "UPDATE keys SET limit_text='999'", "UPDATE keys SET algorithm='unknown'"]
        statements.extend(["UPDATE keys SET used_text='0'", "UPDATE accounting SET used_text='0'",
                           "UPDATE accounting SET last_receipt='missing'"])
        with budget.connection() as db:
            for statement in statements:
                with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                    db.execute(statement)
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("INSERT INTO reservations(receipt,key_id,ordinal_text,message_sha256,reserved_utc,status) "
                           "SELECT 'uncharged',key_id,'2','" + "0"*64 + "','now','reserved' FROM keys")
        self.assertEqual(budget.reconcile()["reservations"], 1)

    def test_live_count_corruption_fails_fast_and_on_reopen(self):
        budget = SigningBudget(self.path)
        receipt = budget.reserve("ml-dsa-44", self.public, self.message)
        budget.finish(receipt, self.signature)
        for table, field, value in (("keys", "used_text", "0"), ("accounting", "used_text", "0"),
                                    ("accounting", "last_receipt", "missing")):
            with self.subTest(table=table, field=field):
                with budget.connection() as db:
                    old = db.execute(f"SELECT {field} FROM {table}").fetchone()[0]
                    guard = "budget_key_charge" if table == "keys" else "budget_accounting_charge"
                    statement = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (guard,)).fetchone()[0]
                    # Simulate page/storage corruption after defeating the SQL
                    # write guard, then restore its exact definition. Ordinary
                    # SQL mutation is tested separately and is rejected.
                    db.execute("DROP TRIGGER " + guard)
                    db.execute(f"UPDATE {table} SET {field}=?", (value,))
                    db.execute(statement)
                with self.assertRaisesRegex(BudgetError, "reconciliation"):
                    budget.reserve("ml-dsa-44", self.public, self.message)
                with self.assertRaisesRegex(BudgetError, "reconciliation"):
                    budget.validate_receipt(receipt)
                with self.assertRaisesRegex(BudgetError, "reconciliation"):
                    SigningBudget(self.path)
                with budget.connection() as db:
                    db.execute("DROP TRIGGER " + guard)
                    db.execute(f"UPDATE {table} SET {field}=?", (old,))
                    db.execute(statement)

    def test_dropped_guard_fails_before_any_new_charge(self):
        budget = SigningBudget(self.path)
        receipt = budget.reserve("ml-dsa-44", self.public, self.message)
        with budget.connection() as db:
            db.execute("DROP TRIGGER budget_reservation_no_delete")
        for operation in (lambda: budget.reserve("ml-dsa-44", self.public, self.message),
                          lambda: budget.validate_receipt(receipt, statuses=("reserved",)), budget.reconcile,
                          lambda: SigningBudget(self.path)):
            with self.assertRaisesRegex(BudgetError, "guard differs or is missing"):
                operation()
        with budget.connection() as db:
            self.assertEqual(db.execute("SELECT used_text FROM keys").fetchone()[0], "1")

    def test_ordinal_corruption_is_found_by_explicit_full_reconciliation(self):
        budget = SigningBudget(self.path)
        for index in range(3):
            receipt = budget.reserve("ml-dsa-44", self.public, self.message)
            budget.finish(receipt)
        with budget.connection() as db:
            statement = db.execute("SELECT sql FROM sqlite_master WHERE name='budget_reservation_identity'").fetchone()[0]
            db.execute("DROP TRIGGER budget_reservation_identity")
            db.execute("UPDATE reservations SET ordinal_text='99' WHERE ordinal_text='1'")
            db.execute(statement)
        with self.assertRaisesRegex(BudgetError, "ordinal reconciliation"):
            budget.reconcile()
        with self.assertRaisesRegex(BudgetError, "ordinal reconciliation"):
            SigningBudget(self.path)

    def test_interrupted_charge_transaction_rolls_back_both_counters(self):
        budget = SigningBudget(self.path)
        receipt = budget.reserve("ml-dsa-44", self.public, self.message)
        budget.finish(receipt)
        real_connection = budget.connection
        @contextmanager
        def interrupted_connection():
            with real_connection() as db:
                # sqlite3 authorizer simulates an INSERT failure after the
                # two counter updates, without weakening production guards.
                db.set_authorizer(lambda action, table, *unused:
                    sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and table == "reservations" else sqlite3.SQLITE_OK)
                yield db
        with patch.object(budget, "connection", interrupted_connection), self.assertRaises(sqlite3.DatabaseError):
            budget.reserve("ml-dsa-44", self.public, self.message)
        self.assertEqual(budget.reconcile()["reservations"], 1)
        self.assertEqual(budget.status()[0]["used"], 1)

    def test_large_history_fast_path_has_bounded_vm_work_and_no_count_scan(self):
        work = []
        for count in (100, 10000):
            path = self.folder / f"large-{count}.sqlite"
            identifier = SigningBudget.key_id("ml-dsa-44", self.public)
            with closing(sqlite3.connect(path)) as db:
                db.executescript("""
                  CREATE TABLE keys(key_id TEXT PRIMARY KEY,algorithm TEXT NOT NULL,public_key BLOB NOT NULL,
                    limit_text TEXT NOT NULL,used_text TEXT NOT NULL,created_utc TEXT NOT NULL);
                  CREATE TABLE reservations(receipt TEXT PRIMARY KEY,key_id TEXT NOT NULL REFERENCES keys(key_id),
                    ordinal_text TEXT NOT NULL,message_sha256 TEXT NOT NULL,reserved_utc TEXT NOT NULL,status TEXT NOT NULL,
                    signature_sha256 TEXT,finished_utc TEXT,UNIQUE(key_id,ordinal_text));
                  CREATE TABLE ledger_metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL);
                """)
                db.execute("INSERT INTO keys VALUES(?,?,?,?,?,?)", (identifier, "ml-dsa-44", self.public, str(1<<64), str(count), "now"))
                db.execute("INSERT INTO ledger_metadata VALUES('identity_schema','2')")
                db.execute("INSERT INTO ledger_metadata VALUES('ledger_uuid',?)", ("9"*32,))
                db.executemany("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)", (
                    (f"receipt-{index}", identifier, str(index+1), cpu.sha(self.message), "now", "failed", None, "now")
                    for index in range(count)))
                db.commit()
            budget = SigningBudget(path)
            real_connection = budget.connection
            steps, statements = [0], []
            @contextmanager
            def observed_connection():
                with real_connection() as db:
                    def progress():
                        steps[0] += 1
                        return 0
                    db.set_progress_handler(progress, 1)
                    db.set_trace_callback(statements.append)
                    yield db
            with patch.object(budget, "connection", observed_connection):
                budget.validate_receipt("receipt-0", statuses=("failed",))
                validation_steps = steps[0]
                steps[0] = 0
                budget.reserve("ml-dsa-44", self.public, self.message)
                reserve_steps = steps[0]
            self.assertFalse(any("COUNT(" in statement.upper() for statement in statements))
            self.assertEqual(budget.reconcile()["reservations"], count + 1)
            work.append({"history_entries": count, "receipt_validation_vm_steps": validation_steps, "reserve_vm_steps": reserve_steps})
        for field in ("receipt_validation_vm_steps", "reserve_vm_steps"):
            self.assertLessEqual(work[1][field], work[0][field] * 1.5 + 100)
        print(json.dumps({"sqlite_logical_work": work, "timing_samples": 0, "native_calls": 0}))


if __name__ == "__main__":
    with patch.object(cpu, "NativeSlhDsa", side_effect=AssertionError("native forbidden")), \
         patch.object(cuda, "NativeSlhDsa", side_effect=AssertionError("native forbidden")), \
         patch.object(cpu.time, "perf_counter_ns", side_effect=AssertionError("performance timer forbidden")):
        unittest.main(verbosity=2)
