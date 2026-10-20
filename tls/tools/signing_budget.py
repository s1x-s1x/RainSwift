"""Durable per-key signing reservations for the shared experimental CA.

Every reservation consumes budget before the signing computation starts. Crashes
and failed signatures never refund it. All cooperating issuers must use this
same database; offline copies and restored databases need external reconciliation.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid


class BudgetError(RuntimeError):
    pass


# Stable identities are independent of caller spelling (CLI and CA use different
# capitalization). Unknown names fail closed rather than creating another quota.
_ALGORITHMS = {
    **{f"slh-dsa-{hash_name}-{parameter}": f"a15:slh:pid:{pid}"
       for hash_name, parameter, pid in (
           ("sm3", "128s", 1), ("sm3", "128f", 2), ("sm3", "128-24", 3),
           ("sha2", "128s", 101), ("sha2", "128f", 102),
           ("sha2", "128-24", 103), ("sm3", "toy", 201))},
    "ml-dsa-44": "oid:2.16.840.1.101.3.4.3.17",
}

# These guards make accidental row removal/rewriting fail immediately. Their
# definitions are checked on every operation; opening a ledger also performs a
# full reconciliation. They do not protect against an adversary replacing a
# whole consistent database snapshot (external anti-rollback is still needed).
_GUARDS = {
    "budget_reservation_no_delete": "CREATE TRIGGER budget_reservation_no_delete BEFORE DELETE ON reservations BEGIN SELECT RAISE(ABORT,'reservations are append-only'); END",
    "budget_reservation_identity": "CREATE TRIGGER budget_reservation_identity BEFORE UPDATE OF receipt,key_id,ordinal_text,message_sha256,reserved_utc,operation_id,case_identity ON reservations BEGIN SELECT RAISE(ABORT,'reservation identity is immutable'); END",
    "budget_reservation_finish": "CREATE TRIGGER budget_reservation_finish BEFORE UPDATE OF status,signature_sha256,finished_utc ON reservations WHEN OLD.status!='reserved' OR NEW.status NOT IN ('committed','failed') OR NEW.finished_utc IS NULL OR (NEW.status='committed' AND (NEW.signature_sha256 IS NULL OR length(NEW.signature_sha256)!=64 OR NEW.signature_sha256 GLOB '*[^0-9a-f]*')) OR (NEW.status='failed' AND NEW.signature_sha256 IS NOT NULL) BEGIN SELECT RAISE(ABORT,'invalid reservation finalization'); END",
    "budget_reservation_insert": "CREATE TRIGGER budget_reservation_insert BEFORE INSERT ON reservations WHEN NEW.status!='reserved' OR NEW.signature_sha256 IS NOT NULL OR NEW.finished_utc IS NOT NULL OR (NEW.operation_id IS NULL)!=(NEW.case_identity IS NULL) OR NOT EXISTS(SELECT 1 FROM keys k JOIN accounting a ON a.key_id=k.key_id WHERE k.key_id=NEW.key_id AND k.used_text=NEW.ordinal_text AND a.used_text=NEW.ordinal_text AND a.last_receipt=NEW.receipt) BEGIN SELECT RAISE(ABORT,'reservation charge is inconsistent'); END",
    "budget_key_identity": "CREATE TRIGGER budget_key_identity BEFORE UPDATE OF key_id,algorithm,public_key,limit_text,created_utc ON keys BEGIN SELECT RAISE(ABORT,'key identity and limit are immutable'); END",
    "budget_key_no_delete": "CREATE TRIGGER budget_key_no_delete BEFORE DELETE ON keys BEGIN SELECT RAISE(ABORT,'charged keys are append-only'); END",
    "budget_accounting_no_delete": "CREATE TRIGGER budget_accounting_no_delete BEFORE DELETE ON accounting BEGIN SELECT RAISE(ABORT,'accounting is append-only'); END",
    "budget_key_charge": "CREATE TRIGGER budget_key_charge BEFORE UPDATE OF used_text ON keys WHEN NEW.used_text!=budget_next_ordinal(OLD.used_text) BEGIN SELECT RAISE(ABORT,'key charges must advance by one'); END",
    "budget_accounting_charge": "CREATE TRIGGER budget_accounting_charge BEFORE UPDATE ON accounting WHEN NEW.key_id!=OLD.key_id OR NEW.used_text!=budget_next_ordinal(OLD.used_text) OR NEW.last_receipt IS NULL OR EXISTS(SELECT 1 FROM reservations WHERE receipt=NEW.last_receipt) OR NOT EXISTS(SELECT 1 FROM keys WHERE key_id=NEW.key_id AND used_text=NEW.used_text) BEGIN SELECT RAISE(ABORT,'accounting charges must advance consistently'); END",
}


def canonical_algorithm(algorithm):
    if not isinstance(algorithm, str) or algorithm.lower() not in _ALGORITHMS:
        raise ValueError("unsupported signing-budget algorithm")
    return algorithm.lower()


class SigningBudget:
    def __init__(self, database):
        self.path = Path(database).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS keys(
                  key_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL,
                  public_key BLOB NOT NULL, limit_text TEXT NOT NULL,
                  used_text TEXT NOT NULL, created_utc TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reservations(
                  receipt TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES keys(key_id),
                  ordinal_text TEXT NOT NULL, message_sha256 TEXT NOT NULL,
                  reserved_utc TEXT NOT NULL, status TEXT NOT NULL,
                  signature_sha256 TEXT, finished_utc TEXT,
                  UNIQUE(key_id, ordinal_text));
                CREATE TABLE IF NOT EXISTS ledger_metadata(
                  name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS identity_migrations(
                  legacy_key_id TEXT PRIMARY KEY, canonical_key_id TEXT NOT NULL,
                  legacy_algorithm TEXT NOT NULL, legacy_limit_text TEXT NOT NULL,
                  legacy_used_text TEXT NOT NULL, migrated_utc TEXT NOT NULL);
            """)
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT OR IGNORE INTO ledger_metadata VALUES('ledger_uuid',?)", (uuid.uuid4().hex,))
                self._migrate_identity(db)
                self._migrate_accounting(db)
                self._check_guards(db)
                self._reconcile(db)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            self.ledger_uuid = db.execute("SELECT value FROM ledger_metadata WHERE name='ledger_uuid'").fetchone()[0]
            if len(self.ledger_uuid) != 32 or any(c not in "0123456789abcdef" for c in self.ledger_uuid):
                raise BudgetError("ledger UUID is malformed")

    def _migrate_identity(self, db):
        version = db.execute("SELECT value FROM ledger_metadata WHERE name='identity_schema'").fetchone()
        if version:
            if version[0] != "2":
                raise BudgetError("unsupported ledger identity schema")
            return
        groups = {}
        for row in db.execute("SELECT key_id,algorithm,public_key,limit_text,used_text,created_utc FROM keys").fetchall():
            old_id, algorithm, public, limit, used, created = row
            name = canonical_algorithm(algorithm)
            identifier = self.key_id(name, public)
            legacy_id = hashlib.sha256(algorithm.encode("ascii") + b"\0" + bytes(public)).hexdigest()
            if old_id not in (identifier, legacy_id):
                raise BudgetError("legacy key identity reconciliation failed")
            maximum = 1 << (24 if name.endswith("128-24") else 64)
            if not 0 < int(limit) <= maximum or int(used) < 0:
                raise BudgetError("legacy key allowance is invalid")
            actual = db.execute("SELECT COUNT(*) FROM reservations WHERE key_id=?", (old_id,)).fetchone()[0]
            if actual != int(used):
                raise BudgetError("legacy ledger count reconciliation failed")
            groups.setdefault(identifier, []).append(row)
        now = datetime.now(timezone.utc).isoformat()
        # Preserve every receipt/status/digest. Re-number the merged ordinals in
        # historical time order; never refund charges, including failed calls.
        for identifier, aliases in groups.items():
            name = canonical_algorithm(aliases[0][1])
            public = aliases[0][2]
            limit = min(int(row[3]) for row in aliases)
            used = sum(int(row[4]) for row in aliases)
            created = min(row[5] for row in aliases)
            receipts = []
            for row in aliases:
                receipts.extend(db.execute("SELECT receipt,reserved_utc FROM reservations WHERE key_id=?", (row[0],)).fetchall())
            db.execute("INSERT OR IGNORE INTO keys VALUES(?,?,?,?,?,?)", (identifier, name, public, str(limit), str(used), created))
            for ordinal, (receipt, _) in enumerate(sorted(receipts, key=lambda row: (row[1], row[0])), 1):
                # Negative temporary ordinals prevent collisions if a canonical
                # row already exists in the legacy database.
                db.execute("UPDATE reservations SET key_id=?,ordinal_text=? WHERE receipt=?", (identifier, str(-ordinal), receipt))
            for ordinal, (receipt, _) in enumerate(sorted(receipts, key=lambda row: (row[1], row[0])), 1):
                db.execute("UPDATE reservations SET ordinal_text=? WHERE receipt=?", (str(ordinal), receipt))
            for row in aliases:
                db.execute("INSERT INTO identity_migrations VALUES(?,?,?,?,?,?)", (row[0], identifier, row[1], row[3], row[4], now))
                if row[0] != identifier:
                    db.execute("DELETE FROM keys WHERE key_id=?", (row[0],))
            db.execute("UPDATE keys SET algorithm=?,limit_text=?,used_text=?,created_utc=? WHERE key_id=?", (name, str(limit), str(used), created, identifier))
        db.execute("INSERT INTO ledger_metadata VALUES('identity_schema','2')")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=60, isolation_level=None)
        # SQLite integers stop at 2^63-1; allowances and ordinals are exact
        # canonical decimal text. Raw connections lack this function and fail
        # closed if they try to alter the guarded counters.
        db.create_function("budget_next_ordinal", 1, lambda value: str(self._number(value) + 1), deterministic=True)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=60000")
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def _number(value, *, positive=False):
        if (not isinstance(value, str) or not value.isascii() or not value.isdecimal()
                or str(int(value)) != value or (positive and int(value) == 0)):
            raise BudgetError("ledger count/allowance is malformed")
        return int(value)

    def _migrate_accounting(self, db):
        version = db.execute("SELECT value FROM ledger_metadata WHERE name='accounting_schema'").fetchone()
        if version:
            if version[0] != "1":
                raise BudgetError("unsupported ledger accounting schema")
            return
        columns = {row[1] for row in db.execute("PRAGMA table_info(reservations)")}
        for name in ("operation_id", "case_identity"):
            if name not in columns:
                db.execute("ALTER TABLE reservations ADD COLUMN " + name + " TEXT")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS reservation_operation ON reservations(operation_id) WHERE operation_id IS NOT NULL")
        db.execute("CREATE INDEX reservation_history_order ON reservations(key_id,length(ordinal_text),ordinal_text)")
        db.execute("CREATE TABLE accounting(key_id TEXT PRIMARY KEY REFERENCES keys(key_id),used_text TEXT NOT NULL,last_receipt TEXT)")
        for identifier, used in db.execute("SELECT key_id,used_text FROM keys").fetchall():
            last = db.execute("SELECT receipt FROM reservations WHERE key_id=? AND ordinal_text=?", (identifier, used)).fetchone()
            db.execute("INSERT INTO accounting VALUES(?,?,?)", (identifier, used, last[0] if last else None))
        # Validate the complete old history before installing append-only guards.
        self._reconcile(db)
        for statement in _GUARDS.values():
            db.execute(statement)
        db.execute("INSERT INTO ledger_metadata VALUES('accounting_schema','1')")

    @staticmethod
    def _check_guards(db):
        definitions = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'"))
        if any(definitions.get(name) != statement for name, statement in _GUARDS.items()):
            raise BudgetError("ledger integrity guard differs or is missing; full reconciliation required")
        index = db.execute("SELECT sql FROM sqlite_master WHERE name='reservation_operation' AND type='index'").fetchone()
        if index is None or index[0] != "CREATE UNIQUE INDEX reservation_operation ON reservations(operation_id) WHERE operation_id IS NOT NULL":
            raise BudgetError("ledger operation uniqueness index differs or is missing")
        ordered = db.execute("SELECT sql FROM sqlite_master WHERE name='reservation_history_order' AND type='index'").fetchone()
        if ordered is None or ordered[0] != "CREATE INDEX reservation_history_order ON reservations(key_id,length(ordinal_text),ordinal_text)":
            raise BudgetError("ledger reconciliation index differs or is missing")

    def _check_charge(self, db, identifier):
        row = db.execute("SELECT k.used_text,a.used_text,a.last_receipt,r.ordinal_text FROM keys k "
                         "JOIN accounting a ON a.key_id=k.key_id LEFT JOIN reservations r ON r.receipt=a.last_receipt AND r.key_id=k.key_id "
                         "WHERE k.key_id=?", (identifier,)).fetchone()
        if row is None:
            raise BudgetError("ledger accounting row is missing")
        used = self._number(row[0])
        if row[1] != row[0] or (used == 0 and row[2:] != (None, None)) or (used > 0 and row[3] != row[0]):
            raise BudgetError("ledger count reconciliation failed")
        return used

    def _reconcile(self, db):
        """One indexed streaming pass, not one history scan per receipt."""
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise BudgetError("ledger foreign key reconciliation failed")
        keys = db.execute("SELECT key_id,algorithm,public_key,limit_text,used_text FROM keys").fetchall()
        charged = 0
        for identifier, algorithm, public, limit, used_text in keys:
            name = canonical_algorithm(algorithm)
            if algorithm != name or identifier != self.key_id(name, public) or not public:
                raise BudgetError("ledger canonical key identity reconciliation failed")
            maximum = 1 << (24 if name.endswith("128-24") else 64)
            if self._number(limit, positive=True) > maximum:
                raise BudgetError("ledger key allowance is invalid")
            used = self._number(used_text)
            count, last = 0, None
            for receipt, ordinal, status, digest, finished, operation, case, message, reserved in db.execute(
                    "SELECT receipt,ordinal_text,status,signature_sha256,finished_utc,operation_id,case_identity,message_sha256,reserved_utc "
                    "FROM reservations WHERE key_id=? ORDER BY length(ordinal_text),ordinal_text", (identifier,)):
                count += 1
                if self._number(ordinal, positive=True) != count:
                    raise BudgetError("ledger ordinal reconciliation failed")
                if (not isinstance(receipt, str) or not receipt or not isinstance(reserved, str) or not reserved or
                        not isinstance(message, str) or len(message) != 64 or any(c not in "0123456789abcdef" for c in message) or
                        status not in ("reserved", "committed", "failed") or
                        (status == "reserved" and (digest is not None or finished is not None)) or
                        (status == "failed" and (digest is not None or finished is None)) or
                        (status == "committed" and (not isinstance(digest, str) or len(digest) != 64 or
                                                   any(c not in "0123456789abcdef" for c in digest) or finished is None)) or
                        ((operation is None) != (case is None)) or
                        (operation is not None and (not operation or not case))):
                    raise BudgetError("ledger reservation state reconciliation failed")
                last = receipt
            if used != count:
                raise BudgetError("ledger count reconciliation failed")
            accounting = db.execute("SELECT used_text,last_receipt FROM accounting WHERE key_id=?", (identifier,)).fetchone()
            if accounting != (used_text, last):
                raise BudgetError("ledger accounting reconciliation failed")
            charged += count
        return {"keys": len(keys), "reservations": charged, "reconciled": True}

    def reconcile(self):
        """Explicit full-history audit; call at campaign boundaries, not per sample."""
        with self.connection() as db:
            db.execute("BEGIN")
            self._check_uuid(db)
            result = self._reconcile(db)
            return {"ledger_uuid": self.ledger_uuid, **result}

    @staticmethod
    def key_id(algorithm, public_key):
        name = canonical_algorithm(algorithm)
        return hashlib.sha256(_ALGORITHMS[name].encode("ascii") + b"\0" + bytes(public_key)).hexdigest()

    def reserve(self, algorithm, public_key, message, *, limit=None, operation_id=None, case_identity=None):
        algorithm = canonical_algorithm(algorithm)
        public_key = bytes(public_key)
        if not public_key:
            raise ValueError("public key must have content")
        maximum = 1 << (24 if algorithm.lower().endswith("128-24") else 64)
        limit = maximum if limit is None else limit
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 < limit <= maximum:
            raise ValueError("budget limit must be positive and within the parameter allowance")
        if ((operation_id is None) != (case_identity is None) or
                (operation_id is not None and (not isinstance(operation_id, str) or not operation_id or
                    not isinstance(case_identity, str) or not case_identity))):
            raise ValueError("operation_id and case_identity must be nonempty strings supplied together")
        identifier, receipt = self.key_id(algorithm, public_key), uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._check_uuid(db)
                db.execute("INSERT OR IGNORE INTO keys VALUES(?,?,?,?,?,?)",
                           (identifier, algorithm, public_key, str(limit), "0", now))
                db.execute("INSERT OR IGNORE INTO accounting VALUES(?,?,NULL)", (identifier, "0"))
                row = db.execute("SELECT algorithm,public_key,limit_text,used_text FROM keys WHERE key_id=?",
                                 (identifier,)).fetchone()
                if row[:2] != (algorithm, public_key) or self._number(row[2], positive=True) != limit:
                    raise BudgetError("registered key or budget limit differs; explicit migration required")
                used = self._check_charge(db, identifier)
                if used >= limit:
                    raise BudgetError("signing budget exhausted; rotate the key")
                if operation_id is not None and db.execute("SELECT 1 FROM reservations WHERE operation_id=?", (operation_id,)).fetchone():
                    raise BudgetError("signing operation was already charged")
                db.execute("UPDATE keys SET used_text=? WHERE key_id=?", (str(used + 1), identifier))
                db.execute("UPDATE accounting SET used_text=?,last_receipt=? WHERE key_id=?", (str(used + 1), receipt, identifier))
                db.execute("INSERT INTO reservations(receipt,key_id,ordinal_text,message_sha256,reserved_utc,status,signature_sha256,finished_utc,operation_id,case_identity) VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (receipt, identifier, str(used + 1), hashlib.sha256(bytes(message)).hexdigest(),
                            now, "reserved", None, None, operation_id, case_identity))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return receipt

    def operation(self, operation_id):
        """Return one persisted operation by identity, or ``None``.

        Used by an interrupted issuer to reconcile before retrying: a charge that
        already exists must never be reissued under a fresh receipt.
        """
        if not isinstance(operation_id, str) or not operation_id:
            raise ValueError("operation_id must be a nonempty string")
        with self.connection() as db:
            db.execute("BEGIN")
            self._check_uuid(db)
            row = db.execute("SELECT receipt,key_id,algorithm,public_key,message_sha256,status,"
                             "signature_sha256,case_identity FROM reservations r "
                             "JOIN keys k USING(key_id) WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None:
                return None
            return {"receipt": row[0], "key_id": row[1], "algorithm": row[2],
                    "public_key_sha256": hashlib.sha256(row[3]).hexdigest(),
                    "message_sha256": row[4], "status": row[5],
                    "signature_sha256": row[6], "case_identity": row[7]}

    def validate_receipt(self, receipt, *, algorithm=None, public_key=None,
                         message=None, message_sha256=None, signature=None,
                         signature_sha256=None, statuses=("committed",), operation_id=None, case_identity=None):
        """Reconcile one preserved operation against this live ledger.

        Digest arguments allow benchmark JSONL to audit RNG validation without
        publishing the validation key or signature. This does not make restored
        or copied ledgers globally monotonic; external anti-rollback is separate.
        """
        with self.connection() as db:
            db.execute("BEGIN")
            self._check_uuid(db)
            row = db.execute("SELECT r.key_id,k.algorithm,k.public_key,r.message_sha256,r.status,"
                             "r.signature_sha256,r.operation_id,r.case_identity "
                             "FROM reservations r JOIN keys k ON k.key_id=r.key_id WHERE receipt=?", (receipt,)).fetchone()
            if row is None or row[4] not in statuses:
                raise BudgetError("receipt missing or status differs from preserved operation")
            self._check_charge(db, row[0])
            if row[0] != self.key_id(row[1], row[2]):
                raise BudgetError("receipt canonical key identity differs")
            if algorithm is not None and row[1] != canonical_algorithm(algorithm):
                raise BudgetError("receipt algorithm differs")
            if public_key is not None and row[2] != bytes(public_key):
                raise BudgetError("receipt public key differs")
            message_digest = hashlib.sha256(bytes(message)).hexdigest() if message is not None else message_sha256
            signature_digest = hashlib.sha256(bytes(signature)).hexdigest() if signature is not None else signature_sha256
            if message_digest is not None and row[3] != message_digest:
                raise BudgetError("receipt message digest differs")
            if signature_digest is not None and row[5] != signature_digest:
                raise BudgetError("receipt signature digest differs")
            if operation_id is not None and row[6] != operation_id:
                raise BudgetError("receipt operation identity differs")
            if case_identity is not None and row[7] != case_identity:
                raise BudgetError("receipt case identity differs")
            if row[4] == "committed" and (not isinstance(row[5], str) or len(row[5]) != 64 or
                                          any(c not in "0123456789abcdef" for c in row[5])):
                raise BudgetError("committed receipt lacks signature digest")
            result = {"ledger_uuid": self.ledger_uuid, "receipt": receipt, "key_id": row[0],
                    "algorithm": row[1], "public_key_sha256": hashlib.sha256(row[2]).hexdigest(),
                    "message_sha256": row[3], "status": row[4], "signature_sha256": row[5]}
            # Unbound pre-upgrade/CA receipts remain readable. Performance
            # workers require the additional fields for all new operations.
            if row[6] is not None:
                result["operation_id"], result["case_identity"] = row[6:8]
            return result

    def _check_uuid(self, db):
        row = db.execute("SELECT value FROM ledger_metadata WHERE name='ledger_uuid'").fetchone()
        if row is None or row[0] != self.ledger_uuid:
            raise BudgetError("live ledger UUID changed")
        if dict(db.execute("SELECT name,value FROM ledger_metadata WHERE name IN ('identity_schema','accounting_schema')")) != {
                "identity_schema": "2", "accounting_schema": "1"}:
            raise BudgetError("live ledger schema changed")
        self._check_guards(db)

    def finish(self, receipt, signature=None):
        status = "committed" if signature is not None else "failed"
        digest = hashlib.sha256(bytes(signature)).hexdigest() if signature is not None else None
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._check_uuid(db)
                key = db.execute("SELECT key_id FROM reservations WHERE receipt=?", (receipt,)).fetchone()
                if key is None:
                    raise BudgetError("reservation missing or already finalized")
                self._check_charge(db, key[0])
                changed = db.execute("UPDATE reservations SET status=?,signature_sha256=?,finished_utc=? "
                                     "WHERE receipt=? AND status='reserved'",
                                     (status, digest, datetime.now(timezone.utc).isoformat(), receipt)).rowcount
                if changed != 1:
                    raise BudgetError("reservation missing or already finalized")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def callback(self, algorithm, public_key, message):
        """Fixture-builder hook; the charged reservation remains auditable."""
        return self.reserve(algorithm, public_key, message)

    def status(self):
        with self.connection() as db:
            keys = db.execute("SELECT key_id,algorithm,limit_text,used_text FROM keys ORDER BY key_id").fetchall()
            result = []
            for key_id, algorithm, limit, used in keys:
                states = dict(db.execute("SELECT status,COUNT(*) FROM reservations WHERE key_id=? GROUP BY status", (key_id,)))
                result.append({"key_id": key_id, "algorithm": algorithm, "limit": int(limit),
                               "used": int(used), "remaining": int(limit) - int(used), "states": states,
                               "count_reconciled": sum(states.values()) == int(used)})
            return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--reconcile", action="store_true", help="audit all history before printing status")
    args = parser.parse_args()
    ledger = SigningBudget(args.database)
    print(json.dumps({"reconciliation": ledger.reconcile(), "status": ledger.status()} if args.reconcile else ledger.status(), indent=2))
