"""
clinical/tests/test_w129c_fastq_session.py
──────────────────────────────────────────

w129c: the two FASTQ ingestion operations stop taking a raw `org_id` and start
taking the caller's `Session`, and the WRITE is gated on the internal `System`
role.

WHAT WAS WRONG. At `8185385` these two were the only tenant-scoped operations in
`clinical/data_access.py` that named their own organisation:

    find_fastq_set_by_checksums(self, org_id, r1_checksum, r2_checksum)   @ :6110
    record_fastq_set(self, org_id, sample_id, ...)                        @ :6132

(Both line numbers verified at `8185385`. The numbers 5945/5967 carried in the
w129 commit message body match NO commit in the stack and are corrected here and
in this branch's commit message; held history cannot be rewritten.)

`Session`'s own docstring states the architectural invariant these two broke:
"`org_id` is the organisation scope for every call that takes this object -- it
is read from here and never from a caller argument, which is what makes the
isolation structural rather than remembered." A caller-supplied org_id is a
CLAIM. Every other tenant-scoped operation in the file derives it from an
authenticated principal.

THE SESSION COMES FROM THE CALLER, NOT FROM THE SCANNER. `FastqScanner.scan_org`
now takes a `Session` instead of an `org_id`. It deliberately does NOT mint one:
`_create_system_session` is an authentication bypass whose invariant is about
WHERE, not how many -- every call site must sit in a background worker class in
`geper/api/`. A scanner-minted session would be a fifth site in a non-worker
module and
`test_identity.py::test_create_system_session_call_sites_are_the_four_pinned_worker_sites`
would fail. THAT GUARD IS THE TEST FOR "no new authentication-bypass call site";
this file deliberately does not write a second one.

WHY THE READ CHANGED TOO, when the ruling left the read path alone by default.
The read keeps its existing AUTHORISATION posture exactly: no role gate, still
`auditable=False` with its original reason. What changed is only that its
organisation stops being a caller argument -- because the probe is an existence
oracle over another tenant's checksum space, and because leaving it as the one
tenant-scoped read in the file that names its own org would leave the invariant
quoted above with a documented exception. Stated rather than assumed.

THE FOUR CELLS, the shape the rest of w129 uses: right principal + right org
allowed; wrong principal refused; right principal + WRONG org refused and
INDISTINGUISHABLE from unknown; and the positive twin that the whole thing still
works.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import uuid
from datetime import date, datetime, timezone

import pytest

from clinical.data_access import (
    AuthorizationError,
    BcryptHasher,
    DataAccess,
    NotFoundError,
    SystemClock,
)

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = __import__("pathlib").Path(__file__).parent.parent / "schema.sql"

NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def conn():
    psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")
    if not DSN:
        pytest.skip("CLINICAL_TEST_DSN not set")
    connection = psycopg.connect(DSN, autocommit=False, connect_timeout=10)
    with connection.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        for role in ("clinical_app", "clinical_retention"):
            cur.execute(f"DO $$ BEGIN CREATE ROLE {role}; EXCEPTION WHEN duplicate_object THEN NULL; END $$;")
        cur.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture()
def dao(conn):
    return DataAccess(conn, clock=SystemClock(), password_hasher=BcryptHasher(rounds=4))


def _seed(dao, conn, label: str) -> dict:
    """One organisation carrying one sample, one human session that holds every
    HUMAN role, and one System session. The human account deliberately holds
    Administrator, Interpreter, Orderer and Lab technician and NOT System: the
    refusal below must be about the internal principal, not about an
    under-privileged account."""
    org_id = dao.create_organisation(f"W129c Org {label}")
    admin_id = dao.create_user(org_id, f"admin@w129c-{label}.test", "password")
    with conn.cursor() as cur:
        for role in ("Administrator", "Interpreter", "Orderer", "Lab technician"):
            cur.execute(
                "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (admin_id, org_id, role, admin_id, NOW),
            )
    conn.commit()
    human = dao.login(f"admin@w129c-{label}.test", org_id, "password")

    test_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tests (test_id, org_id, name, assembly, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (test_id, org_id, "Panel", "GRCh38", "active", NOW),
        )
    conn.commit()
    patient_id = dao.create_patient(human, f"Patient {label}", date(1990, 1, 1), "M")
    consent_id = dao.record_consent(human, patient_id, "testing")
    order_id = dao.create_order(
        human,
        patient_id=patient_id,
        test_id=test_id,
        consent_id=consent_id,
        required_scope="testing",
        priority="routine",
    )
    sample_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO samples (sample_id, order_id, org_id, type, collected_at, collected_by, qc_status) "
            "VALUES (%s, %s, %s, 'blood', %s, %s, 'passed')",
            (sample_id, order_id, org_id, NOW, admin_id),
        )
    conn.commit()

    system = dao._create_system_session(org_id)
    conn.commit()
    return {
        "org_id": org_id,
        "sample_id": sample_id,
        "human": human,
        "system": system,
        "human_user_id": admin_id,
    }


@pytest.fixture()
def orgs(dao, conn):
    return {"a": _seed(dao, conn, "A"), "b": _seed(dao, conn, "B")}


def _record(dao, session, sample_id, r1="/inc/a_R1_001.fastq.gz", r2="/inc/a_R2_001.fastq.gz", n="1"):
    return dao.record_fastq_set(
        session,
        sample_id=sample_id,
        r1_path=r1,
        r2_path=r2,
        r1_checksum=f"r1sum{n}",
        r2_checksum=f"r2sum{n}",
        detected_at=NOW,
    )


# ── cell 1: the internal principal is allowed ───────────────────────────────


class TestTheSystemPrincipalCanRecord:
    def test_a_system_session_records_a_set_and_the_probe_finds_it(self, dao, conn, orgs):
        """Right principal, right organisation. Read back THROUGH THE METHOD --
        a `db_session.execute()` here would pass while the method is broken
        (Phase 5d)."""
        a = orgs["a"]
        fastq_set_id = _record(dao, a["system"], a["sample_id"])
        conn.commit()

        assert isinstance(fastq_set_id, uuid.UUID)
        assert dao.find_fastq_set_by_checksums(a["system"], "r1sum1", "r2sum1") == fastq_set_id


# ── cell 2: a non-internal principal is refused ─────────────────────────────


class TestANonInternalPrincipalIsRefused:
    def test_a_human_session_cannot_record_a_fastq_set(self, dao, conn, orgs):
        """The account holds Administrator, Interpreter, Orderer AND Lab
        technician. It is refused anyway, because detection is the platform
        acting, not a member of laboratory staff -- and w129 forbids treating an
        internal principal as a normal human staff role."""
        a = orgs["a"]
        with pytest.raises(AuthorizationError) as excinfo:
            _record(dao, a["human"], a["sample_id"])
        conn.commit()
        assert "System" in str(excinfo.value)

    def test_the_refused_write_wrote_nothing(self, dao, conn, orgs):
        """THE POSITIVE TWIN OF THE REFUSAL (Rule 4): an absence assertion that
        the broken state also satisfies proves nothing, so the same probe is run
        twice -- once after the refusal, where it must find NOTHING, and once
        after an allowed write of the same checksums, where it must find the
        row. Both through the method."""
        a = orgs["a"]
        with pytest.raises(AuthorizationError):
            _record(dao, a["human"], a["sample_id"])
        conn.commit()
        assert dao.find_fastq_set_by_checksums(a["system"], "r1sum1", "r2sum1") is None

        fastq_set_id = _record(dao, a["system"], a["sample_id"])
        conn.commit()
        assert dao.find_fastq_set_by_checksums(a["system"], "r1sum1", "r2sum1") == fastq_set_id


# ── cell 3: the session, not the caller, names the organisation ─────────────


class TestTheOrganisationComesFromTheSession:
    def test_another_orgs_system_session_cannot_reach_this_orgs_sample(self, dao, conn, orgs):
        """RIGHT PRINCIPAL, WRONG ORGANISATION. B's System session is a real
        internal principal -- it passes the role gate -- and it still cannot
        record against A's sample, because the org the sample is resolved
        against is read off the session. And it is INDISTINGUISHABLE from a
        sample that exists nowhere: the two refusals are compared to each
        other, not to a literal."""
        a, b = orgs["a"], orgs["b"]
        nowhere = uuid.uuid4()

        with pytest.raises(NotFoundError) as cross_org:
            _record(dao, b["system"], a["sample_id"], n="x")
        conn.commit()
        with pytest.raises(NotFoundError) as unknown:
            _record(dao, b["system"], nowhere, n="y")
        conn.commit()

        assert str(cross_org.value).replace(str(a["sample_id"]), "") == str(unknown.value).replace(str(nowhere), "")

        # And B's own sample DOES resolve for B -- so the two refusals above are
        # about the organisation, not about B's session being inert.
        assert isinstance(_record(dao, b["system"], b["sample_id"], n="z"), uuid.UUID)

    def test_the_probe_is_scoped_to_the_session_and_the_audit_actor_is_the_session_user(self, dao, conn, orgs):
        """THE 'IS THE SESSION ACTUALLY CONSULTED' TEST. Passing a session and
        seeing success proves nothing. So the session's IDENTITY is made
        observable three ways over one single write:

          * the probe finds the row under A's session and NOT under B's -- the
            read's organisation came off the session;
          * the audit row's user_id is A's SYSTEM user, not null and not the
            human who happens to be logged in -- before w129c this column was
            null for every detection;
          * the audit row's actor_role is 'System'.
        """
        a, b = orgs["a"], orgs["b"]
        fastq_set_id = _record(dao, a["system"], a["sample_id"])
        conn.commit()

        assert dao.find_fastq_set_by_checksums(a["system"], "r1sum1", "r2sum1") == fastq_set_id
        assert dao.find_fastq_set_by_checksums(b["system"], "r1sum1", "r2sum1") is None

        with conn.cursor() as cur:
            cur.execute(
                "SELECT org_id, user_id, actor_role FROM audit_log "
                "WHERE action = 'fastq_set_detected' AND resource_id = %s",
                (str(fastq_set_id),),
            )
            rows = cur.fetchall()
        assert len(rows) == 1, rows
        org_id, user_id, actor_role = rows[0]
        assert org_id == a["org_id"]
        assert user_id == a["system"].user_id
        assert user_id != a["human_user_id"]
        assert actor_role == "System"


# ── cell 4: the scanner threads the caller's session through, unchanged ─────


def _write_gz(path, payload: bytes) -> str:
    with gzip.open(path, "wb") as fh:
        fh.write(payload)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_pair(directory, sample_id, payload=b"@r\nACGT\n+\nIIII\n", tag="S1_L001"):
    r1 = directory / f"{sample_id}_{tag}_R1_001.fastq.gz"
    r2 = directory / f"{sample_id}_{tag}_R2_001.fastq.gz"
    return r1, r2, _write_gz(r1, payload), _write_gz(r2, payload + b"T")


class TestTheScannerRunsOnTheSessionItIsGiven:
    def test_scan_org_scans_the_sessions_organisation_and_no_other(self, dao, conn, orgs, tmp_path):
        """END TO END, and the integration half of "the session is consulted":
        BOTH organisations have an ingestible pair on disk. The scan is handed
        A's System session and nothing else -- no org_id argument exists any
        more -- so which directory is read, which sample resolves and which
        organisation's row is written all follow from the session alone."""
        from clinical.ingestion import FastqScanner

        a, b = orgs["a"], orgs["b"]
        root = tmp_path / "fastq_root"
        for org in (a, b):
            directory = root / str(org["org_id"]) / "incoming"
            directory.mkdir(parents=True, exist_ok=True)
            _write_pair(directory, org["sample_id"])

        scanner = FastqScanner(dao, fastq_root=root, clock=SystemClock())
        first = scanner.scan_org(a["system"])
        second = scanner.scan_org(a["system"])
        conn.commit()

        assert first.ingested == []
        assert len(second.ingested) == 1
        assert second.org_id == a["org_id"]
        ingested = second.ingested[0]
        assert ingested.sample_id == str(a["sample_id"])

        # Through the method, and B's pair really was there and really was
        # ingestible -- proved by scanning B afterwards.
        with conn.cursor() as cur:
            cur.execute("SELECT org_id FROM fastq_sets")
            assert [r[0] for r in cur.fetchall()] == [a["org_id"]]

        b_scanner = FastqScanner(dao, fastq_root=root, clock=SystemClock())
        b_scanner.scan_org(b["system"])
        b_second = b_scanner.scan_org(b["system"])
        conn.commit()
        assert len(b_second.ingested) == 1
        assert b_second.org_id == b["org_id"]

    def test_a_scan_driven_by_a_non_internal_session_ingests_nothing(self, dao, conn, orgs, tmp_path):
        """The role gate is on the WRITE, so it is reached through the scanner
        too. A human session with every laboratory role still records nothing;
        the AuthorizationError is not swallowed into a rejected outcome, because
        a refusal that looks like 'file was no good' would be a silent
        authorisation failure."""
        from clinical.ingestion import FastqScanner

        a = orgs["a"]
        directory = root_dir = tmp_path / "fastq_root" / str(a["org_id"]) / "incoming"
        directory.mkdir(parents=True, exist_ok=True)
        _write_pair(directory, a["sample_id"])

        scanner = FastqScanner(dao, fastq_root=tmp_path / "fastq_root", clock=SystemClock())
        scanner.scan_org(a["human"])
        with pytest.raises(AuthorizationError):
            scanner.scan_org(a["human"])
        conn.commit()

        assert root_dir.exists()
        assert dao.find_fastq_set_by_checksums(a["system"], *_checksums(directory, a["sample_id"])) is None


def _checksums(directory, sample_id, tag="S1_L001"):
    r1 = directory / f"{sample_id}_{tag}_R1_001.fastq.gz"
    r2 = directory / f"{sample_id}_{tag}_R2_001.fastq.gz"
    return (
        hashlib.sha256(r1.read_bytes()).hexdigest(),
        hashlib.sha256(r2.read_bytes()).hexdigest(),
    )
