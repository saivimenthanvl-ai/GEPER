"""
clinical/tests/test_w141_system_role_is_not_assignable.py
─────────────────────────────────────────────────────────
"System" IS IN `ROLES`, AND `assign_role` VALIDATES AGAINST `ROLES`.

At f89766a that meant an Administrator could grant a human being the internal
system principal — the one `_require_role(session, "System")` gates the fastq
detection write path on — and the grant was refused by nothing. The convention
that no human holds "System" was written down in four places and enforced in
none of them:

  * `login()` refuses `is_system_account = true`, so the SYSTEM ACCOUNT cannot
    authenticate interactively. That is a different column from the role.
  * `_create_system_session` writes the "System" `role_assignments` row with
    raw SQL, next to the `is_system_account = true` user it just made, and its
    four call sites are pinned by name in test_identity.py. That pins where
    the row is written, not who may also write one.
  * `_require_role` reads `role_assignments` ONLY. It never consults
    `is_system_account`.

So: grant "System" to an ordinary human; that human's account is not a system
account, so they log in normally; their session now passes the System gate.

NO TENANT BOUNDARY IS CROSSED. `assign_role` binds `session.org_id` into the
INSERT and the composite foreign key on `(user_id, org_id)` enforces it
regardless. This is privilege separation inside ONE organisation, which is why
it is a defect and not a leak.

WHAT THIS FILE ASSERTS, AND WHAT IT REFUSES TO ASSERT. The refusal itself
(row 1) is the cheap half: a test that only asserted "assign_role raises" would
pass against an implementation that raised for the wrong reason, and it proves
nothing about the capability the role confers. Row 2 is the load-bearing one —
it takes the human session to the actual System-gated WRITE and asserts the
write is refused. That is the assertion the broken version fails, because in
the broken version the row is written.

Rows 3, 4 and 5 are the positive twins Standing Rule 4 requires: a fix that
refused everything, or that broke the legitimate system principal, or that
answered the wrong refusal to an under-privileged caller, passes rows 1 and 2
and fails these.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

DSN = os.getenv("CLINICAL_TEST_DSN")

PASSWORD = "correct horse battery staple"
APP_PASSWORD = "test-app-password"
RETENTION_PASSWORD = "test-retention-password"
NOW = dt.datetime(2026, 9, 18, 9, 0, tzinfo=dt.timezone.utc)


# ─── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def clinical_dsn():
    psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")
    if not DSN:
        pytest.skip("CLINICAL_TEST_DSN not set")

    from clinical.bootstrap import apply_schema, ensure_roles

    connection = psycopg.connect(DSN, autocommit=False, connect_timeout=10)
    with connection.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    ensure_roles(connection, app_password=APP_PASSWORD, retention_password=RETENTION_PASSWORD)
    apply_schema(connection)
    connection.commit()
    connection.close()
    return DSN


@pytest.fixture()
def conn(clinical_dsn):
    import psycopg

    connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
    yield connection
    connection.close()


@pytest.fixture()
def dao(conn):
    from clinical.data_access import BcryptHasher, DataAccess

    return DataAccess(conn, password_hasher=BcryptHasher(rounds=4))


@pytest.fixture()
def world(dao, conn):
    """
    ONE organisation, an Administrator, a SECOND ordinary human to be the
    grant's target, and a sample the System gate protects.

    The target is a second account and not the Administrator itself because
    "an Administrator escalated themselves" and "an Administrator escalated
    somebody else" are different acts, and the second is the one the role
    table exists to prevent.
    """
    org_id = dao.create_organisation("W141 Org")
    admin_id = dao.create_user(org_id, "admin@w141.test", PASSWORD)
    target_id = dao.create_user(org_id, "human@w141.test", PASSWORD)
    with conn.cursor() as cur:
        for role in ("Administrator", "Interpreter", "Orderer", "Lab technician"):
            cur.execute(
                "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (admin_id, org_id, role, admin_id, NOW),
            )
        # The target holds a real, ordinary role, so a refusal below cannot be
        # explained by "that account can do nothing at all".
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, %s, %s, %s)",
            (target_id, org_id, "Orderer", admin_id, NOW),
        )
    conn.commit()

    admin = dao.login("admin@w141.test", org_id, PASSWORD)
    human = dao.login("human@w141.test", org_id, PASSWORD)

    test_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tests (test_id, org_id, name, assembly, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (test_id, org_id, "Panel", "GRCh38", "active", NOW),
        )
    conn.commit()
    patient_id = dao.create_patient(admin, "Patient W141", dt.date(1990, 1, 1), "M")
    consent_id = dao.record_consent(admin, patient_id, "testing")
    order_id = dao.create_order(
        admin,
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

    return {
        "org_id": org_id,
        "admin": admin,
        "admin_id": admin_id,
        "human": human,
        "target_id": target_id,
        "sample_id": sample_id,
    }


def _record(dao, session, sample_id, n="1"):
    return dao.record_fastq_set(
        session,
        sample_id=sample_id,
        r1_path=f"/inc/w141_{n}_R1_001.fastq.gz",
        r2_path=f"/inc/w141_{n}_R2_001.fastq.gz",
        r1_checksum=f"r1sum{n}",
        r2_checksum=f"r2sum{n}",
        detected_at=NOW,
    )


# ─── the refusal ─────────────────────────────────────────────────────────────


class TestTheSystemPrincipalCannotBeGrantedToAPerson:
    def test_an_administrator_cannot_assign_System(self, dao, conn, world):
        """
        Row 1. THE CHEAP HALF, and it is here for the error text as much as
        the exception: a ValueError and not an AuthorizationError, because an
        AuthorizationError says "you may not do this", which invites the reader
        to go and find a principal who may. There is none.

        Catches: the f89766a version, in which the call returns an assignment
        id. VACUOUS AGAINST: an implementation that refuses every role — see
        row 3.
        """
        with pytest.raises(ValueError) as caught:
            dao.assign_role(world["admin"], world["target_id"], "System")
        conn.rollback()
        message = str(caught.value)
        assert "System" in message, message
        assert "cannot be granted to a person" in message, message

    def test_the_human_still_cannot_reach_the_System_GATED_WRITE(self, dao, conn, world):
        """
        Row 2. THE LOAD-BEARING ROW. The refusal in row 1 is a means; the end
        is that no human session passes `_require_role(session, "System")` at
        `record_fastq_set`. This asserts the CAPABILITY, through the method,
        not the exception type of a helper.

        Both halves are asserted as a pair, as Standing Rule 4 requires: the
        grant is refused AND no `fastq_sets` row exists afterwards. An
        exception-only assertion would pass against an implementation that
        raised after writing.

        Catches: the f89766a version — there the grant succeeds, the human's
        session passes the gate, and `record_fastq_set` RETURNS AN ID. VACUOUS
        AGAINST: a version that breaks `record_fastq_set` for everyone, which
        row 4 catches.
        """
        # DELIBERATELY TOLERANT OF THE GRANT'S OUTCOME. Row 1 already asserts
        # the refusal; if this row asserted it too it would fail HERE on the
        # broken version and never reach the assertion it exists for. The
        # question this row asks is not "was the grant refused" but "can a
        # human session reach the System-gated write", and it must be able to
        # ask that question of a version where the grant SUCCEEDED.
        try:
            dao.assign_role(world["admin"], world["target_id"], "System")
            conn.commit()
        except ValueError:
            conn.rollback()

        from clinical.data_access import AuthorizationError

        # A fresh login, because the credential a person holds after a failed
        # escalation is a fresh one, not the one minted before it.
        human = dao.login("human@w141.test", world["org_id"], PASSWORD)
        conn.commit()

        with pytest.raises(AuthorizationError):
            _record(dao, human, world["sample_id"])
        conn.rollback()

        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM fastq_sets WHERE org_id = %s", (world["org_id"],))
            assert cur.fetchone()[0] == 0

    def test_a_non_administrator_is_refused_for_BEING_A_NON_ADMINISTRATOR(self, dao, conn, world):
        """
        Row 5. THE ORDERING ROW. The Administrator check stays FIRST, so a
        caller who is not an Administrator gets AuthorizationError for "System"
        exactly as they would for "Auditor" — the new refusal must not become
        an oracle telling an under-privileged caller which role names are
        special.

        Asserted as a set of size one over the two role names, per Rule 8's
        shape: a per-case check passes against a split nobody listed.

        Catches: a fix placed ABOVE `_require_role`. VACUOUS AGAINST: the
        f89766a version, which also refuses this caller — which is why it is
        not the only row.
        """
        from clinical.data_access import AuthorizationError

        observed = set()
        for role in ("System", "Auditor"):
            with pytest.raises(AuthorizationError) as caught:
                dao.assign_role(world["human"], world["admin_id"], role)
            conn.rollback()
            observed.add((type(caught.value).__name__, str(caught.value)))
        assert len(observed) == 1, observed


# ─── the positive twins ──────────────────────────────────────────────────────


class TestThePositiveTwins:
    def test_every_other_role_is_still_assignable(self, dao, conn, world):
        """
        Row 3. Standing Rule 4's positive twin for row 1. Six roles, each
        granted for real and read back THROUGH `get_user_roles` — never through
        a hand-written SELECT, which would pass while the method was broken
        (the Phase 5d precedent).

        Catches: a fix that refuses every role, or that refuses one by typo.
        VACUOUS AGAINST: the f89766a version, which assigns all seven.
        """
        from clinical.data_access import HUMAN_ASSIGNABLE_ROLES

        for role in HUMAN_ASSIGNABLE_ROLES:
            basis = "GMC 1234567, consultant" if role == "Approver" else None
            dao.assign_role(world["admin"], world["target_id"], role, basis=basis)
        conn.commit()

        target_session = dao.login("human@w141.test", world["org_id"], PASSWORD)
        conn.commit()
        held = {a.role for a in dao.get_user_roles(target_session)}
        assert set(HUMAN_ASSIGNABLE_ROLES) <= held, held
        assert "System" not in held, held

    def test_the_real_system_principal_still_records_a_fastq_set(self, dao, conn, world):
        """
        Row 4. The twin for row 2, and the one that stops the fix from being a
        blanket break of the System gate. `_create_system_session` is the ONLY
        thing entitled to the role and it writes its `role_assignments` row
        with raw SQL, not through `assign_role` — so the refusal added to
        `assign_role` must not touch it.

        Read back THROUGH `find_fastq_set_by_checksums`, not through a SELECT.

        Catches: a fix that removed "System" from `ROLES` (which would break
        the schema CHECK and the system principal both), or one that put the
        refusal inside `_require_role`. VACUOUS AGAINST: the f89766a version,
        where this also passes.
        """
        system = dao._create_system_session(world["org_id"])
        conn.commit()
        recorded = _record(dao, system, world["sample_id"], n="sys")
        conn.commit()
        assert recorded is not None
        found = dao.find_fastq_set_by_checksums(system, "r1sumsys", "r2sumsys")
        assert found == recorded


# ─── the census ──────────────────────────────────────────────────────────────


class TestTheVocabularyIsUnchangedAndTheSplitIsExplicit:
    def test_ROLES_still_holds_all_seven_because_the_schema_CHECK_does(self):
        """
        NO SCHEMA CHANGE AND NO ROLE REMOVED. `role_assignments.role` has a
        CHECK constraint enumerating all seven names, and
        `_create_system_session` writes "System" into it. Narrowing `ROLES`
        instead of adding a second tuple would have broken that row.

        Standing Rule 3: this is a census, so it counts.
        """
        from clinical.data_access import HUMAN_ASSIGNABLE_ROLES, ROLES

        assert len(ROLES) == 7, ROLES
        assert "System" in ROLES
        assert set(ROLES) - set(HUMAN_ASSIGNABLE_ROLES) == {"System"}
        assert len(HUMAN_ASSIGNABLE_ROLES) == 6, HUMAN_ASSIGNABLE_ROLES

    def test_the_schema_CHECK_still_accepts_System(self, conn, clinical_dsn):
        """
        The non-vacuity guard for the row above: it asserts the DATABASE still
        permits the value, so "ROLES has seven entries" is not a claim about a
        Python tuple alone. Written and rolled back.
        """
        with conn.cursor() as cur:
            cur.execute(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'role_assignments'::regclass AND contype = 'c'"
            )
            definitions = " ".join(row[0] for row in cur.fetchall())
        conn.rollback()
        assert "System" in definitions, definitions
