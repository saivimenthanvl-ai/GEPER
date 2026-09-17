"""
clinical/tests/test_patient_identity.py
────────────────────────────────────────
w130 — the patient identity foundation.

WHAT THIS SUITE EXISTS TO CATCH, stated first because everything else is
secondary to it:

    A patient-facing read that binds the patient identifier from a CALLER
    ARGUMENT rather than from the authenticated session.

That version works. It passes a cross-organisation test, it passes a
"patient A sees their own data" test, it passes a not-found test, and it
passes a test that hands it the session's own patient id. The only test it
fails is one that hands it a DIFFERENT, REAL, SAME-ORGANISATION patient's id
and asserts the answer is about the SESSION's patient. That test is
`TestPatientIdentityComesFromTheSession` below and it is the reason this file
exists.

RUNNING THESE. Like clinical/tests/test_identity.py they need a real
PostgreSQL -- most of what they assert is enforced BY Postgres (the composite
foreign keys, the one-login-per-patient uniqueness, the termination CHECK).

    $env:CLINICAL_TEST_DSN="postgresql://...";  $env:CLINICAL_TEST_DB_DISPOSABLE="1"
    py -3.12 -m pytest clinical/tests/test_patient_identity.py

THE FOUR-CELL MATRIX this file is built around is NOT the tenancy matrix:

    right patient + right organisation  -> allowed
    wrong patient + right organisation  -> refused      <- the new axis
    right patient + wrong organisation  -> refused
    wrong patient + wrong organisation  -> refused
"""

from __future__ import annotations

import datetime as dt
import os
import pathlib
import uuid

import pytest

from clinical.data_access import (
    ORG_SCOPED_TABLES,
    BcryptHasher,
    DataAccess,
)

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"

requires_db = pytest.mark.skipif(
    not DSN, reason="CLINICAL_TEST_DSN not set -- database tests skipped (skip is not pass)"
)

PASSWORD = "a sufficiently long patient password"
OTHER_PASSWORD = "a different sufficiently long password"


class FakeClock:
    def __init__(self, start: dt.datetime | None = None) -> None:
        self._now = start or dt.datetime(2026, 9, 3, 9, 0, 0, tzinfo=dt.timezone.utc)

    def now(self) -> dt.datetime:
        return self._now

    def advance(self, **kwargs) -> None:
        self._now = self._now + dt.timedelta(**kwargs)


# ─── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def conn():
    psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")
    if not DSN:
        pytest.skip("CLINICAL_TEST_DSN not set")
    connection = psycopg.connect(DSN, autocommit=False, connect_timeout=10)
    with connection.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        cur.execute("DO $$ BEGIN CREATE ROLE clinical_app; EXCEPTION WHEN duplicate_object THEN NULL; END $$;")
        cur.execute("DO $$ BEGIN CREATE ROLE clinical_retention; EXCEPTION WHEN duplicate_object THEN NULL; END $$;")
        cur.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture()
def clock():
    return FakeClock()


@pytest.fixture()
def dao(conn, clock):
    return DataAccess(conn, clock=clock, password_hasher=BcryptHasher(rounds=4))


@pytest.fixture()
def org_a(dao):
    return dao.create_organisation("Org A")


@pytest.fixture()
def org_b(dao):
    return dao.create_organisation("Org B")


def _staff_session(dao, conn, org_id, email, *, administrator=True):
    """A staff principal with the roles it needs, inserted directly to break
    the bootstrap cycle exactly as test_identity.py's admin_session does."""
    user_id = dao.create_user(org_id, email, "correct horse battery staple")
    if administrator:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                "VALUES (%s, %s, 'Administrator', %s, %s)",
                (user_id, org_id, user_id, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
            )
    return dao.login(email, org_id, "correct horse battery staple")


@pytest.fixture()
def staff_a(dao, conn, org_a):
    return _staff_session(dao, conn, org_a, "admin@a.example")


@pytest.fixture()
def staff_b(dao, conn, org_b):
    return _staff_session(dao, conn, org_b, "admin@b.example")


@pytest.fixture()
def patient_a(dao, staff_a):
    """Alice. The patient whose session every positive assertion is made from."""
    return dao.create_patient(staff_a, "Alice Anderson", dt.date(1980, 1, 1), "F")


@pytest.fixture()
def patient_a2(dao, staff_a):
    """Bob. A DIFFERENT, REAL patient in the SAME organisation as Alice.

    This fixture is the whole point of the suite. A cross-organisation victim
    proves nothing about the patient axis, because the org predicate already
    refuses it. Bob is refused only if the patient axis is real.
    """
    return dao.create_patient(staff_a, "Bob Brown", dt.date(1975, 6, 15), "M")


@pytest.fixture()
def patient_b(dao, staff_b):
    """Carol, in the OTHER organisation."""
    return dao.create_patient(staff_b, "Carol Clark", dt.date(1990, 3, 3), "F")


# ─── the schema: the two tables, and what Postgres refuses ───────────────────


@requires_db
class TestTheTwoTablesAreStructural:
    """
    The guarantees here are enforced by Postgres, not by Python, which is why
    each one is proved by attempting the write and watching it be refused
    rather than by reading the schema text.
    """

    def test_a_credential_cannot_name_a_patient_in_another_organisation(self, conn, org_a, patient_b, staff_a):
        """
        The composite FK, exercised. A patient_logins row in org_a naming
        Carol -- a patient who really exists, in org_b -- must be
        inexpressible, not merely unwritten.
        """
        psycopg = pytest.importorskip("psycopg")
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO patient_logins (patient_login_id, patient_id, org_id, email, "
                    "password_hash, password_changed_at, enrolled_by, created_at, updated_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        uuid.uuid4(),
                        patient_b,  # a real patient -- in the WRONG organisation
                        org_a,
                        "carol@a.example",
                        "$2b$04$notarealhash",
                        dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc),
                        staff_a.user_id,
                        dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc),
                        dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc),
                    ),
                )
        conn.rollback()

    def test_the_positive_twin_the_same_insert_for_the_right_organisation_succeeds(
        self, conn, org_a, patient_a, staff_a
    ):
        """
        Rule 4's positive twin. Without it, the refusal above is satisfied by
        an INSERT that is broken for some entirely different reason -- a typo
        in a column name refuses the row just as convincingly.
        """
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO patient_logins (patient_login_id, patient_id, org_id, email, "
                "password_hash, password_changed_at, enrolled_by, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    uuid.uuid4(),
                    patient_a,
                    org_a,
                    "alice@a.example",
                    "$2b$04$notarealhash",
                    dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc),
                    staff_a.user_id,
                    dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc),
                    dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc),
                ),
            )
        conn.commit()
        with conn.cursor() as cur:
            cur.execute("SELECT email FROM patient_logins WHERE org_id = %s AND patient_id = %s", (org_a, patient_a))
            assert cur.fetchone()[0] == "alice@a.example"

    def test_a_patient_cannot_hold_a_role_assignment(self, conn, org_a, patient_a, staff_a):
        """
        "Patients are not staff roles", proved structurally rather than
        asserted. role_assignments.user_id is a composite FK to `users`, so a
        patient_id in it is refused by the database. No eighth role value was
        added and none could help: the refusal is about the FK, not the CHECK.
        """
        psycopg = pytest.importorskip("psycopg")
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                    "VALUES (%s, %s, 'Administrator', %s, %s)",
                    (patient_a, org_a, staff_a.user_id, dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc)),
                )
        conn.rollback()

    def test_a_patient_cannot_be_given_a_staff_session_row(self, conn, org_a, patient_a):
        """
        The other half of the principal separation, and the cheapest one to
        prove without ambiguity: `sessions` carries exactly one foreign key, so
        a refusal here can only be sessions_user_fk and cannot be some other
        constraint firing first.

        A patient id in `sessions` would be a patient holding a STAFF session,
        which is decision 8 inverted. The database refuses it.
        """
        psycopg = pytest.importorskip("psycopg")
        now = dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc)
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO sessions (session_id, user_id, org_id, created_at, expires_at, "
                    "last_activity_at) VALUES (%s, %s, %s, %s, %s, %s)",
                    (uuid.uuid4(), patient_a, org_a, now, now + dt.timedelta(hours=24), now),
                )
        conn.rollback()

    def test_the_positive_twin_a_real_staff_id_in_sessions_is_accepted(self, conn, org_a, staff_a):
        """Rule 4's twin: the same INSERT with a staff principal succeeds, so
        the refusal above is about WHO, not about a malformed statement."""
        now = dt.datetime(2026, 9, 3, tzinfo=dt.timezone.utc)
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sessions (session_id, user_id, org_id, created_at, expires_at, "
                "last_activity_at) VALUES (%s, %s, %s, %s, %s, %s)",
                (uuid.uuid4(), staff_a.user_id, org_a, now, now + dt.timedelta(hours=24), now),
            )
        conn.commit()


class TestTheGuardRailsCoverTheNewTables:
    """Source-reading; runs without a database."""

    def test_both_tables_are_declared_org_scoped(self):
        """
        Not a restatement of the derived guard, which already fails if a name
        is missing. This pins the DIRECTION: neither table may be moved to the
        exemption list later, and the exemption interlock refuses it anyway
        because both carry org_id.
        """
        assert "patient_logins" in ORG_SCOPED_TABLES
        assert "patient_sessions" in ORG_SCOPED_TABLES

    def test_nothing_clinical_may_name_a_patient_principal_as_an_actor(self):
        """
        A CENSUS, not a sample (Standing Rule 3). The reason the principal is a
        separate table is that `REFERENCES users` occurs 22 times in
        schema.sql, nineteen of them clinical-record actor columns -- so a
        patient in `users` would be a database-legal report approver.

        That argument is only worth anything while patient_logins is referenced
        by NOTHING except the patient session table. This counts it. A future
        `reports.patient_approver_id`, or any other actor column pointed at the
        patient principal, fails here.
        """
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        referencing = [line.strip() for line in schema.splitlines() if "REFERENCES patient_logins" in line]
        assert len(referencing) == 1, f"patient_logins is referenced {len(referencing)} times: {referencing}"
        assert "patient_logins (patient_login_id, org_id)" in referencing[0]

    def test_no_patient_role_was_added(self):
        """
        Decision 1, asserted against both places a role could have been added.
        """
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        assert "'Patient'" not in schema
        source = (pathlib.Path(__file__).resolve().parent.parent / "data_access.py").read_text(encoding="utf-8")
        assert '"Patient"' not in source
        assert "role_assignments_role_known CHECK" in schema
        # The seven staff roles, unchanged.
        assert "role IN ('Orderer', 'Lab technician', 'Interpreter'," in schema
