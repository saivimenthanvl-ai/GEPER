"""
clinical/tests/test_identity.py
────────────────────────────────
Phase 1 identity suite.

RUNNING THESE. They need a real PostgreSQL database, because most of what
they assert is enforced BY Postgres -- composite foreign keys, the CHECK on
Approver's basis, REVOKE on audit_log. A sqlite stand-in would run faster and
prove none of it.

    export CLINICAL_TEST_DSN=postgresql://user:pw@localhost:5432/clinical_test
    pytest clinical/tests/test_identity.py

Without that variable every database test SKIPS. A skip is not a pass: if the
suite reports "skipped" then nothing here has been verified, and it should be
read as no evidence rather than as green. TestStructuralIsolation is the one
class that runs anywhere, because it reads source rather than rows.
"""

from __future__ import annotations

import ast
import datetime as dt
import os
import pathlib
import re
import uuid

import pytest

from clinical.data_access import (
    GENERIC_AUTH_ERROR,
    MAX_FAILED_LOGIN_ATTEMPTS,
    ORG_SCOPED_TABLES,
    TABLES_EXEMPT_FROM_ORG_SCOPING,
    AuthenticationError,
    AuthorizationError,
    BcryptHasher,
    DataAccess,
    NotFoundError,
    SessionExpired,
)

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"

requires_db = pytest.mark.skipif(
    not DSN, reason="CLINICAL_TEST_DSN not set -- database tests skipped (skip is not pass)"
)


# ─── test doubles ────────────────────────────────────────────────────────────


class FakeClock:
    """
    The single clock. Passed into DataAccess, so production reads exactly the
    time the test sets -- no `datetime.now()` anywhere in the layer to drift
    against it. Without that, an advancing mock and a wall-clock read compare
    two different clocks and the assertion passes or fails for the wrong
    reason.
    """

    def __init__(self, start: dt.datetime | None = None) -> None:
        self._now = start or dt.datetime(2026, 9, 3, 9, 0, 0, tzinfo=dt.timezone.utc)

    def now(self) -> dt.datetime:
        return self._now

    def advance(self, **kwargs) -> None:
        self._now = self._now + dt.timedelta(**kwargs)


class ReversibleCipher:
    """Stand-in for the production secret cipher. Reversible, never secure."""

    def encrypt(self, plaintext: str) -> str:
        return "enc:" + plaintext

    def decrypt(self, ciphertext: str) -> str:
        assert ciphertext.startswith("enc:")
        return ciphertext[4:]


class FixedTotpVerifier:
    """Accepts one known code, so the suite does not depend on pyotp or on time steps."""

    VALID = "424242"

    def verify(self, secret: str, code: str, at: dt.datetime) -> bool:
        return secret == "SECRET" and code == self.VALID


# ─── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def conn():
    psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")
    if not DSN:
        pytest.skip("CLINICAL_TEST_DSN not set")
    # connect_timeout is not tuning. Without it, a DSN pointing at nothing
    # makes this fixture BLOCK rather than raise -- measured: the run hung past
    # two minutes against a closed port. In CI that is a job that sits until the
    # workflow timeout and reports neither pass nor fail, which is the same
    # silent non-result the fail-not-skip guard exists to prevent. Ten seconds
    # is long enough for a service container that is still starting and short
    # enough that "the database is not there" arrives as an error.
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
    return DataAccess(
        conn,
        clock=clock,
        # Low cost so the suite stays fast while remaining real bcrypt --
        # the algorithm under test is the one that ships.
        password_hasher=BcryptHasher(rounds=4),
        totp_verifier=FixedTotpVerifier(),
        secret_cipher=ReversibleCipher(),
    )


@pytest.fixture()
def org_a(dao):
    return dao.create_organisation("Org A")


@pytest.fixture()
def org_b(dao):
    return dao.create_organisation("Org B")


@pytest.fixture()
def admin_session(dao, org_a, conn):
    """An administrator in org_a, with the role inserted directly to break the
    bootstrap cycle (assign_role itself requires an Administrator)."""
    admin_id = dao.create_user(org_a, "admin@a.example", "correct horse battery staple")
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Administrator', %s, %s)",
            (admin_id, org_a, admin_id, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
        )
        # w129 phase B: the ordering operations require Orderer and the
        # sample / laboratory / QC operations require Lab technician. This
        # fixture's account is the whole staff of its organisation -- it
        # orders, receives, runs and reviews -- so it holds the roles for
        # the work it performs. Roles are additive; still an Administrator.
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Orderer', %s, %s)",
            (admin_id, org_a, admin_id, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
        )
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Lab technician', %s, %s)",
            (admin_id, org_a, admin_id, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
        )
    return dao.login("admin@a.example", org_a, "correct horse battery staple", ip_address="10.0.0.1")


# ─── organisation isolation ──────────────────────────────────────────────────


@requires_db
class TestOrgIsolation:
    def test_cross_org_read_by_id_is_not_found(self, dao, org_a, org_b, admin_session):
        """
        The real cross-org attempt: a valid org_a session, holding a REAL
        org_b user id, asking for that record by id. Not a wrong function
        call -- an actual read of a record that exists, from the wrong side of
        the boundary.
        """
        victim = dao.create_user(org_b, "clinician@b.example", "a sufficiently long password")

        with pytest.raises(NotFoundError):
            dao.get_user(admin_session, victim)

    def test_cross_org_miss_is_indistinguishable_from_absent(self, dao, org_b, admin_session):
        """
        A real id in another organisation and an invented id must produce the
        same error. If they differed, the difference would confirm the record
        exists somewhere -- existence is itself information.
        """
        real_elsewhere = dao.create_user(org_b, "someone@b.example", "a sufficiently long password")
        invented = uuid.uuid4()

        with pytest.raises(NotFoundError) as real_exc:
            dao.get_user(admin_session, real_elsewhere)
        with pytest.raises(NotFoundError) as invented_exc:
            dao.get_user(admin_session, invented)

        assert type(real_exc.value) is type(invented_exc.value)
        # Only the echoed id differs; the shape of the message does not.
        assert str(real_exc.value).replace(str(real_elsewhere), "X") == str(invented_exc.value).replace(
            str(invented), "X"
        )

    def test_cross_org_role_read_returns_nothing(self, dao, org_b, admin_session):
        victim = dao.create_user(org_b, "roles@b.example", "a sufficiently long password")
        assert dao.get_user_roles(admin_session, victim) == []

    def test_composite_fk_blocks_cross_org_role_row(self, dao, conn, org_a, org_b):
        """
        The schema half of the isolation: even bypassing this layer entirely
        and inserting straight into the table, a role in org_a cannot name a
        user who belongs to org_b.
        """
        psycopg = pytest.importorskip("psycopg")
        victim = dao.create_user(org_b, "fk@b.example", "a sufficiently long password")
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                    "VALUES (%s, %s, 'Interpreter', %s, %s)",
                    (victim, org_a, victim, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
                )


# ─── authentication failure is uniform ───────────────────────────────────────


@requires_db
class TestAuthFailureIsUniform:
    def test_disabled_user_auth_indistinguishable(self, dao, org_a, admin_session):
        """
        Asserts EQUALITY against the generic message, not the absence of a
        word. An absence check passes for "Invalid account credentials" --
        which is fine -- and would therefore not break if someone later
        shipped a message that is fine in wording but distinguishing in
        effect. Equality breaks the moment any path says something different.
        """
        target = dao.create_user(org_a, "off@a.example", "a sufficiently long password")
        dao.set_user_disabled(admin_session, target, True)

        with pytest.raises(AuthenticationError) as disabled_exc:
            dao.login("off@a.example", org_a, "a sufficiently long password")
        with pytest.raises(AuthenticationError) as wrong_pw_exc:
            dao.login("off@a.example", org_a, "definitely not the password")

        assert str(disabled_exc.value) == GENERIC_AUTH_ERROR
        assert str(wrong_pw_exc.value) == GENERIC_AUTH_ERROR

    def test_unknown_user_matches_wrong_password(self, dao, org_a):
        dao.create_user(org_a, "real@a.example", "a sufficiently long password")

        with pytest.raises(AuthenticationError) as unknown:
            dao.login("nobody@a.example", org_a, "a sufficiently long password")
        with pytest.raises(AuthenticationError) as wrong:
            dao.login("real@a.example", org_a, "wrong wrong wrong wrong")

        assert str(unknown.value) == str(wrong.value) == GENERIC_AUTH_ERROR


# ─── lockout ─────────────────────────────────────────────────────────────────


@requires_db
class TestLockout:
    def test_lockout_enforcement(self, dao, clock, org_a):
        """
        No sleep, and no second clock. `clock` is the same object DataAccess
        was constructed with, so advancing it advances production's view of
        time as well -- the locked_until comparison inside login() reads this
        clock, not the wall clock.
        """
        dao.create_user(org_a, "locked@a.example", "a sufficiently long password")

        for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(AuthenticationError):
                dao.login("locked@a.example", org_a, "wrong password entirely")

        # Locked: the CORRECT password is now refused.
        with pytest.raises(AuthenticationError) as locked:
            dao.login("locked@a.example", org_a, "a sufficiently long password")
        assert str(locked.value) == GENERIC_AUTH_ERROR

        # Still locked one minute before the window closes.
        clock.advance(minutes=29)
        with pytest.raises(AuthenticationError):
            dao.login("locked@a.example", org_a, "a sufficiently long password")

        # Open after it.
        clock.advance(minutes=2)
        session = dao.login("locked@a.example", org_a, "a sufficiently long password")
        assert session.org_id == org_a

    def test_successful_login_resets_only_that_users_counter(self, dao, clock, conn, org_a):
        """
        The counter is per-user, so an attacker holding one valid credential
        cannot keep a second account permanently unlocked by logging in as
        themselves.
        """
        dao.create_user(org_a, "victim@a.example", "a sufficiently long password")
        dao.create_user(org_a, "attacker@a.example", "another sufficiently long one")

        for _ in range(3):
            with pytest.raises(AuthenticationError):
                dao.login("victim@a.example", org_a, "wrong")

        dao.login("attacker@a.example", org_a, "another sufficiently long one")

        with conn.cursor() as cur:
            cur.execute(
                "SELECT failed_login_attempts FROM users WHERE org_id = %s AND email = %s",
                (org_a, "victim@a.example"),
            )
            assert cur.fetchone()[0] == 3, "another user's login cleared this user's counter"

        dao.login("victim@a.example", org_a, "a sufficiently long password")
        with conn.cursor() as cur:
            cur.execute(
                "SELECT failed_login_attempts FROM users WHERE org_id = %s AND email = %s",
                (org_a, "victim@a.example"),
            )
            assert cur.fetchone()[0] == 0


# ─── audit ───────────────────────────────────────────────────────────────────


@requires_db
class TestAudit:
    def test_lockout_audit_distinguishes_sources(self, dao, conn, org_a):
        """
        Proves ORDER and GROUPING, not merely presence: five failures from one
        address and one from another must be readable as that, in sequence.
        A count alone would not tell a distributed attempt from a single
        source.
        """
        dao.create_user(org_a, "watched@a.example", "a sufficiently long password")

        for _ in range(5):
            with pytest.raises(AuthenticationError):
                dao.login("watched@a.example", org_a, "wrong", ip_address="203.0.113.7")
        with pytest.raises(AuthenticationError):
            dao.login("watched@a.example", org_a, "wrong", ip_address="198.51.100.2")

        with conn.cursor() as cur:
            cur.execute(
                "SELECT ip_address FROM audit_log WHERE action = 'login_failed' AND org_id = %s "
                'ORDER BY "timestamp", log_id',
                (org_a,),
            )
            addresses = [str(r[0]) for r in cur.fetchall()]

        assert addresses == ["203.0.113.7"] * 5 + ["198.51.100.2"]

    def test_failed_login_against_unknown_org_is_logged_with_null_org(self, dao, conn):
        """
        The event most worth recording is the one an FK would have rejected.
        """
        with pytest.raises(AuthenticationError):
            dao.login("probe@nowhere.example", uuid.uuid4(), "guess", ip_address="203.0.113.9")

        with conn.cursor() as cur:
            cur.execute("SELECT org_id, details FROM audit_log WHERE action = 'login_failed' AND org_id IS NULL")
            rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0][0] is None
        assert rows[0][1]["reason"] == "unknown_organisation"
        assert rows[0][1]["email"] == "probe@nowhere.example"

    def test_audit_log_rejects_update_and_delete_for_app_role(self, conn):
        """
        Append-only is a privilege, not a comment. Asserted as the application
        role, since the owner can always do anything.
        """
        psycopg = pytest.importorskip("psycopg")
        with conn.cursor() as cur:
            cur.execute("SET ROLE clinical_app")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("UPDATE audit_log SET action = 'tampered'")
            # Transaction entered error state; must rollback before continuing
            conn.rollback()
            cur.execute("RESET ROLE")

        conn.commit()

        with conn.cursor() as cur:
            cur.execute("SET ROLE clinical_app")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("DELETE FROM audit_log")
            # Transaction entered error state; must rollback before continuing
            conn.rollback()
            cur.execute("RESET ROLE")

        conn.commit()


# ─── sessions ────────────────────────────────────────────────────────────────


@requires_db
class TestSessions:
    def test_session_revocation(self, dao, org_a, admin_session):
        dao.create_user(org_a, "user@a.example", "a sufficiently long password")
        victim = dao.login("user@a.example", org_a, "a sufficiently long password")

        assert dao.session_valid(victim.session_id).user_id == victim.user_id

        dao.terminate_session(admin_session, victim.session_id)

        with pytest.raises(SessionExpired):
            dao.session_valid(victim.session_id)

    def test_idle_timeout_expires_and_activity_refreshes_it(self, dao, clock, org_a):
        dao.create_user(org_a, "idle@a.example", "a sufficiently long password")
        session = dao.login("idle@a.example", org_a, "a sufficiently long password")

        # Activity inside the window keeps it alive, repeatedly.
        for _ in range(4):
            clock.advance(minutes=20)
            assert dao.session_valid(session.session_id).session_id == session.session_id

        # Silence past the window ends it.
        clock.advance(minutes=31)
        with pytest.raises(SessionExpired):
            dao.session_valid(session.session_id)

    def test_absolute_cap_is_not_extended_by_activity(self, dao, clock, conn, org_a):
        """
        The 24-hour ceiling holds even for a session used continuously, AND the
        expiry at the end is the cap rather than the idle timeout.

        Every step advances 15 minutes -- strictly less than the 30-minute idle
        window -- so the idle timer is refreshed before it can ever fire. An
        earlier version of this test stepped by exactly 30 minutes, which is the
        inclusive idle boundary, so it died on the first step and never reached
        the assertion it was named for. Stepping under the window is what
        isolates the two expiries from each other.
        """
        dao.create_user(org_a, "long@a.example", "a sufficiently long password")
        session = dao.login("long@a.example", org_a, "a sufficiently long password")

        # 23h45m of steady activity, each step inside the idle window.
        for step in range(95):
            clock.advance(minutes=15)
            try:
                dao.session_valid(session.session_id)
            except SessionExpired:
                pytest.fail(f"session expired at step {step} ({(step + 1) * 15} min), before the cap")

        # One more 15-minute step lands exactly on the 24-hour cap. Activity was
        # 15 minutes ago, so the idle window is NOT exceeded -- the only thing
        # that can end the session here is the absolute ceiling.
        clock.advance(minutes=15)
        with pytest.raises(SessionExpired):
            dao.session_valid(session.session_id)

        # Prove that claim rather than assert it in prose: at the moment of
        # failure the session was well inside its idle window, so idle cannot
        # have been the cause.
        with conn.cursor() as cur:
            cur.execute(
                "SELECT last_activity_at, idle_timeout_minutes, expires_at FROM sessions WHERE session_id = %s",
                (session.session_id,),
            )
            last_activity, idle_minutes, expires_at = cur.fetchone()

        now = clock.now()
        assert now < last_activity + dt.timedelta(minutes=idle_minutes), (
            "idle window had also elapsed -- this test no longer isolates the absolute cap"
        )
        assert now >= expires_at, "session should have reached its absolute cap"

    def test_terminate_session_requires_administrator(self, dao, org_a, admin_session):
        dao.create_user(org_a, "plain@a.example", "a sufficiently long password")
        plain = dao.login("plain@a.example", org_a, "a sufficiently long password")
        other = dao.login("plain@a.example", org_a, "a sufficiently long password")

        with pytest.raises(AuthorizationError):
            dao.terminate_session(plain, other.session_id)


# ─── roles ───────────────────────────────────────────────────────────────────


@requires_db
class TestRoles:
    def test_assign_role_requires_administrator_not_approver(self, dao, org_a, admin_session):
        """
        Approver signs reports; Administrator manages users. An Approver who
        could grant Approver would collapse the separation the role table
        exists to express.
        """
        approver_id = dao.create_user(org_a, "approver@a.example", "a sufficiently long password")
        dao.assign_role(admin_session, approver_id, "Approver", basis="GMC 1234567, consultant")
        approver = dao.login("approver@a.example", org_a, "a sufficiently long password")

        target = dao.create_user(org_a, "target@a.example", "a sufficiently long password")
        with pytest.raises(AuthorizationError):
            dao.assign_role(approver, target, "Interpreter")

    def test_approver_requires_basis(self, dao, org_a, admin_session):
        target = dao.create_user(org_a, "needsbasis@a.example", "a sufficiently long password")
        with pytest.raises(ValueError):
            dao.assign_role(admin_session, target, "Approver")

    def test_approver_basis_is_retrievable(self, dao, org_a, admin_session):
        """ISO 15189 7.4.1.5 c): who granted it, when, and on what basis."""
        target = dao.create_user(org_a, "signer@a.example", "a sufficiently long password")
        dao.assign_role(admin_session, target, "Approver", basis="GMC 7654321, histopathology")

        (assignment,) = dao.get_user_roles(admin_session, target)
        assert assignment.role == "Approver"
        assert assignment.basis == "GMC 7654321, histopathology"
        assert assignment.assigned_by == admin_session.user_id
        assert assignment.assigned_at is not None

    def test_schema_rejects_approver_without_basis(self, dao, conn, org_a):
        """The CHECK, not just the Python guard."""
        psycopg = pytest.importorskip("psycopg")
        target = dao.create_user(org_a, "rawinsert@a.example", "a sufficiently long password")
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                    "VALUES (%s, %s, 'Approver', %s, %s)",
                    (target, org_a, target, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
                )


# ─── TOTP ────────────────────────────────────────────────────────────────────


@requires_db
class TestTotp:
    def test_totp_required_once_enrolled(self, dao, org_a, admin_session):
        target = dao.create_user(org_a, "mfa@a.example", "a sufficiently long password")
        dao.enrol_totp(admin_session, target, "SECRET")

        with pytest.raises(AuthenticationError):
            dao.login("mfa@a.example", org_a, "a sufficiently long password")

        session = dao.login(
            "mfa@a.example",
            org_a,
            "a sufficiently long password",
            totp_code=FixedTotpVerifier.VALID,
        )
        assert session.user_id == target

    def test_recovery_code_used_once(self, dao, org_a, admin_session):
        target = dao.create_user(org_a, "codes@a.example", "a sufficiently long password")
        codes = dao.enrol_totp(admin_session, target, "SECRET")
        assert len(codes) == 8

        first = codes[0]
        session = dao.login("codes@a.example", org_a, "a sufficiently long password", totp_code=first)
        assert session.user_id == target

        with pytest.raises(AuthenticationError):
            dao.login("codes@a.example", org_a, "a sufficiently long password", totp_code=first)

        # A different, unused code still works.
        assert dao.login("codes@a.example", org_a, "a sufficiently long password", totp_code=codes[1]).user_id == target

    def test_backup_codes_are_not_stored_readably(self, dao, conn, org_a, admin_session):
        target = dao.create_user(org_a, "hashed@a.example", "a sufficiently long password")
        codes = dao.enrol_totp(admin_session, target, "SECRET")

        with conn.cursor() as cur:
            cur.execute(
                "SELECT code_hash FROM totp_backup_codes WHERE user_id = %s AND org_id = %s",
                (target, org_a),
            )
            stored = [r[0] for r in cur.fetchall()]

        for code in codes:
            assert code not in stored
        assert all(h.startswith("$2") for h in stored), "backup codes must be bcrypt hashes"


# ─── structural isolation (runs without a database) ──────────────────────────


class TestStructuralIsolation:
    """
    The test the design promised: it fails if a raw-query path or an
    org-unscoped statement is introduced. Reads source, so it runs anywhere.
    """

    @staticmethod
    def _schema_tables() -> dict[str, str]:
        """
        Every CREATE TABLE in schema.sql, name -> column/constraint body.

        The census the coverage guard is derived from. Parsing the schema
        rather than reading a hand-written tuple is the whole point: a table
        that exists is on this list the moment it is created, whether or not
        anybody remembered to mention it in Python.
        """
        src = SCHEMA_PATH.read_text(encoding="utf-8")
        return dict(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)\s*\((.*?)\n\);", src, re.S))

    @classmethod
    def _org_owned_tables(cls) -> set[str]:
        """Schema census minus the written exemptions. Never the hand-written tuple."""
        return set(cls._schema_tables()) - set(TABLES_EXEMPT_FROM_ORG_SCOPING)

    def test_org_scoped_table_coverage_is_derived_from_the_schema(self):
        """
        w129 GAP-3. ORG_SCOPED_TABLES listed twelve of the schema's twenty-six
        tables. The twelve it omitted were not exempt and not argued for --
        they were simply missing, and a missing name is a guard rail that
        silently declines to look. exception_events, where the cross-tenant
        write of GAP-1 landed, was one of them.

        So the coverage is derived here from schema.sql, and the tuple is held
        to the derivation. A new org-owned table fails this test on the day it
        is created; the only way out is to name it in
        TABLES_EXEMPT_FROM_ORG_SCOPING with a reason somebody has to write down.
        """
        census = set(self._schema_tables())
        assert census, "parsed no CREATE TABLE from schema.sql -- the census regex is broken, not the schema"

        exempt = set(TABLES_EXEMPT_FROM_ORG_SCOPING)
        listed = set(ORG_SCOPED_TABLES)

        assert not (listed & exempt), f"table(s) both listed as org-scoped and exempted: {sorted(listed & exempt)}"
        assert not (exempt - census), f"exemption(s) for table(s) that are not in schema.sql: {sorted(exempt - census)}"

        missing = census - exempt - listed
        assert not missing, (
            f"org-owned table(s) in schema.sql that ORG_SCOPED_TABLES does not cover: {sorted(missing)}. "
            "Add the name and bind org_id in every statement against it, or exempt it in "
            "TABLES_EXEMPT_FROM_ORG_SCOPING with a written reason."
        )
        stale = listed - census
        assert not stale, f"ORG_SCOPED_TABLES names table(s) that schema.sql does not create: {sorted(stale)}"

    def test_only_a_table_without_an_org_id_column_may_be_exempt(self):
        """
        The interlock that stops the exemption list becoming the new hiding
        place. Exemption is available only where the column genuinely does not
        exist -- so a table cannot be exempted out of the org_id rule once it
        has an org_id, and conversely every name on ORG_SCOPED_TABLES must
        actually have the column it is being held to.
        """
        tables = self._schema_tables()

        def has_org_id(body: str) -> bool:
            return re.search(r"^\s*org_id\b", body, re.M) is not None

        wrongly_exempt = [name for name in TABLES_EXEMPT_FROM_ORG_SCOPING if has_org_id(tables.get(name, ""))]
        assert not wrongly_exempt, (
            f"table(s) exempted from org scoping that DO have an org_id column: {wrongly_exempt}. "
            "The exemption exists for tables where the column is absent, not for tables where "
            "binding it was inconvenient."
        )

        no_column = [name for name in ORG_SCOPED_TABLES if not has_org_id(tables.get(name, ""))]
        assert not no_column, (
            f"table(s) declared org-scoped with no org_id column in schema.sql: {no_column}. "
            "The statements against them cannot bind what the table does not have."
        )

    @staticmethod
    def _sql_literals() -> list[str]:
        source = (pathlib.Path(__file__).resolve().parent.parent / "data_access.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                if any(kw in text for kw in ("SELECT ", "UPDATE ", "DELETE FROM", "INSERT INTO")):
                    out.append(" ".join(text.split()))
        return out

    def test_every_org_scoped_statement_binds_org_id(self):
        """
        Driven off the SCHEMA-DERIVED set, deliberately, and not off
        ORG_SCOPED_TABLES.

        If this read the tuple, then deleting a name from the tuple would
        delete the check -- which is precisely the shape of the GAP-3 defect:
        the guard was silent about exception_events because nobody had typed
        its name. Deriving the set here means the only way to stop this test
        looking at a table is to remove the table from the schema or to write
        an exemption for it, and the exemption is itself checked above.
        """
        scoped = self._org_owned_tables()
        offenders = []
        for sql in self._sql_literals():
            touched = sorted(
                {table for table in scoped for verb in ("FROM", "INTO", "UPDATE", "JOIN") if f"{verb} {table}" in sql}
            )
            if touched and "org_id" not in sql:
                offenders.append(f"{','.join(touched)}: {sql}")
        assert not offenders, "statement(s) against an org-scoped table without an org_id predicate:\n  " + "\n  ".join(
            offenders
        )

    def test_no_public_attribute_exposes_the_connection(self):
        sentinel = object()
        dao = DataAccess(sentinel, clock=FakeClock())
        exposed = [name for name in dir(dao) if not name.startswith("_") and getattr(dao, name, None) is sentinel]
        assert not exposed, f"connection reachable via public attribute(s): {exposed}"

    def test_no_method_accepts_caller_supplied_sql(self):
        source = (pathlib.Path(__file__).resolve().parent.parent / "data_access.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        offenders = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and not node.name.startswith("_")
            and any(a.arg in ("sql", "query", "where", "predicate") for a in node.args.args)
        ]
        assert not offenders, f"public method(s) accepting caller-supplied SQL: {offenders}"

    def test_layer_never_reads_the_wall_clock(self):
        """
        Clock injection, asserted rather than trusted. If any method starts
        calling datetime.now() directly, a test that advances a mock clock
        silently begins comparing two different clocks.
        """
        source = (pathlib.Path(__file__).resolve().parent.parent / "data_access.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        offenders = []
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            if cls.name == "SystemClock":
                continue  # the one permitted reader of the wall clock
            for node in ast.walk(cls):
                if isinstance(node, ast.Attribute) and node.attr in ("now", "utcnow", "today"):
                    value = node.value
                    name = getattr(value, "attr", None) or getattr(value, "id", None)
                    if name in ("datetime", "date", "_datetime"):
                        offenders.append(f"{cls.name}: {name}.{node.attr}()")
        assert not offenders, f"wall-clock read(s) outside SystemClock: {offenders}"

    def test_every_public_method_has_auditable_decorator(self):
        """
        Phase 2 audit: every public DataAccess method declares its audit status
        via @auditable. Absence of the decorator means "nobody looked", not
        "deliberately non-auditable". Non-auditable methods must declare
        auditable=False with a reason.
        """
        source = (pathlib.Path(__file__).resolve().parent.parent / "data_access.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        undecorated = []
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "DataAccess"]:
            for node in cls.body:
                if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                    # Check if @auditable decorator is present
                    has_auditable = any(
                        (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == "auditable")
                        or (isinstance(d, ast.Name) and d.id == "auditable")
                        for d in node.decorator_list
                    )
                    if not has_auditable:
                        undecorated.append(node.name)

        assert not undecorated, (
            f"Public method(s) without @auditable decorator: {undecorated}. "
            f"Every public method must declare @auditable(auditable=True) or "
            f"@auditable(auditable=False, reason='...')."
        )

    # ─── the _create_system_session call-site guard (w129 GAP-5) ─────────────
    #
    # THE CONTROL THAT REPORTED ITSELF ENFORCED AND WAS NOT.
    #
    # This guard used to read only clinical/data_access.py and match only
    # `self._create_system_session(...)`. There are ZERO such calls in that
    # file. The assertion was `0 <= 1`. It passed vacuously and had never once
    # examined a real call site -- Rule 4 in its exact form, a counting test
    # satisfied by the broken state as easily as by the working one.
    #
    # Widening the matcher and the tree makes it report 4, not 0. The stated
    # invariant was "at most one"; reality is four. THE RULE WAS NOT "ONE", AND
    # THE NUMBER WAS NOT CHANGED TO MAKE A TEST PASS. It was established from
    # the code, and this is what the four sites have in common:
    #
    #   * all four are inside a BACKGROUND WORKER CLASS in geper/api/ --
    #     ExceptionRetryWorker and InterpretationWorker;
    #   * each worker class is instantiated in exactly one place, its own
    #     module's main() entry point, and in nothing else: counted repo-wide,
    #     `InterpretationWorker(` and `ExceptionRetryWorker(` appear zero times
    #     outside their own modules and the test suites, and neither appears in
    #     geper/api/main.py, clinical/app.py or clinical/endpoints.py at all;
    #   * so none of them sits in, or is reachable from, a request-handling
    #     path -- which is precisely and only what the method's docstring says
    #     must never happen;
    #   * each needs an organisation context for work that HAS no human actor:
    #     retry scheduling, recording a submission failure, clinical preflight
    #     for a queued submission, and reconciling interrupted submissions.
    #
    # The invariant is therefore about WHERE, not HOW MANY, and the sites are
    # pinned BY NAME. A fifth call site fails this test; so does reverting the
    # widening, because a narrowed scan finds fewer than four.
    #
    # TESTS ARE EXCLUDED FROM THE SCAN ON PURPOSE. clinical/tests/ mints system
    # sessions dozens of times by design (test_phase_7_commit4_retention.py
    # alone does it twenty times). The docstring's claim is about production,
    # and a test suite is not a request-handling path.
    _SYSTEM_SESSION_CALL_SITES = frozenset(
        {
            ("geper/api/exception_retry_worker.py", "ExceptionRetryWorker::_process_all_orgs"),
            ("geper/api/submission_worker.py", "InterpretationWorker::_create_submission_failure_exception"),
            ("geper/api/submission_worker.py", "InterpretationWorker::_clinical_preflight"),
            ("geper/api/submission_worker.py", "InterpretationWorker::reconcile_interrupted_submissions"),
        }
    )

    @staticmethod
    def _scan_for_system_session_calls(root: pathlib.Path) -> tuple[set[tuple[str, str]], int]:
        """
        Every attribute access ending in `_create_system_session` that is CALLED,
        whatever it is spelled on -- `self.`, `self.data_access.`, `dao.`, or
        anything else. The old matcher required the receiver to be the bare name
        `self`, which is why it found nothing: the real sites are all
        `self.data_access._create_system_session`.

        Returns the (file, Class::method) set and the number of files parsed, so
        a scan that quietly stopped visiting the tree can be told apart from a
        tree that genuinely has no call sites.
        """
        found: set[tuple[str, str]] = set()
        files = 0
        for path in sorted(root.rglob("*.py")):
            rel = path.relative_to(root)
            if "tests" in rel.parts or ".git" in rel.parts or ".venv" in rel.parts:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            files += 1
            context: list[str] = []
            rel_posix = rel.as_posix()

            class _Visitor(ast.NodeVisitor):
                def visit_FunctionDef(self, node):  # noqa: N802
                    context.append(node.name)
                    self.generic_visit(node)
                    context.pop()

                visit_AsyncFunctionDef = visit_FunctionDef

                def visit_ClassDef(self, node):  # noqa: N802
                    context.append(node.name)
                    self.generic_visit(node)
                    context.pop()

                def visit_Call(self, node):  # noqa: N802
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "_create_system_session":
                        found.add((rel_posix, "::".join(context)))
                    self.generic_visit(node)

            _Visitor().visit(tree)
        return found, files

    def test_create_system_session_call_sites_are_the_four_pinned_worker_sites(self):
        """
        w129 GAP-5. The real source tree, the widened matcher, and the sites
        pinned by name.
        """
        root = pathlib.Path(__file__).resolve().parent.parent.parent
        found, files = self._scan_for_system_session_calls(root)

        assert files > 1, (
            f"the scan parsed {files} file(s) -- it is not looking at the source tree. "
            "This guard was vacuous for exactly this reason once already."
        )

        unexpected = found - self._SYSTEM_SESSION_CALL_SITES
        assert not unexpected, (
            f"NEW _create_system_session call site(s): {sorted(unexpected)}. "
            "This method creates a session WITHOUT authentication. A new call site is "
            "legitimate only in a background worker that has no human actor and is not "
            "reachable from any request-handling path; if that is what this is, add it to "
            "TestStructuralIsolation._SYSTEM_SESSION_CALL_SITES and say why. If it is in a "
            "route, a dependency or an endpoint module, it is an authentication bypass."
        )

        missing = self._SYSTEM_SESSION_CALL_SITES - found
        assert not missing, (
            f"pinned call site(s) not found by the scan: {sorted(missing)}. Either they were "
            "removed -- in which case update the pin -- or the scan has been narrowed back "
            "to the file that contains none of them, which is the original defect."
        )

    def test_the_call_site_matcher_is_not_vacuous(self):
        """
        THE POSITIVE TWIN, and the direct antidote to `0 <= 1`.

        The defect this guard shipped with was not a wrong threshold, it was a
        matcher that matched nothing. An absence assertion whose matcher is
        broken passes forever. So: show the scanner sources it has never seen,
        each spelling a call site a different way, and require it to find every
        one of them.
        """
        probe = tmp_source_tree = pathlib.Path(__import__("tempfile").mkdtemp(prefix="w129-callsite-"))
        (probe / "worker_one.py").write_text(
            "class W:\n    def run(self):\n        return self.data_access._create_system_session(org)\n",
            encoding="utf-8",
        )
        (probe / "worker_two.py").write_text(
            "class X:\n"
            "    def handle(self):\n"
            "        s = dao._create_system_session(org)\n"
            "        return self._create_system_session(org) or s\n",
            encoding="utf-8",
        )
        (probe / "not_a_call.py").write_text(
            "REFERENCE = 'see DataAccess._create_system_session in the docstring'\n",
            encoding="utf-8",
        )
        try:
            found, files = self._scan_for_system_session_calls(tmp_source_tree)
        finally:
            __import__("shutil").rmtree(tmp_source_tree, ignore_errors=True)

        assert files == 3
        assert found == {
            ("worker_one.py", "W::run"),
            ("worker_two.py", "X::handle"),
        }, f"the matcher missed a call site spelling: {sorted(found)}"

    def test_auditable_session_signature_enforcement(self):
        """
        When @auditable declares requires_session=True, the method must have
        Session as its first parameter (after self).
        """
        source = (pathlib.Path(__file__).resolve().parent.parent / "data_access.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        offenders = []
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "DataAccess"]:
            for node in cls.body:
                if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                    # Find @auditable decorator and check requires_session param
                    for dec in node.decorator_list:
                        if isinstance(dec, ast.Call) and getattr(dec.func, "id", None) == "auditable":
                            # Check if requires_session is explicitly set to False
                            requires_session = True  # default
                            for keyword in dec.keywords:
                                if keyword.arg == "requires_session":
                                    if isinstance(keyword.value, ast.Constant):
                                        requires_session = keyword.value.value
                                    elif isinstance(keyword.value, ast.NameConstant):
                                        requires_session = keyword.value.value

                            if requires_session:
                                # Check if first parameter (after self) is Session
                                if len(node.args.args) < 2:
                                    offenders.append((node.name, "requires_session=True but no first parameter"))
                                elif node.args.args[1].arg != "session":
                                    offenders.append(
                                        (
                                            node.name,
                                            f"requires_session=True but first param is '{node.args.args[1].arg}' not 'session'",
                                        )
                                    )

        assert not offenders, "Method(s) with requires_session=True mismatch:\n  " + "\n  ".join(
            f"{m}: {reason}" for m, reason in offenders
        )
