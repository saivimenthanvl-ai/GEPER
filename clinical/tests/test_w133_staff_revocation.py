"""
clinical/tests/test_w133_staff_revocation.py
─────────────────────────────────────────────
w133 — the staff half of the same ruling, AND IT IS NOT A COPY OF THE PATIENT
HALF.

THE GAP THIS CLOSES, measured at `aa37288` before the change:

    `set_user_disabled` wrote one row in `users`. `session_valid` read only
    `sessions`. `_require_role` read only `role_assignments`. NO CODE ANYWHERE
    consulted `users.disabled` after a session existed, and NO TEST in the
    repository held a session across a disable -- so a staff user disabled at
    10:00 passed validation at 10:01 and kept every Administrator-gated
    capability in the system, including disabling somebody else.

    That is not a reconstruction. The two rows in
    TestTheDisabledStaffSessionCannotPerformARoleGatedOperation below failed
    with "DID NOT RAISE" against the unmodified `aa37288` method, which is the
    runtime confirmation the w133 audit could state from the code but could
    not run.

WHY VALIDATION IS NOT THE WHOLE CLAIM ON THIS SIDE. For a patient, refusing
the session is the end of it: every portal read binds the patient from the
session. For staff, ROLE RESOLUTION IS A SEPARATE READ -- `_require_role`
consults `role_assignments` and has never consulted `users.disabled`, and
still does not. So "validation refuses it" and "it can no longer act" are two
different claims, and the second one is the one that matters. These rows make
a REAL Administrator-gated call through the terminated session's own request
path and assert ON CONTENT that the privileged act did not happen.

POINT-IN-TIME, NOT CONTINUOUS -- the same statement the patient file makes,
and the residue is the same: `session_valid` still reads one row from
`sessions` by primary key and never joins `users`. See
test_w133_revocation.py::TestTheResidueIsReal and TestTheResidueIsReal below.

    $env:CLINICAL_TEST_DSN="postgresql://...";  $env:CLINICAL_TEST_DB_DISPOSABLE="1"
    py -3.12 -m pytest clinical/tests/test_w133_staff_revocation.py
"""

from __future__ import annotations

import datetime as dt
import os
import pathlib

import pytest

from clinical.data_access import (
    GENERIC_AUTH_ERROR,
    AuthenticationError,
    BcryptHasher,
    DataAccess,
    SessionExpired,
)

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"

requires_db = pytest.mark.skipif(
    not DSN, reason="CLINICAL_TEST_DSN not set -- database tests skipped (skip is not pass)"
)

STAFF_PASSWORD = "correct horse battery staple"


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


def _staff_session(dao, conn, org_id, email, *, roles=("Administrator",)):
    """A staff principal with the roles it needs.

    The role rows are inserted directly to break the bootstrap cycle, exactly
    as test_identity.py's admin_session already does. THE SESSION ITSELF IS
    REAL: it comes back from `dao.login`, never from a hand-built `Session`,
    because a hand-built one would prove nothing about what a request holds.
    """
    user_id = dao.create_user(org_id, email, STAFF_PASSWORD)
    if roles:
        with conn.cursor() as cur:
            for role in roles:
                cur.execute(
                    "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (user_id, org_id, role, user_id, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
                )
    return dao.login(email, org_id, STAFF_PASSWORD)


@pytest.fixture()
def admin_a(dao, conn, org_a):
    """The acting Administrator -- the one who performs the offboarding.

    w162: "Orderer" joins the pair because this session registers the patient
    whose credential `test_a_terminated_administrator_cannot_revoke_a_patient_credential`
    acts on, and registration is now the ordering clinician's (human ruling
    2026-09-19). Roles are additive and nothing here is relaxed: every claim
    in this file is about a session ENDED by offboarding, and `victim` still
    holds Administrator alone.
    """
    return _staff_session(dao, conn, org_a, "admin@a.example", roles=("Administrator", "Auditor", "Orderer"))


@pytest.fixture()
def admin_b(dao, conn, org_b):
    return _staff_session(dao, conn, org_b, "admin@b.example", roles=("Administrator", "Auditor"))


@pytest.fixture()
def victim(dao, conn, org_a):
    """The user being offboarded. An ADMINISTRATOR on purpose: the sharpest
    version of the gap is a disabled Administrator who can still administer."""
    return _staff_session(dao, conn, org_a, "victim@a.example", roles=("Administrator",))


@pytest.fixture()
def bystander(dao, conn, org_a):
    """A DIFFERENT, REAL user in the SAME organisation. A cross-organisation
    bystander would prove nothing: the org predicate already refuses that."""
    return _staff_session(dao, conn, org_a, "bystander@a.example", roles=("Orderer",))


def _act_as_a_request_would(dao, session_id):
    """
    Re-derive the Session from its id, exactly as `_get_session` does
    (clinical/endpoints.py:330 -- `return dao.session_valid(session_id)`).

    THIS FUNCTION IS THE POINT OF THIS FILE. At the data layer a `Session` is
    a dataclass and nothing re-reads it: `_require_role` resolves roles from
    `role_assignments` and NEVER consults `users.disabled` -- true at
    `aa37288`, and STILL TRUE after this wave, which does not change role
    resolution. So handing `assign_role` a stale Session OBJECT would still
    succeed, and a test that did so would be testing something no request can
    do. What a real request holds is a Session that `session_valid` produced
    THIS REQUEST, and that is the only gate there is. Every staff row below
    goes through here.
    """
    return dao.session_valid(session_id)


@requires_db
class TestStaffRevocationReachesLiveSessions:
    def test_s1_the_disabled_users_live_session_is_refused(self, dao, admin_a, victim):
        # Validated IMMEDIATELY BEFORE, so the refusal below cannot be a
        # session that was never valid.
        assert dao.session_valid(victim.session_id).user_id == victim.user_id

        dao.set_user_disabled(admin_a, victim.user_id, True)

        with pytest.raises(SessionExpired) as exc:
            dao.session_valid(victim.session_id)
        assert str(exc.value) == GENERIC_AUTH_ERROR

    def test_s2_a_different_users_live_session_in_the_same_org_still_validates(
        self, dao, admin_a, org_a, victim, bystander
    ):
        """
        THE ROW THAT DOES TWO OPPOSITE JOBS.

        It is VACUOUS against a disable that terminates NOTHING -- the
        bystander's session works either way -- and it is the ONLY row that
        catches a disable that terminates EVERY session in the organisation.
        Its pair is `test_s1_...` directly above, which fails under the
        terminates-nothing version. Neither may be deleted without the other:
        together they pin the statement to exactly one user.
        """
        dao.set_user_disabled(admin_a, victim.user_id, True)

        still = dao.session_valid(bystander.session_id)
        # CONTENT, naming the bystander. A bare "does not raise" would be
        # satisfied by a method that returned somebody else's session.
        assert still.user_id == bystander.user_id
        assert still.session_id == bystander.session_id
        assert still.org_id == org_a

    def test_the_acting_administrators_own_session_survives(self, dao, admin_a, victim):
        dao.set_user_disabled(admin_a, victim.user_id, True)
        assert dao.session_valid(admin_a.session_id).user_id == admin_a.user_id

    def test_a_disable_in_org_a_leaves_org_bs_sessions_alone(self, dao, admin_a, admin_b, victim):
        dao.set_user_disabled(admin_a, victim.user_id, True)
        assert dao.session_valid(admin_b.session_id).user_id == admin_b.user_id

    def test_every_session_the_user_holds_is_ended_not_just_the_newest(self, dao, org_a, admin_a, victim):
        """Keyed on user_id, so a user logged in on two machines loses both.
        The termination is the point of an offboarding; leaving one device
        alive is the defect, not a lesser version of the fix."""
        second = dao.login("victim@a.example", org_a, STAFF_PASSWORD)
        assert second.session_id != victim.session_id

        dao.set_user_disabled(admin_a, victim.user_id, True)

        for ended in (victim, second):
            with pytest.raises(SessionExpired) as exc:
                dao.session_valid(ended.session_id)
            assert str(exc.value) == GENERIC_AUTH_ERROR

    def test_re_enabling_does_not_resurrect_the_terminated_session(self, dao, org_a, admin_a, victim):
        dao.set_user_disabled(admin_a, victim.user_id, True)
        dao.set_user_disabled(admin_a, victim.user_id, False)
        with pytest.raises(SessionExpired):
            dao.session_valid(victim.session_id)
        # [T] but a NEW login works, so the re-enable really happened
        assert dao.login("victim@a.example", org_a, STAFF_PASSWORD).user_id == victim.user_id

    def test_re_enabling_does_not_terminate_a_session_opened_since(self, dao, org_a, admin_a, victim):
        """Termination is conditional on `disabled` being truthy. A version
        that terminates unconditionally would sign the user out on the very
        call that restored their access."""
        dao.set_user_disabled(admin_a, victim.user_id, True)
        dao.set_user_disabled(admin_a, victim.user_id, False)
        fresh = dao.login("victim@a.example", org_a, STAFF_PASSWORD)
        dao.set_user_disabled(admin_a, victim.user_id, False)
        assert dao.session_valid(fresh.session_id).user_id == victim.user_id

    def test_disabling_twice_keeps_the_first_instant(self, dao, conn, clock, admin_a, victim):
        """`terminated_at IS NULL` in the predicate: a second call is a no-op,
        not a rewrite. CONTENT -- the stored stamp."""
        first = clock.now()
        dao.set_user_disabled(admin_a, victim.user_id, True)
        clock.advance(minutes=11)
        assert clock.now() != first
        dao.set_user_disabled(admin_a, victim.user_id, True)
        with conn.cursor() as cur:
            cur.execute("SELECT terminated_at FROM sessions WHERE session_id = %s", (victim.session_id,))
            assert cur.fetchone()[0] == first

    def test_the_terminator_recorded_is_the_acting_administrator(self, dao, conn, admin_a, victim):
        """`terminated_by` names the ACTOR, consistent with terminate_session.
        Expressible without a schema change only because `terminated_by`
        carries no foreign key on either session table."""
        dao.set_user_disabled(admin_a, victim.user_id, True)
        with conn.cursor() as cur:
            cur.execute("SELECT terminated_by FROM sessions WHERE session_id = %s", (victim.session_id,))
            assert cur.fetchone()[0] == admin_a.user_id


@requires_db
class TestTheDisabledStaffSessionCannotPerformARoleGatedOperation:
    """
    THE ROWS THE PATIENT HALF DOES NOT HAVE. See the module docstring: on the
    staff side, refusing validation and removing capability are two claims.
    """

    def test_a_terminated_administrators_session_cannot_assign_a_role(self, dao, conn, org_a, admin_a, victim):
        target = dao.create_user(org_a, "target@a.example", STAFF_PASSWORD)

        # [T] THE POSITIVE TWIN FIRST: the very same Administrator-gated call,
        # through the very same request path, SUCCEEDS while the user is
        # enabled -- so the refusal below cannot be a call that never worked.
        live = _act_as_a_request_would(dao, victim.session_id)
        dao.assign_role(live, target, "Orderer")
        assert {a.role for a in dao.get_user_roles(live, target)} == {"Orderer"}

        dao.set_user_disabled(admin_a, victim.user_id, True)

        with pytest.raises(SessionExpired) as exc:
            session = _act_as_a_request_would(dao, victim.session_id)
            dao.assign_role(session, target, "Interpreter")
        assert str(exc.value) == GENERIC_AUTH_ERROR

        # CONTENT: the role was NOT granted. A bare "it raised" would be
        # satisfied by a raise that happened AFTER the write.
        with conn.cursor() as cur:
            cur.execute(
                "SELECT role FROM role_assignments WHERE org_id = %s AND user_id = %s AND revoked_at IS NULL",
                (org_a, target),
            )
            roles = {r[0] for r in cur.fetchall()}
        assert roles == {"Orderer"}, "the Interpreter grant must not have happened"

    def test_a_terminated_administrator_cannot_disable_somebody_else(
        self, dao, conn, org_a, admin_a, victim, bystander
    ):
        """The sharpest case: a disabled Administrator disabling the people
        who might disable them."""
        # [T] THE POSITIVE TWIN FIRST, on a throwaway third user: the victim's
        # session really does hold this capability while they are enabled, so
        # the refusal below cannot be a call that never worked.
        spare = _staff_session(dao, conn, org_a, "spare@a.example", roles=("Orderer",))
        live = _act_as_a_request_would(dao, victim.session_id)
        dao.set_user_disabled(live, spare.user_id, True)
        with pytest.raises(AuthenticationError):
            dao.login("spare@a.example", org_a, STAFF_PASSWORD)

        dao.set_user_disabled(admin_a, victim.user_id, True)

        with pytest.raises(SessionExpired):
            session = _act_as_a_request_would(dao, victim.session_id)
            dao.set_user_disabled(session, bystander.user_id, True)

        # CONTENT: the bystander is untouched, validates, and still
        # authenticates.
        assert dao.session_valid(bystander.session_id).user_id == bystander.user_id
        assert dao.login("bystander@a.example", org_a, STAFF_PASSWORD).user_id == bystander.user_id

    def test_a_terminated_administrator_cannot_revoke_a_patient_credential(self, dao, org_a, admin_a, victim):
        """The two halves of this wave meet here: the staff capability added in
        commit 1 is itself gated by the session the offboarding just ended."""
        patient_id = dao.create_patient(admin_a, "Alice Anderson", dt.date(1980, 1, 1), "F")
        login_id = dao.enrol_patient_login(admin_a, patient_id, "alice@portal.example", "a long portal password")

        dao.set_user_disabled(admin_a, victim.user_id, True)

        with pytest.raises(SessionExpired):
            session = _act_as_a_request_would(dao, victim.session_id)
            dao.set_patient_login_disabled(session, login_id, True)

        # CONTENT: the patient credential still authenticates.
        assert dao.patient_login("alice@portal.example", org_a, "a long portal password").patient_id == patient_id


@requires_db
class TestTheStaffAuditRowIsUnchanged:
    """The disable's audit vocabulary is not this wave's to change: the
    action strings, the resource_id and the outcome must be exactly what
    test_w120_audit_resource_id.py already pins."""

    def test_the_success_row_still_names_the_target_user(self, dao, conn, org_a, admin_a, victim):
        dao.set_user_disabled(admin_a, victim.user_id, True)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT resource_id, outcome, org_id, user_id FROM audit_log WHERE action = %s",
                ("user_disabled",),
            )
            rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0] == (str(victim.user_id), "success", org_a, admin_a.user_id)


@requires_db
class TestTheResidueIsReal:
    """
    POINT-IN-TIME, NOT CONTINUOUS. This row exists so that nobody reads this
    wave as a guarantee it does not make, and so that the day somebody DOES
    close the residue -- by joining `users` in `session_valid` -- it fails
    loudly and is deleted deliberately rather than quietly outliving the
    decision it records.
    """

    def test_a_disabled_flag_set_by_any_other_route_leaves_live_sessions_running(self, dao, conn, org_a, victim):
        # NOT through the method. This is the residue: direct SQL, a restore, a
        # future bootstrap. session_valid does not read `users` at all.
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET disabled = TRUE WHERE user_id = %s", (victim.user_id,))
        conn.commit()

        assert dao.session_valid(victim.session_id).user_id == victim.user_id, (
            "If this now RAISES, session validation has been taught to read the principal row. "
            "That is the CONTINUOUS version and it closes the residue this wave left open. "
            "Delete this row deliberately and say so -- do not 'fix' it."
        )
        # and the next authentication IS refused, which is the half that has
        # always worked
        with pytest.raises(AuthenticationError):
            dao.login("victim@a.example", org_a, STAFF_PASSWORD)
