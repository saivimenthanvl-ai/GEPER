"""
clinical/tests/test_w133_revocation.py
───────────────────────────────────────
w133 — principal credential revocation, and what it does to live sessions.

WHAT THIS SUITE EXISTS TO CATCH, stated first:

    A revocation that flips a boolean and leaves the revoked principal's live
    sessions running.

That version passes "the credential no longer authenticates". It passes
"a different principal is unaffected". It passes the audit-row rows. It looks
exactly like the reviewed house style, because `set_user_disabled` at
`aa37288` WAS that version. The rows that carry the claim are the ones that
hold a session ACROSS the revocation:

    TestTheRevokedCredentialsLiveSessionsAreDead   (here, patient)
    test_w133_staff_revocation.py                  (the staff half, which is
                                                    NOT a copy of this one)

WHAT IS IMPLEMENTED, AND WHAT IS NOT — say it plainly, once, here:

    THIS IS POINT-IN-TIME TERMINATION, NOT CONTINUOUS VALIDATION.
    `set_patient_login_disabled` writes `terminated_at` on that credential's
    live sessions at the moment it runs. Session validation is UNCHANGED:
    `patient_session_valid` still reads one row from `patient_sessions` by
    primary key and still never joins `patient_logins`.

    THE RESIDUE THIS LEAVES: a `disabled` flag set by ANY OTHER ROUTE — direct
    SQL, a restore from backup, a future bootstrap or provisioning path —
    leaves that principal's live sessions untouched and fully valid until
    their own idle or absolute window closes. `TestTheResidueIsReal` below
    PROVES that residue rather than leaving it as prose, so that nobody reads
    this wave as a continuous guarantee. Closing it is a different change
    (a join in session validation) and it was deliberately not made.

RUNNING THESE. A real PostgreSQL, and BOTH variables:

    $env:CLINICAL_TEST_DSN="postgresql://...";  $env:CLINICAL_TEST_DB_DISPOSABLE="1"
    py -3.12 -m pytest clinical/tests/test_w133_revocation.py
"""

from __future__ import annotations

import datetime as dt
import os
import pathlib
import uuid

import pytest

from clinical.data_access import (
    GENERIC_AUTH_ERROR,
    PATIENT_NOT_FOUND,
    AuthenticationError,
    AuthorizationError,
    BcryptHasher,
    DataAccess,
    NotFoundError,
    PatientSession,
    SessionExpired,
)

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"

requires_db = pytest.mark.skipif(
    not DSN, reason="CLINICAL_TEST_DSN not set -- database tests skipped (skip is not pass)"
)

STAFF_PASSWORD = "correct horse battery staple"
PASSWORD = "a sufficiently long patient password"
OTHER_PASSWORD = "a different sufficiently long password"

ADMIN_REQUIRED = "This action requires the Administrator role."


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


def _staff_session(dao, conn, org_id, email, *, roles=("Administrator", "Orderer")):
    """A staff principal with the roles it needs.

    The role rows are inserted directly to break the bootstrap cycle, exactly
    as test_identity.py's admin_session and test_patient_identity.py's
    _staff_session already do. THE SESSION ITSELF IS REAL: it comes back from
    `dao.login`, never from a hand-built `Session`.
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
def staff_a(dao, conn, org_a):
    """Org A's Administrator. Also an Auditor, so the audit rows can be read
    back through `read_audit` rather than by hand."""
    return _staff_session(dao, conn, org_a, "admin@a.example", roles=("Administrator", "Orderer", "Auditor"))


@pytest.fixture()
def staff_b(dao, conn, org_b):
    return _staff_session(dao, conn, org_b, "admin@b.example", roles=("Administrator", "Orderer", "Auditor"))


@pytest.fixture()
def clerk_a(dao, conn, org_a):
    """An authenticated staff principal in org A who is NOT an Administrator."""
    return _staff_session(dao, conn, org_a, "clerk@a.example", roles=("Orderer",))


@pytest.fixture()
def patient_a(dao, staff_a):
    return dao.create_patient(staff_a, "Alice Anderson", dt.date(1980, 1, 1), "F")


@pytest.fixture()
def patient_a2(dao, staff_a):
    """Bob. A DIFFERENT, REAL patient in the SAME organisation as Alice."""
    return dao.create_patient(staff_a, "Bob Brown", dt.date(1975, 6, 15), "M")


@pytest.fixture()
def patient_b(dao, staff_b):
    return dao.create_patient(staff_b, "Carol Clark", dt.date(1990, 3, 3), "F")


@pytest.fixture()
def alice_login(dao, staff_a, patient_a):
    """Alice's credential id, issued through the real enrolment method."""
    return dao.enrol_patient_login(staff_a, patient_a, "alice@portal.example", PASSWORD)


@pytest.fixture()
def bob_login(dao, staff_a, patient_a2):
    return dao.enrol_patient_login(staff_a, patient_a2, "bob@portal.example", OTHER_PASSWORD)


@pytest.fixture()
def carol_login(dao, staff_b, patient_b):
    return dao.enrol_patient_login(staff_b, patient_b, "carol@portal.example", PASSWORD)


def _audit_rows(conn, action):
    """(resource_id, outcome, org_id, user_id) for one action, oldest first.

    Read directly because `read_audit` returns neither `resource_id` nor
    `outcome`, and those two columns are the w120 property this wave must not
    break. The house pattern: test_w120_audit_resource_id.py::_resource_ids.
    Rule 2a is not in tension with this — the METHOD UNDER TEST is the
    revocation, which every row below calls; this only reads what it wrote.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT resource_id, outcome, org_id, user_id, resource_type FROM audit_log "
            'WHERE action = %s ORDER BY "timestamp", log_id',
            (action,),
        )
        return list(cur.fetchall())


# ═══════════════════════════════════════════════════════════════════════════
# PATIENT — the credential half
# ═══════════════════════════════════════════════════════════════════════════


@requires_db
class TestTheRevokedCredentialNoLongerAuthenticates:
    def test_r1_a_revoked_credential_is_refused_at_login(self, dao, staff_a, org_a, alice_login):
        dao.set_patient_login_disabled(staff_a, alice_login, True)
        with pytest.raises(AuthenticationError) as exc:
            dao.patient_login("alice@portal.example", org_a, PASSWORD)
        assert str(exc.value) == GENERIC_AUTH_ERROR

    def test_r1t_the_positive_twin_it_authenticated_immediately_before(
        self, dao, staff_a, org_a, patient_a, alice_login
    ):
        """Rule 4. Without this the refusal above is satisfied by a credential
        that never worked -- a typo in the enrolment email refuses just as
        convincingly."""
        session = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        assert session.patient_id == patient_a
        dao.set_patient_login_disabled(staff_a, alice_login, True)
        with pytest.raises(AuthenticationError):
            dao.patient_login("alice@portal.example", org_a, PASSWORD)

    def test_r8_re_enabling_restores_authentication(self, dao, staff_a, org_a, patient_a, alice_login):
        """The boolean parameter is honoured and not hardcoded."""
        dao.set_patient_login_disabled(staff_a, alice_login, True)
        dao.set_patient_login_disabled(staff_a, alice_login, False)
        session = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        assert session.patient_id == patient_a


@requires_db
class TestWhoMayRevoke:
    def test_r2_a_non_administrator_in_the_same_org_is_refused(self, dao, clerk_a, alice_login):
        with pytest.raises(AuthorizationError) as exc:
            dao.set_patient_login_disabled(clerk_a, alice_login, True)
        assert str(exc.value) == ADMIN_REQUIRED

    def test_r2t_the_positive_twin_the_credential_still_authenticates_after_that_refusal(
        self, dao, clerk_a, org_a, patient_a, alice_login
    ):
        with pytest.raises(AuthorizationError):
            dao.set_patient_login_disabled(clerk_a, alice_login, True)
        assert dao.patient_login("alice@portal.example", org_a, PASSWORD).patient_id == patient_a

    def test_r3_an_administrator_of_another_org_is_refused_by_id(self, dao, staff_b, carol_login, alice_login):
        """Org B's Administrator naming org A's credential id.

        EQUALITY against the module constant, so an f-string that names the id
        -- which is what `set_user_disabled` does -- fails this row.
        """
        with pytest.raises(NotFoundError) as exc:
            dao.set_patient_login_disabled(staff_b, alice_login, True)
        assert str(exc.value) == PATIENT_NOT_FOUND

    def test_r3t_the_positive_twin_org_as_credential_still_authenticates(
        self, dao, staff_b, org_a, patient_a, alice_login
    ):
        with pytest.raises(NotFoundError):
            dao.set_patient_login_disabled(staff_b, alice_login, True)
        assert dao.patient_login("alice@portal.example", org_a, PASSWORD).patient_id == patient_a

    def test_r3t2_the_positive_twin_org_bs_own_credential_can_be_revoked(
        self, dao, staff_b, org_b, carol_login, alice_login
    ):
        """The SECOND positive twin, and the one that matters: without it, a
        method that raises NotFoundError for EVERY target satisfies R3."""
        dao.set_patient_login_disabled(staff_b, carol_login, True)
        with pytest.raises(AuthenticationError):
            dao.patient_login("carol@portal.example", org_b, PASSWORD)

    def test_r4_the_three_identifier_shaped_refusals_are_one_set(self, dao, staff_a, alice_login, carol_login):
        """Rule 8: both channels, as a SET OF SIZE ONE.

        The three identifier-shaped refusals a legitimate Administrator can
        provoke: an id from another organisation, an id that exists nowhere,
        and a well-formed invented id. The ROLE refusal is deliberately NOT in
        this set -- it answers a different question to an authenticated staff
        caller and must stay distinguishable.
        """
        seen = set()
        for target in (carol_login, uuid.uuid4(), uuid.uuid4()):
            with pytest.raises(Exception) as exc:
                dao.set_patient_login_disabled(staff_a, target, True)
            seen.add((type(exc.value).__name__, str(exc.value)))
        assert seen == {("NotFoundError", PATIENT_NOT_FOUND)}
        assert len(seen) == 1

    def test_r16_a_patient_session_cannot_revoke(self, dao, staff_a, org_a, patient_a, alice_login):
        """w130 decision 7, inherited free from the decorator -- and pinned, so
        that nobody reaches for requires_session=False to work around it."""
        patient_session = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        assert isinstance(patient_session, PatientSession)
        with pytest.raises(AuthorizationError) as exc:
            dao.set_patient_login_disabled(patient_session, alice_login, True)
        assert "does not accept a patient session" in str(exc.value)
        # [T] and the credential still authenticates afterwards
        assert dao.patient_login("alice@portal.example", org_a, PASSWORD).patient_id == patient_a


@requires_db
class TestTheRevokedCredentialsLiveSessionsAreDead:
    """
    THE SIX ROWS THAT CARRY THE WAVE. Everything above is satisfied by a
    revocation that does nothing to sessions.
    """

    def test_r5_the_live_session_of_the_revoked_credential_is_refused(
        self, dao, staff_a, org_a, patient_a, alice_login
    ):
        session = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        # Validated IMMEDIATELY BEFORE, so the refusal below cannot be a
        # session that was never valid.
        assert dao.patient_session_valid(session.session_id).patient_id == patient_a

        dao.set_patient_login_disabled(staff_a, alice_login, True)

        with pytest.raises(SessionExpired) as exc:
            dao.patient_session_valid(session.session_id)
        assert str(exc.value) == GENERIC_AUTH_ERROR

    def test_r5t_a_different_patients_live_session_in_the_same_org_still_validates(
        self, dao, staff_a, org_a, patient_a2, alice_login, bob_login
    ):
        """
        THE ROW THAT DOES TWO OPPOSITE JOBS, and the reason it is not trusted
        alone.

        It is VACUOUS against a revocation that terminates NOTHING -- Bob's
        session works whether or not Alice's was ended -- and it is the ONLY
        row that catches a revocation that terminates EVERY session in the
        organisation. One assertion, vacuous against one failure and the whole
        defence against the opposite one.

        Its pair is `test_r5_...` directly above, which fails under the
        terminates-nothing version. NEITHER ROW MAY BE DELETED WITHOUT THE
        OTHER: together they pin the statement to exactly one credential.
        """
        dao.patient_login("alice@portal.example", org_a, PASSWORD)
        bob = dao.patient_login("bob@portal.example", org_a, OTHER_PASSWORD)

        dao.set_patient_login_disabled(staff_a, alice_login, True)

        still = dao.patient_session_valid(bob.session_id)
        # CONTENT, naming Bob. A bare "does not raise" would be satisfied by a
        # method that returned some other patient's session.
        assert still.patient_id == patient_a2
        assert still.patient_login_id == bob_login
        assert still.session_id == bob.session_id

    def test_r6_every_device_the_credential_holds_is_ended_not_just_one(self, dao, staff_a, org_a, alice_login):
        """Keyed on the CREDENTIAL, which is the statement w132 deliberately
        refused for LOGOUT. Logout is self-scoped and takes no target, so
        keying it on the credential would sign a patient out of every device
        they have. Revocation is the one operation where that key is correct:
        the credential is what is being withdrawn, so every session it minted
        must end.
        """
        phone = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        laptop = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        assert phone.session_id != laptop.session_id
        assert dao.patient_session_valid(phone.session_id).session_id == phone.session_id
        assert dao.patient_session_valid(laptop.session_id).session_id == laptop.session_id

        dao.set_patient_login_disabled(staff_a, alice_login, True)

        for ended in (phone, laptop):
            with pytest.raises(SessionExpired) as exc:
                dao.patient_session_valid(ended.session_id)
            assert str(exc.value) == GENERIC_AUTH_ERROR

    def test_r7_revoking_twice_keeps_the_first_instant(self, dao, conn, clock, staff_a, org_a, alice_login):
        """`terminated_at IS NULL` in the predicate: a second call is a no-op,
        not a rewrite. The recorded moment a session ended must be the first
        one. CONTENT -- the stored stamp, not 'it did not raise'."""
        session = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        first = clock.now()
        dao.set_patient_login_disabled(staff_a, alice_login, True)
        clock.advance(minutes=7)
        assert clock.now() != first
        dao.set_patient_login_disabled(staff_a, alice_login, True)

        with conn.cursor() as cur:
            cur.execute("SELECT terminated_at FROM patient_sessions WHERE session_id = %s", (session.session_id,))
            stored = cur.fetchone()[0]
        assert stored == first

    def test_r8t_re_enabling_does_not_resurrect_the_terminated_session(
        self, dao, staff_a, org_a, patient_a, alice_login
    ):
        session = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        dao.set_patient_login_disabled(staff_a, alice_login, True)
        dao.set_patient_login_disabled(staff_a, alice_login, False)

        with pytest.raises(SessionExpired):
            dao.patient_session_valid(session.session_id)
        # [T] but a NEW authentication works -- so the re-enable really happened
        assert dao.patient_login("alice@portal.example", org_a, PASSWORD).patient_id == patient_a

    def test_re_enabling_does_not_terminate_a_session_opened_since(self, dao, staff_a, org_a, patient_a, alice_login):
        """Termination is conditional on `disabled` being truthy. A version
        that terminates unconditionally would sign the patient out on the very
        call that restored their access."""
        dao.set_patient_login_disabled(staff_a, alice_login, True)
        dao.set_patient_login_disabled(staff_a, alice_login, False)
        fresh = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        dao.set_patient_login_disabled(staff_a, alice_login, False)
        assert dao.patient_session_valid(fresh.session_id).patient_id == patient_a


@requires_db
class TestRevocationDoesNotReachAnotherOrganisation:
    def test_a_revocation_in_org_a_leaves_org_bs_sessions_alone(
        self, dao, staff_a, org_a, org_b, patient_b, alice_login, carol_login
    ):
        carol = dao.patient_login("carol@portal.example", org_b, PASSWORD)
        dao.patient_login("alice@portal.example", org_a, PASSWORD)

        dao.set_patient_login_disabled(staff_a, alice_login, True)

        still = dao.patient_session_valid(carol.session_id)
        assert still.patient_id == patient_b
        assert still.patient_login_id == carol_login


@requires_db
class TestTheAuditRow:
    def test_r9_the_success_row_names_the_credential(self, dao, conn, staff_a, org_a, alice_login):
        dao.set_patient_login_disabled(staff_a, alice_login, True)
        rows = _audit_rows(conn, "patient_login_disabled")
        assert len(rows) == 1
        resource_id, outcome, org_id, user_id, resource_type = rows[0]
        assert resource_id == str(alice_login)  # NOT "<none>" -- the w120 property
        assert outcome == "success"
        assert resource_type == "patient_login"
        assert org_id == org_a
        assert user_id == staff_a.user_id

    def test_the_enable_row_is_a_different_action(self, dao, conn, staff_a, alice_login):
        dao.set_patient_login_disabled(staff_a, alice_login, True)
        dao.set_patient_login_disabled(staff_a, alice_login, False)
        assert len(_audit_rows(conn, "patient_login_disabled")) == 1
        enabled = _audit_rows(conn, "patient_login_enabled")
        assert len(enabled) == 1
        assert enabled[0][0] == str(alice_login)
        assert enabled[0][1] == "success"

    def test_r10_the_denied_row_is_written(self, dao, conn, clerk_a, alice_login):
        with pytest.raises(AuthorizationError):
            dao.set_patient_login_disabled(clerk_a, alice_login, True)
        rows = _audit_rows(conn, "patient_login_disabled")
        assert len(rows) == 1
        assert rows[0][0] == "<denied>"
        assert rows[0][1] == "denied"

    def test_r11_the_cross_org_attempt_is_visible_in_the_actors_org_and_not_the_targets(
        self, dao, staff_a, staff_b, alice_login, carol_login
    ):
        """Content, both directions, through `read_audit` -- the real
        Auditor-gated reader, org-scoped."""
        with pytest.raises(NotFoundError):
            dao.set_patient_login_disabled(staff_b, alice_login, True)

        actions = ("patient_login_disabled", "patient_login_enabled")
        in_target_org = dao.read_audit(staff_a, actions=actions)
        in_actor_org = dao.read_audit(staff_b, actions=actions)

        assert in_target_org == []
        assert len(in_actor_org) == 1
        # index 3 is `action` in read_audit's SELECT list
        assert in_actor_org[0][3] == "patient_login_disabled"
        assert in_actor_org[0][2] == staff_b.user_id


@requires_db
class TestAtomicity:
    """
    Wrong version F: the audit row commits while the credential / session
    transaction fails.

    `@auditable` commits after EVERY audit row it writes. A revocation
    assembled out of two decorated calls would therefore leave the first
    call's SUCCESS row committed when the second failed, and the audit would
    record a revocation that did not happen. One method, one body, one
    transaction -- and this is the third wave in which that lesson has had to
    be pinned.
    """

    def test_r12_a_failure_inside_the_body_leaves_no_success_row_and_no_revocation(
        self, dao, conn, monkeypatch, staff_a, org_a, patient_a, alice_login
    ):
        session = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        real_execute = dao._execute
        calls = {"n": 0}

        def failing_execute(sql, params=()):
            # Let the credential UPDATE through, then break the session
            # termination -- the exact seam a two-call composition would have.
            if "UPDATE patient_sessions" in sql:
                calls["n"] += 1
                raise RuntimeError("forced failure inside the revocation body")
            return real_execute(sql, params)

        monkeypatch.setattr(dao, "_execute", failing_execute)
        with pytest.raises(RuntimeError):
            dao.set_patient_login_disabled(staff_a, alice_login, True)
        monkeypatch.undo()

        assert calls["n"] == 1, "the session-termination statement was never reached"

        # NO success audit row. (An 'error' row is expected and correct: the
        # decorator records the attempt. What must not exist is a row saying
        # the revocation succeeded.)
        assert [r for r in _audit_rows(conn, "patient_login_disabled") if r[1] == "success"] == []

        # AND the credential still authenticates -- the write was rolled back.
        assert dao.patient_login("alice@portal.example", org_a, PASSWORD).patient_id == patient_a
        # AND the session that was live before is still live.
        assert dao.patient_session_valid(session.session_id).patient_id == patient_a

    def test_r12t_the_positive_twin_on_success_the_audit_row_IS_written(self, dao, conn, staff_a, org_a, alice_login):
        """Rule 4. Without this, R12 is satisfied by a method that never writes
        an audit row at all."""
        dao.set_patient_login_disabled(staff_a, alice_login, True)
        success = [r for r in _audit_rows(conn, "patient_login_disabled") if r[1] == "success"]
        assert len(success) == 1
        assert success[0][0] == str(alice_login)


@requires_db
class TestTheW132LogoutPropertyIsNotCollateralDamage:
    def test_r17_patient_logout_still_ends_exactly_one_session(self, dao, org_a, staff_a, alice_login):
        phone = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        laptop = dao.patient_login("alice@portal.example", org_a, PASSWORD)

        dao.terminate_my_patient_session(phone)

        with pytest.raises(SessionExpired):
            dao.patient_session_valid(phone.session_id)
        assert dao.patient_session_valid(laptop.session_id).session_id == laptop.session_id


# ===========================================================================
# THE RESIDUE -- proved, not promised
# ===========================================================================


@requires_db
class TestTheResidueIsReal:
    """
    POINT-IN-TIME, NOT CONTINUOUS. This row exists so that nobody reads this
    wave as a guarantee it does not make, and so that the day somebody DOES
    close the residue -- by joining the credential row in session validation
    -- it fails loudly and is deleted deliberately rather than quietly
    outliving the decision it records.
    """

    def test_a_disabled_flag_set_by_any_other_route_leaves_live_sessions_running(
        self, dao, conn, org_a, patient_a, alice_login
    ):
        session = dao.patient_login("alice@portal.example", org_a, PASSWORD)
        # NOT through the method. This is the residue: direct SQL, a restore, a
        # future bootstrap. patient_session_valid does not read patient_logins.
        with conn.cursor() as cur:
            cur.execute("UPDATE patient_logins SET disabled = TRUE WHERE patient_login_id = %s", (alice_login,))
        conn.commit()

        assert dao.patient_session_valid(session.session_id).patient_id == patient_a, (
            "If this now RAISES, patient session validation has been taught to read the credential "
            "row. That is the CONTINUOUS version and it closes the residue this wave left open. "
            "Delete this row deliberately and say so -- do not 'fix' it."
        )
        # and the next authentication IS refused, which is the half that has
        # always worked
        with pytest.raises(AuthenticationError):
            dao.patient_login("alice@portal.example", org_a, PASSWORD)
