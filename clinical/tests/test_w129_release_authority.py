"""
clinical/tests/test_w129_release_authority.py
─────────────────────────────────────────────

w129 phase B item 5: release, the release gate and amendment check that the
actor EXISTS, not that the actor is PERMITTED.

`_approve_report` already carries the stronger pattern, twenty lines of whose
docstring exist to explain why checking the recorded actor's role as well as
the session's is necessary (clinical/data_access.py, ISO 15189 7.4.1.5 c)).
`_release_report` does the identity half -- "SELECT 1 FROM users WHERE org_id
= %s AND user_id = %s" -- and omits the authority half entirely.
`require_release` and `create_amendment` do neither.

EVERY NEGATIVE HERE USES AN AUTHENTICATED ACTOR WHO EXISTS AND LACKS THE
PERMISSION. That is the only case that distinguishes "checks existence" from
"checks authority": a test passing a nonexistent user id proves nothing about
this fix, because the pre-fix code already raises NotFoundError for one.

Every absence assertion (no release_events row, report state unmoved, no
amendments row) is paired with a positive twin in the same class that the
broken state fails -- Rule 4. A refusal test that only counts rows is
satisfiable by a method that raises for the wrong reason.

The role this wave attaches to release is Approver, and it is read off the
code rather than invented: the ruling gives Approver "review/approval", every
one of these three operations acts only on an already-approved report, and
`_approve_report` is the sibling in the same file that already names that
role. No new role, no releaser concept, no second mechanism -- `_require_role`
and the session model that nine other call sites already use.
"""

from __future__ import annotations

import datetime
from datetime import date, timezone
import json
import os
import uuid

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

_CREATE_ROLE = "DO $$ BEGIN CREATE ROLE clinical_app; EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
_CREATE_ROLE_RETENTION = (
    "DO $$ BEGIN CREATE ROLE clinical_retention; EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
)


@pytest.fixture()
def conn():
    psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")
    if not DSN:
        pytest.skip("CLINICAL_TEST_DSN not set")
    connection = psycopg.connect(DSN, autocommit=False, connect_timeout=10)
    with connection.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        cur.execute(_CREATE_ROLE)
        cur.execute(_CREATE_ROLE_RETENTION)
        cur.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture
def dao(conn):
    return DataAccess(conn, clock=SystemClock(), password_hasher=BcryptHasher(rounds=4))


@pytest.fixture
def org_a(dao):
    return dao.create_organisation("Org A")


@pytest.fixture
def org_b(dao):
    return dao.create_organisation("Org B")


def _admin_session(dao, conn, org_id, email):
    user_id = dao.create_user(org_id, email, "password")
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Administrator', %s, %s)",
            (user_id, org_id, user_id, datetime.datetime(2026, 9, 1, tzinfo=timezone.utc)),
        )
    conn.commit()
    return dao.login(email, org_id, "password")


@pytest.fixture
def session_a(dao, org_a, conn):
    """An Administrator in org A. Authenticated, real, and NOT an Approver."""
    return _admin_session(dao, conn, org_a, "admin@org-a.test")


@pytest.fixture
def session_b(dao, org_b, conn):
    return _admin_session(dao, conn, org_b, "admin@org-b.test")


def _role_session(dao, admin_session, org_id, email, role):
    user_id = dao.create_user(org_id, email, "password")
    dao.assign_role(admin_session, user_id, role, basis=f"w129 test fixture: {role}")
    return dao.login(email, org_id, "password")


@pytest.fixture
def approver_a(dao, session_a, org_a):
    return _role_session(dao, session_a, org_a, "approver@org-a.test", "Approver")


@pytest.fixture
def approver_b(dao, session_b, org_b):
    return _role_session(dao, session_b, org_b, "approver@org-b.test", "Approver")


@pytest.fixture
def interpreter_a(dao, session_a, org_a):
    """
    An authenticated org-A user holding a REAL role that is not Approver.
    This is the wrong-role-right-organisation cell of the matrix, and it is
    the fixture that separates "the actor exists" from "the actor may".
    """
    return _role_session(dao, session_a, org_a, "interpreter@org-a.test", "Interpreter")


@pytest.fixture
def interpreter_b(dao, session_b, org_b):
    """Wrong role AND wrong organisation."""
    return _role_session(dao, session_b, org_b, "interpreter@org-b.test", "Interpreter")


def _make_interpretation(dao, conn, session):
    org_id = session.org_id
    now = datetime.datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)

    test_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tests (test_id, org_id, name, assembly, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (test_id, org_id, "Panel", "GRCh38", "active", now),
        )
    conn.commit()

    patient_id = dao.create_patient(session, "Test", date(1990, 1, 1), "M")
    consent_id = dao.record_consent(session, patient_id, "testing")
    order_id = uuid.uuid4()
    sample_id = uuid.uuid4()
    run_id = uuid.uuid4()
    vcf_id = uuid.uuid4()
    interp_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO orders (order_id, org_id, patient_id, test_id, required_scope, consent_id, "
            "ordered_by, priority, state, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                order_id,
                org_id,
                patient_id,
                test_id,
                "testing",
                consent_id,
                session.user_id,
                "routine",
                "draft",
                now,
            ),
        )
        cur.execute(
            "INSERT INTO samples (sample_id, order_id, org_id, type, collected_at, collected_by, qc_status) "
            "VALUES (%s, %s, %s, 'blood', %s, %s, 'passed')",
            (sample_id, order_id, org_id, now, session.user_id),
        )
        cur.execute(
            "INSERT INTO sequencing_runs (org_id, id, sample_id, created_at, created_by) VALUES (%s, %s, %s, %s, %s)",
            (org_id, run_id, sample_id, now, session.user_id),
        )
        cur.execute(
            "INSERT INTO vcfs (org_id, id, sequencing_run_id, vcf_path, content_hash, created_at, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (org_id, vcf_id, run_id, "/tmp/x.vcf", "0" * 64, now, session.user_id),
        )
        cur.execute(
            "INSERT INTO interpretations "
            "(org_id, id, vcf_id, run_document, submission_key, created_at, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                org_id,
                interp_id,
                vcf_id,
                json.dumps({"variants": []}),
                "sub-" + str(interp_id),
                now,
                session.user_id,
            ),
        )
    conn.commit()
    return interp_id


def _approved_report(dao, conn, session, approver):
    interp_id = _make_interpretation(dao, conn, session)
    report_id = dao.create_report(session, interp_id)
    with conn.cursor() as cur:
        cur.execute("UPDATE reports SET state = 'under_review' WHERE id = %s", (report_id,))
    conn.commit()
    dao._approve_report(approver, report_id, actor_id=approver.user_id)
    return report_id


@pytest.fixture
def approved_report_a(dao, conn, session_a, approver_a):
    return _approved_report(dao, conn, session_a, approver_a)


@pytest.fixture
def approved_report_b(dao, conn, session_b, approver_b):
    return _approved_report(dao, conn, session_b, approver_b)


def _release_count(conn, report_id):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM release_events WHERE report_id = %s", (report_id,))
        return cur.fetchone()[0]


def _report_state(conn, report_id):
    with conn.cursor() as cur:
        cur.execute("SELECT state FROM reports WHERE id = %s", (report_id,))
        return cur.fetchone()[0]


def _amendment_count(conn, report_id):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM amendments WHERE original_report_id = %s", (report_id,))
        return cur.fetchone()[0]


class TestReleaseRequiresAuthorityNotMerelyIdentity:
    """
    _release_report's pre-fix check is "SELECT 1 FROM users WHERE org_id = %s
    AND user_id = %s" -- membership. Every negative below satisfies that query
    and must still be refused.
    """

    def test_release_refuses_a_session_that_exists_but_holds_no_release_authority(
        self, dao, conn, session_a, approver_a, approved_report_a
    ):
        """
        session_a is a real, logged-in Administrator of this organisation. It
        passes the membership check the method already performs. It is not an
        Approver, so it may not hand an approved report to a consumer.
        """
        with pytest.raises(AuthorizationError, match="Approver"):
            dao._release_report(session_a, approved_report_a, consumer="LIMS", actor_id=approver_a.user_id)

    def test_release_refused_writes_nothing_and_leaves_the_report_unreleased(
        self, dao, conn, session_a, approver_a, approved_report_a
    ):
        """
        The absence half. Its positive twin is
        test_release_by_an_approver_writes_exactly_one_delivery_record below:
        a method that raised for an unrelated reason would satisfy this test
        and fail that one.
        """
        with pytest.raises(AuthorizationError):
            dao._release_report(session_a, approved_report_a, consumer="LIMS", actor_id=approver_a.user_id)

        assert _release_count(conn, approved_report_a) == 0
        assert _report_state(conn, approved_report_a) == "approved"

    def test_release_by_an_approver_writes_exactly_one_delivery_record(self, dao, conn, approver_a, approved_report_a):
        """The positive twin. Right role, right organisation -> allowed."""
        release_id = dao._release_report(approver_a, approved_report_a, consumer="LIMS", actor_id=approver_a.user_id)

        assert isinstance(release_id, uuid.UUID)
        assert _release_count(conn, approved_report_a) == 1
        assert _report_state(conn, approved_report_a) == "released"
        with conn.cursor() as cur:
            cur.execute("SELECT consumer, released_by FROM release_events WHERE id = %s", (release_id,))
            consumer, released_by = cur.fetchone()
        assert consumer == "LIMS"
        assert released_by == approver_a.user_id

    def test_release_refuses_an_interpreter_holding_a_real_but_wrong_role(
        self, dao, interpreter_a, approver_a, approved_report_a
    ):
        """
        Wrong role + right organisation. Interpreter is a real assignable role
        with a real gate of its own (submit_for_review); it is not release
        authority.
        """
        with pytest.raises(AuthorizationError, match="Approver"):
            dao._release_report(interpreter_a, approved_report_a, consumer="LIMS", actor_id=approver_a.user_id)

    def test_release_refuses_an_approver_of_another_organisation(self, dao, conn, approver_b, approved_report_a):
        """
        Right role + WRONG organisation. approver_b genuinely holds Approver,
        in org B. Org A's report must be indistinguishable from nonexistent,
        and nothing may be written.
        """
        with pytest.raises(NotFoundError):
            dao._release_report(approver_b, approved_report_a, consumer="LIMS", actor_id=approver_b.user_id)
        assert _release_count(conn, approved_report_a) == 0
        assert _report_state(conn, approved_report_a) == "approved"

    def test_release_refuses_wrong_role_and_wrong_organisation(self, dao, conn, interpreter_b, approved_report_a):
        """Wrong role + wrong organisation -> rejected, and nothing written."""
        with pytest.raises((AuthorizationError, NotFoundError)):
            dao._release_report(interpreter_b, approved_report_a, consumer="LIMS", actor_id=interpreter_b.user_id)
        assert _release_count(conn, approved_report_a) == 0


class TestTheRecordedReleaserMustAlsoHoldTheRole:
    """
    The second half of the _approve_report pattern. A session gate alone lets
    an authorised Approver record an unauthorised colleague as the person who
    released the report -- retrievable, and false. release_events.released_by
    is read as an authority claim exactly the way reports.approver_id is.
    """

    def test_release_refuses_an_actor_who_exists_but_is_not_an_approver(
        self, dao, conn, approver_a, interpreter_a, approved_report_a
    ):
        """
        The SESSION is a genuine Approver here -- the session gate passes. The
        recorded actor is a real org-A user holding Interpreter. Pre-fix, the
        membership SELECT returns a row and the release is written with that
        id as released_by.
        """
        with pytest.raises(AuthorizationError, match="Approver"):
            dao._release_report(approver_a, approved_report_a, consumer="LIMS", actor_id=interpreter_a.user_id)
        assert _release_count(conn, approved_report_a) == 0

    def test_release_refuses_an_actor_with_no_roles_at_all(self, dao, conn, session_a, approver_a, approved_report_a):
        """A bystander account: exists in the organisation, holds nothing."""
        bystander = dao.create_user(session_a.org_id, "bystander@org-a.test", "password")
        with pytest.raises(AuthorizationError, match="Approver"):
            dao._release_report(approver_a, approved_report_a, consumer="LIMS", actor_id=bystander)
        assert _release_count(conn, approved_report_a) == 0

    def test_release_records_the_approver_actor_when_both_halves_hold(
        self, dao, conn, session_a, approver_a, approved_report_a
    ):
        """
        Positive twin for both halves: a second Approver may be recorded as
        the releaser by the first Approver's session, because the second one
        genuinely holds the role.
        """
        second = _role_session(dao, session_a, session_a.org_id, "approver2@org-a.test", "Approver")
        release_id = dao._release_report(
            approver_a, approved_report_a, consumer="Clinician portal", actor_id=second.user_id
        )
        with conn.cursor() as cur:
            cur.execute("SELECT released_by FROM release_events WHERE id = %s", (release_id,))
            assert cur.fetchone()[0] == second.user_id


class TestRequireReleaseIsAnAuthorityGateAsWellAsAStateGate:
    """
    require_release is described in data_access.py as "the one gate every
    delivery path calls". Before this wave it answered only "is this report
    approved" -- it had no opinion about who was asking.
    """

    def test_require_release_refuses_a_session_without_the_role(self, dao, session_a, approved_report_a):
        with pytest.raises(AuthorizationError, match="Approver"):
            dao.require_release(session_a, approved_report_a)

    def test_require_release_refuses_a_wrong_role_in_the_right_organisation(
        self, dao, interpreter_a, approved_report_a
    ):
        with pytest.raises(AuthorizationError, match="Approver"):
            dao.require_release(interpreter_a, approved_report_a)

    def test_require_release_passes_for_an_approver_on_an_approved_report(self, dao, approver_a, approved_report_a):
        """The positive twin: the gate still opens for the right role."""
        dao.require_release(approver_a, approved_report_a)  # must not raise

    def test_require_release_still_refuses_an_unapproved_report_for_an_approver(self, dao, conn, session_a, approver_a):
        """
        The state gate is not replaced by the authority gate. An Approver
        asking about a draft report still gets the spec 13.4 refusal.
        """
        interp = _make_interpretation(dao, conn, session_a)
        draft = dao.create_report(session_a, interp)
        with pytest.raises(ValueError, match="13.4"):
            dao.require_release(approver_a, draft)

    def test_require_release_refuses_another_organisations_report_to_a_real_approver(
        self, dao, approver_b, approved_report_a
    ):
        """Right role, wrong organisation."""
        with pytest.raises(NotFoundError):
            dao.require_release(approver_b, approved_report_a)


class TestAmendmentRequiresTheSameAuthorityAsApproval:
    """
    create_amendment produces a new report beside a signed one (ISO 15189
    7.4.1.8). It acts only on an approved or released original, and it is the
    one sanctioned corrective act on a record that has already been signed.
    Its authority is the same authority that signed it.
    """

    def test_amendment_refuses_a_session_without_the_role(self, dao, conn, session_a, approved_report_a):
        with pytest.raises(AuthorizationError, match="Approver"):
            dao.create_amendment(session_a, approved_report_a, "ClinVar reclassified the variant")
        assert _amendment_count(conn, approved_report_a) == 0

    def test_amendment_refuses_a_wrong_role_in_the_right_organisation(
        self, dao, conn, interpreter_a, approved_report_a
    ):
        with pytest.raises(AuthorizationError, match="Approver"):
            dao.create_amendment(interpreter_a, approved_report_a, "ClinVar reclassified the variant")
        assert _amendment_count(conn, approved_report_a) == 0

    def test_amendment_by_an_approver_creates_exactly_one_amendment(self, dao, conn, approver_a, approved_report_a):
        """
        The positive twin. Without it the two refusals above are satisfied by
        a create_amendment that refuses everybody.
        """
        amendment_report_id, notification_id = dao.create_amendment(
            approver_a, approved_report_a, "ClinVar reclassified the variant"
        )
        assert isinstance(amendment_report_id, uuid.UUID)
        assert isinstance(notification_id, uuid.UUID)
        assert _amendment_count(conn, approved_report_a) == 1
        with conn.cursor() as cur:
            cur.execute("SELECT reason FROM amendments WHERE original_report_id = %s", (approved_report_a,))
            assert cur.fetchone()[0] == "ClinVar reclassified the variant"

    def test_amendment_refuses_an_approver_of_another_organisation(self, dao, conn, approver_b, approved_report_a):
        """Right role, wrong organisation -- and no row left behind."""
        with pytest.raises(NotFoundError):
            dao.create_amendment(approver_b, approved_report_a, "ClinVar reclassified the variant")
        assert _amendment_count(conn, approved_report_a) == 0

    def test_amendment_refuses_wrong_role_and_wrong_organisation(self, dao, conn, interpreter_b, approved_report_a):
        with pytest.raises((AuthorizationError, NotFoundError)):
            dao.create_amendment(interpreter_b, approved_report_a, "ClinVar reclassified the variant")
        assert _amendment_count(conn, approved_report_a) == 0
