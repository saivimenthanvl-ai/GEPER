"""
clinical/tests/test_w129_exception_tenant_isolation.py
───────────────────────────────────────────────────────
w129 GAP-1 -- the cross-tenant write into another organisation's append-only
exception history.

WHAT WAS MEASURED BEFORE THE FIX (w129 Phase A, at 9bc3abd, against a real
database, calling the real method):

    [A] exception 67438ce9-... status=open events=1
    --- org B calls resolve_exception(session_B, exception_A) ---
    resolve_exception RETURNED NORMALLY (no exception raised)
    [A] after: status=open events=2
        event action='open'    actor='0f6b9615-...(A)' note="A's own failure"
        event action='resolve' actor='8c6f9be5-...(B)' note='B was here'
    audit_log resolve_exception rows: org_A=0  org_B=1

Two facts in that transcript, and this file pins both:

  1. B's row landed in A's history. `resolve_exception`'s UPDATE was org-scoped
     and matched zero rows; `_execute` never inspects rowcount, so the zero-row
     UPDATE was silent and execution fell through into an INSERT that was NOT
     org-scoped. The single-column foreign key on exception_id was satisfied
     because the exception existed GLOBALLY.

  2. A could not explain the row. The only audit record of who wrote it was in
     B's partition, which A's Auditor cannot read.

WHY THERE ARE FOUR TESTS AND NOT ONE. The refusal is enforced twice on purpose
and the two halves fail independently:

  - the Python guard (`TestTheWritePathRefuses`) gives a CLEAN refusal, the same
    NotFoundError a nonexistent id gets, which is what keeps the endpoint from
    being an existence oracle;
  - the composite foreign key (`TestTheSchemaMakesTheRowInexpressible`) is the
    guarantee that survives someone editing the method. That one deliberately
    does NOT go through the application: the property under test is a database
    property, which is the same reason test_privilege_boundary.py uses raw
    connections.

EVERY ABSENCE ASSERTION HERE HAS A POSITIVE TWIN (Rule 4). "A's history did not
grow" is satisfied just as happily by a resolve path that writes nothing at all,
so each absence is paired with a same-organisation resolve that must produce
exactly one new event with the right actor and note.
"""

from __future__ import annotations

import datetime
import os
import pathlib
import uuid

import pytest

from clinical.data_access import BcryptHasher, DataAccess, NotFoundError, SystemClock
from clinical.models.exception import (
    ExceptionCategory,
    ExceptionReasonCode,
    ResolutionAction,
)

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"

NOW = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)


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
def dao(conn):
    return DataAccess(conn, clock=SystemClock(), password_hasher=BcryptHasher(rounds=4))


def _org_with_admin(dao, conn, name: str, email: str):
    """An organisation, an administrator in it, and a real login session."""
    org_id = dao.create_organisation(name)
    user_id = dao.create_user(org_id, email, "a sufficiently long password")
    with conn.cursor() as cur:
        # Direct insert to break the bootstrap cycle, exactly as the
        # neighbouring exception fixtures do.
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Administrator', %s, %s)",
            (user_id, org_id, user_id, NOW),
        )
        # w129 phase B: the ordering operations require Orderer and the
        # sample / laboratory / QC operations require Lab technician. This
        # fixture's account is the whole staff of its organisation -- it
        # orders, receives, runs and reviews -- so it holds the roles for
        # the work it performs. Roles are additive; still an Administrator.
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Orderer', %s, %s)",
            (user_id, org_id, user_id, NOW),
        )
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Lab technician', %s, %s)",
            (user_id, org_id, user_id, NOW),
        )
    conn.commit()
    return org_id, dao.login(email, org_id, "a sufficiently long password")


def _order_for(dao, conn, session):
    test_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tests (test_id, org_id, name, assembly, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (test_id, session.org_id, "Test Gene Panel", "GRCh38", "active", NOW),
        )
    conn.commit()
    patient_id = dao.create_patient(session, "Test Patient", datetime.date(1990, 1, 1), "M")
    consent_id = dao.record_consent(session, patient_id, "testing")
    return dao.create_order(
        session,
        patient_id=patient_id,
        test_id=test_id,
        required_scope="testing",
        consent_id=consent_id,
        priority="routine",
    )


@pytest.fixture()
def two_orgs(dao, conn):
    """
    A and B: two real organisations, each with an administrator session, and one
    open exception in A created THROUGH THE METHOD (so its 'open' event is the
    one production writes, not one this file invented).

    Returns (session_a, session_b, order_a, exception_a).
    """
    _org_a, session_a = _org_with_admin(dao, conn, "Org A", "admin@org-a.test")
    _org_b, session_b = _org_with_admin(dao, conn, "Org B", "admin@org-b.test")

    order_a = _order_for(dao, conn, session_a)
    exception_a = dao.create_or_reopen_exception(
        session_a,
        order_a,
        ExceptionCategory.PRECONDITION_FAILURE.value,
        ExceptionReasonCode.CONSENT_MISSING.value,
        "A's own failure",
        "orderer",
        str(session_a.user_id),
    )
    conn.commit()
    return session_a, session_b, order_a, exception_a


def _history(dao, session, exception_id):
    """A's view of its own exception, read through the method that serves it."""
    return dao.get_exception_by_id(session, exception_id)


class TestTheWritePathRefuses:
    """
    The behavioural half. Every assertion here comes from calling
    resolve_exception / get_exception_by_id -- never from a hand-written query
    against exception_events, because a query proves the data is right and not
    that the code reads it right (Rule 2a).
    """

    def test_org_b_resolving_org_a_exception_raises_instead_of_returning_normally(self, dao, two_orgs):
        """
        The headline. Before the fix this call RETURNED NORMALLY -- that is the
        word the Phase A transcript uses, and it is the whole defect: a zero-row
        UPDATE that nothing inspected, followed by an INSERT that landed.
        """
        _session_a, session_b, _order_a, exception_a = two_orgs

        with pytest.raises(NotFoundError):
            dao.resolve_exception(
                session_b,
                exception_a,
                ResolutionAction.RETRY_CHECK.value,
                "B was here",
                str(session_b.user_id),
            )

    def test_org_a_history_and_status_are_untouched_by_the_refused_attempt(self, dao, two_orgs):
        """
        The absence half. A's exception must be exactly as it was: still open,
        still one event, and B's user id and free text nowhere in it.

        Note what this asserts and what it deliberately does not. Not "the event
        count is 1" alone -- Rule 4: a count is satisfied by a resolve path that
        writes nothing at all. The content is asserted, and the positive twin
        below is the test that a working resolve still writes.
        """
        session_a, session_b, _order_a, exception_a = two_orgs

        before = _history(dao, session_a, exception_a)
        assert before.status == "open"
        assert [e.action for e in before.events] == ["open"]

        with pytest.raises(NotFoundError):
            dao.resolve_exception(
                session_b,
                exception_a,
                ResolutionAction.RETRY_CHECK.value,
                "B was here",
                str(session_b.user_id),
            )

        after = _history(dao, session_a, exception_a)
        assert after.status == "open", "B's refused resolve must not advance A's exception"
        assert [e.action for e in after.events] == ["open"], "B's refused resolve must not append to A's history"
        assert after.last_resolved_by is None
        assert after.resolution_note is None

        # The contamination as it was actually measured: B's identity and B's
        # free text, present in A's readable history.
        rendered = " ".join(f"{e.action}|{e.actor}|{e.action_note}" for e in after.events)
        assert str(session_b.user_id) not in rendered, "B's user id must not appear in A's exception history"
        assert "B was here" not in rendered, "B's free text must not appear in A's exception history"

    def test_positive_twin_org_a_resolving_its_own_exception_writes_exactly_one_event(self, dao, two_orgs):
        """
        The twin the absence assertion above is worthless without. A refusal that
        refuses everything would pass that test perfectly.
        """
        session_a, _session_b, _order_a, exception_a = two_orgs

        dao.resolve_exception(
            session_a,
            exception_a,
            ResolutionAction.RETRY_CHECK.value,
            "Consent obtained",
            str(session_a.user_id),
        )

        after = _history(dao, session_a, exception_a)
        assert after.status == "resolved"
        assert [e.action for e in after.events] == ["open", "resolve"]
        resolve_event = after.events[-1]
        assert resolve_event.actor == str(session_a.user_id)
        assert resolve_event.action_note == "Consent obtained"
        assert after.last_resolved_by == str(session_a.user_id)

    def test_an_id_that_exists_nowhere_is_refused_the_same_way(self, dao, two_orgs):
        """
        At the method layer, the two refusals must already be the same kind of
        object with the same message shape. The HTTP half of this is
        test_w129_exception_refusal_parity.py; if they diverge here, no amount of
        endpoint tidying can make the responses match.
        """
        _session_a, session_b, _order_a, exception_a = two_orgs
        invented = uuid.uuid4()

        with pytest.raises(NotFoundError) as foreign:
            dao.resolve_exception(
                session_b, exception_a, ResolutionAction.RETRY_CHECK.value, "probe", str(session_b.user_id)
            )
        with pytest.raises(NotFoundError) as nowhere:
            dao.resolve_exception(
                session_b, invented, ResolutionAction.RETRY_CHECK.value, "probe", str(session_b.user_id)
            )

        assert type(foreign.value) is type(nowhere.value)
        assert str(foreign.value).replace(str(exception_a), "X") == str(nowhere.value).replace(str(invented), "X")


class TestTheSchemaMakesTheRowInexpressible:
    """
    The structural half, and the reason the Python guard above is not the whole
    fix. These go through a raw connection ON PURPOSE -- the property under test
    is a database property (a composite foreign key), exactly as
    test_identity.py::test_composite_fk_blocks_cross_org_role_row and
    test_fastq_sets_schema.py do. That is not the cannot-fail-test antipattern;
    the antipattern is using a raw query to prove something the PYTHON is meant
    to do, which is what the class above is for.
    """

    def test_an_event_row_naming_another_organisation_is_refused_by_the_database(self, conn, two_orgs):
        session_a, session_b, _order_a, exception_a = two_orgs
        psycopg = pytest.importorskip("psycopg")

        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO exception_events "
                    "(id, org_id, exception_id, actor, timestamp, action, action_note) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (uuid.uuid4(), session_b.org_id, exception_a, "B", NOW, "resolve", "B was here"),
                )
        conn.rollback()
        assert session_a.org_id != session_b.org_id

    def test_positive_twin_the_same_row_in_the_owning_organisation_is_accepted(self, conn, two_orgs):
        """
        Without this, the refusal above could be passing because the statement is
        malformed, the column list is wrong, or the table does not exist.
        """
        session_a, _session_b, _order_a, exception_a = two_orgs
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO exception_events "
                "(id, org_id, exception_id, actor, timestamp, action, action_note) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (uuid.uuid4(), session_a.org_id, exception_a, "A", NOW, "resolve", "A's own"),
            )
        conn.commit()

        with conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM exception_events WHERE exception_id = %s AND org_id = %s",
                (exception_a, session_a.org_id),
            )
            assert cur.fetchone()[0] == 2


class TestWhereTheAttemptIsRecorded:
    """
    THE SECOND HALF OF GAP-1, AND A DELIBERATE DECISION RATHER THAN AN OVERSIGHT.

    Phase A's finding was not only that B's row landed in A's history -- it was
    that A could SEE the row and could not find out who wrote it, because the
    audit entry sat in B's partition.

    The fix closes that asymmetry by ELIMINATION, not by attribution: once the
    write is refused and the row is inexpressible, nothing lands in A at all, so
    there is no unexplained artefact for A to explain. A's audit log recording
    nothing about a refused attempt is then the same thing as A's audit log
    recording nothing about any of the other organisations that did not touch it.

    THE ALTERNATIVE WAS CONSIDERED AND REJECTED. Writing an audit row into A's
    partition when B is refused would create a NEW cross-tenant write primitive
    -- one that lets any authenticated session in any organisation append
    attacker-chosen text to another organisation's APPEND-ONLY audit log, which
    is the one table where GAP-1's shape would matter most. That is a ruling for
    the human, not a thing to add quietly; this class pins the behaviour as it
    now is so the question stays visible.
    """

    def test_the_refused_attempt_is_audited_in_the_attackers_partition_only(self, dao, conn, two_orgs):
        session_a, session_b, _order_a, exception_a = two_orgs

        with pytest.raises(NotFoundError):
            dao.resolve_exception(
                session_b,
                exception_a,
                ResolutionAction.RETRY_CHECK.value,
                "B was here",
                str(session_b.user_id),
            )

        with conn.cursor() as cur:
            cur.execute(
                "SELECT org_id, outcome, user_id FROM audit_log WHERE action = 'resolve_exception'",
            )
            rows = cur.fetchall()

        assert len(rows) == 1, f"expected exactly one resolve_exception audit row, got {rows}"
        org_id, outcome, user_id = rows[0]
        assert org_id == session_b.org_id, "the attempt is attributed to the organisation that made it"
        assert org_id != session_a.org_id
        assert outcome == "error"
        assert user_id == session_b.user_id

    def test_positive_twin_a_successful_resolve_is_audited_in_its_own_partition(self, dao, conn, two_orgs):
        """
        The twin: 'A's partition has no row' must not be passing because
        resolve_exception writes no audit row at all.
        """
        session_a, _session_b, _order_a, exception_a = two_orgs

        dao.resolve_exception(
            session_a,
            exception_a,
            ResolutionAction.RETRY_CHECK.value,
            "Consent obtained",
            str(session_a.user_id),
        )

        with conn.cursor() as cur:
            cur.execute(
                "SELECT org_id, outcome, resource_id FROM audit_log WHERE action = 'resolve_exception'",
            )
            rows = cur.fetchall()

        assert len(rows) == 1
        org_id, outcome, resource_id = rows[0]
        assert org_id == session_a.org_id
        assert outcome == "success"
        assert resource_id == str(exception_a)
