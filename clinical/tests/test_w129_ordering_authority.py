"""
clinical/tests/test_w129_ordering_authority.py
──────────────────────────────────────────────

w129 phase B item 6, first half: the Orderer role gates the ordering
operations.

Before this wave `Orderer` appeared exactly ONCE in all non-test Python of
clinical/ and geper/ -- inside the ROLES tuple at data_access.py:66. It was
assignable, it was recorded in role_assignments, and no line of code anywhere
consulted it. Ordering a test was permitted to every authenticated session in
the organisation equally, whatever roles it held, including none.

WHICH OPERATIONS REQUIRE IT IS READ OFF THE CODE, NEVER FROM THE ROLE'S NAME.
The complete list of ordering operations in clinical/data_access.py, counted
by scanning every method definition in the file rather than by grepping for a
word:

    create_order   -- the order is minted, ordered_by = session.user_id
    place_order    -- draft -> placed, the act that commits the laboratory
    cancel_order   -- the act that withdraws it

That is the whole of it, and it is the whole of what this file tests. There is
no other method in data_access.py that creates, advances or withdraws an
order. get_order and check_order_data are readers and are deliberately left
alone -- the ruling gives Auditor read-only authority under the EXISTING
model, and narrowing reads would be the broad RBAC redesign it forbids.

THE FOUR CELLS, for each of the three operations:
    right role + right organisation   -> allowed
    wrong role + right organisation   -> AuthorizationError
    right role + WRONG organisation   -> NotFoundError, nothing written
    wrong role + wrong organisation   -> rejected

The wrong-role sessions here hold Interpreter, a REAL assignable role with a
real gate of its own. A session holding nothing at all would leave open the
reading that the gate merely requires "some role"; one holding a different
genuine role does not.
"""

from __future__ import annotations

import datetime
from datetime import date, timezone
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

T0 = datetime.datetime(2026, 9, 1, tzinfo=timezone.utc)


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
            (user_id, org_id, user_id, T0),
        )
    conn.commit()
    return dao.login(email, org_id, "password")


@pytest.fixture
def admin_a(dao, conn, org_a):
    """
    An Administrator. Real, authenticated, in the right organisation, and NOT
    an Orderer. The ruling gives Administrator "organisation/staff
    administration"; this wave does not make it a superuser over clinical
    work, and this fixture is what proves that.
    """
    return _admin_session(dao, conn, org_a, "admin@org-a.test")


@pytest.fixture
def admin_b(dao, conn, org_b):
    return _admin_session(dao, conn, org_b, "admin@org-b.test")


def _role_session(dao, admin_session, org_id, email, *roles):
    user_id = dao.create_user(org_id, email, "password")
    for role in roles:
        dao.assign_role(admin_session, user_id, role, basis=f"w129 test fixture: {role}")
    return dao.login(email, org_id, "password")


@pytest.fixture
def orderer_a(dao, admin_a, org_a):
    return _role_session(dao, admin_a, org_a, "orderer@org-a.test", "Orderer")


@pytest.fixture
def orderer_b(dao, admin_b, org_b):
    return _role_session(dao, admin_b, org_b, "orderer@org-b.test", "Orderer")


@pytest.fixture
def interpreter_a(dao, admin_a, org_a):
    """Wrong role, right organisation -- and a real role, not an empty account."""
    return _role_session(dao, admin_a, org_a, "interpreter@org-a.test", "Interpreter")


@pytest.fixture
def interpreter_b(dao, admin_b, org_b):
    """Wrong role AND wrong organisation."""
    return _role_session(dao, admin_b, org_b, "interpreter@org-b.test", "Interpreter")


def _orderable(dao, conn, session):
    """A patient, an active consent and a catalogue test, all in the session's org."""
    test_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tests (test_id, org_id, name, assembly, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (test_id, session.org_id, "Panel", "GRCh38", "active", T0),
        )
    conn.commit()
    patient_id = dao.create_patient(session, "Test", date(1990, 1, 1), "M")
    consent_id = dao.record_consent(session, patient_id, "testing")
    return patient_id, consent_id, test_id


@pytest.fixture
def orderable_a(dao, conn, orderer_a):
    """
    Built by the ORDERER, which changed at w162 and is the correct fix rather
    than a convenience.

    This fixture used to be built by `admin_a`, on the reasoning that
    `create_patient` and `record_consent` were not ordering operations — true
    of the tree as it then stood, where neither enforced any role at all. The
    human ruled on 2026-09-19 that the ordering clinician owns registration
    and consent, so both are now `Orderer`-gated and an Administrator cannot
    build this. The fixture is given a correctly-roled session; the gate is
    not weakened and the method is not bypassed.

    IT DOES NOT WEAKEN THIS FILE'S OWN CLAIMS. Every row below asks whether a
    principal may CREATE, PLACE or CANCEL an order, and `admin_a` is still the
    Administrator-who-is-not-an-Orderer that those rows refuse. Only the
    construction of the subject moved.
    """
    return _orderable(dao, conn, orderer_a)


def _order_count(conn, org_id):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM orders WHERE org_id = %s", (org_id,))
        return cur.fetchone()[0]


def _order_state(conn, order_id):
    with conn.cursor() as cur:
        cur.execute("SELECT state FROM orders WHERE order_id = %s", (order_id,))
        row = cur.fetchone()
        return row[0] if row else None


def _create(dao, session, orderable):
    patient_id, consent_id, test_id = orderable
    return dao.create_order(
        session,
        patient_id=patient_id,
        test_id=test_id,
        required_scope="testing",
        consent_id=consent_id,
        priority="routine",
    )


class TestCreateOrderRequiresTheOrdererRole:
    def test_an_orderer_may_create_an_order(self, dao, conn, orderer_a, orderable_a):
        """
        Right role + right organisation. The positive twin for every refusal
        in this class: without it, a create_order that refused everybody
        would satisfy all of them.
        """
        order_id = _create(dao, orderer_a, orderable_a)
        assert isinstance(order_id, uuid.UUID)
        assert _order_state(conn, order_id) == "draft"
        with conn.cursor() as cur:
            cur.execute("SELECT ordered_by FROM orders WHERE order_id = %s", (order_id,))
            assert cur.fetchone()[0] == orderer_a.user_id

    def test_an_administrator_may_not_create_an_order(self, dao, conn, admin_a, orderable_a):
        """
        Wrong role + right organisation. admin_a is authenticated, exists, and
        holds a real role -- it is simply not the ordering role. Before this
        wave this call succeeded.
        """
        with pytest.raises(AuthorizationError, match="Orderer"):
            _create(dao, admin_a, orderable_a)
        assert _order_count(conn, admin_a.org_id) == 0

    def test_an_interpreter_may_not_create_an_order(self, dao, conn, interpreter_a, orderable_a):
        with pytest.raises(AuthorizationError, match="Orderer"):
            _create(dao, interpreter_a, orderable_a)
        assert _order_count(conn, interpreter_a.org_id) == 0

    def test_an_orderer_of_another_organisation_may_not_order_for_this_patient(
        self, dao, conn, orderer_b, orderable_a, org_a
    ):
        """
        Right role + WRONG organisation. orderer_b genuinely holds Orderer, in
        org B. Org A's patient must be indistinguishable from a nonexistent
        one, and no order may appear in EITHER organisation.
        """
        with pytest.raises(NotFoundError):
            _create(dao, orderer_b, orderable_a)
        assert _order_count(conn, org_a) == 0
        assert _order_count(conn, orderer_b.org_id) == 0

    def test_wrong_role_and_wrong_organisation_is_refused(self, dao, conn, interpreter_b, orderable_a, org_a):
        with pytest.raises((AuthorizationError, NotFoundError)):
            _create(dao, interpreter_b, orderable_a)
        assert _order_count(conn, org_a) == 0
        assert _order_count(conn, interpreter_b.org_id) == 0


class TestPlaceOrderRequiresTheOrdererRole:
    """
    place_order is the act that commits the laboratory to the work: draft ->
    placed. It is the second of the three ordering operations and it was
    ungated for exactly the same reason the first was.
    """

    @pytest.fixture
    def draft_order(self, dao, orderer_a, orderable_a):
        return _create(dao, orderer_a, orderable_a)

    def test_an_orderer_may_place_the_order(self, dao, conn, orderer_a, draft_order):
        dao.place_order(orderer_a, draft_order)
        assert _order_state(conn, draft_order) == "placed"

    def test_an_administrator_may_not_place_the_order(self, dao, conn, admin_a, draft_order):
        with pytest.raises(AuthorizationError, match="Orderer"):
            dao.place_order(admin_a, draft_order)
        assert _order_state(conn, draft_order) == "draft", "the refusal must leave the order unplaced"

    def test_an_interpreter_may_not_place_the_order(self, dao, conn, interpreter_a, draft_order):
        with pytest.raises(AuthorizationError, match="Orderer"):
            dao.place_order(interpreter_a, draft_order)
        assert _order_state(conn, draft_order) == "draft"

    def test_an_orderer_of_another_organisation_may_not_place_it(self, dao, conn, orderer_b, draft_order):
        with pytest.raises(NotFoundError):
            dao.place_order(orderer_b, draft_order)
        assert _order_state(conn, draft_order) == "draft"

    def test_wrong_role_and_wrong_organisation_may_not_place_it(self, dao, conn, interpreter_b, draft_order):
        with pytest.raises((AuthorizationError, NotFoundError)):
            dao.place_order(interpreter_b, draft_order)
        assert _order_state(conn, draft_order) == "draft"


class TestCancelOrderRequiresTheOrdererRole:
    """
    Cancellation withdraws a committed order. It is an ordering operation by
    the same reading as the other two -- it acts on `orders` and moves its
    state -- and gating creation while leaving withdrawal open would be a hole
    shaped exactly like the one this wave is closing.
    """

    @pytest.fixture
    def placed_order(self, dao, orderer_a, orderable_a):
        order_id = _create(dao, orderer_a, orderable_a)
        dao.place_order(orderer_a, order_id)
        return order_id

    def test_an_orderer_may_cancel_the_order(self, dao, conn, orderer_a, placed_order):
        dao.cancel_order(orderer_a, placed_order)
        assert _order_state(conn, placed_order) == "cancelled"

    def test_an_administrator_may_not_cancel_the_order(self, dao, conn, admin_a, placed_order):
        with pytest.raises(AuthorizationError, match="Orderer"):
            dao.cancel_order(admin_a, placed_order)
        assert _order_state(conn, placed_order) == "placed"

    def test_an_interpreter_may_not_cancel_the_order(self, dao, conn, interpreter_a, placed_order):
        with pytest.raises(AuthorizationError, match="Orderer"):
            dao.cancel_order(interpreter_a, placed_order)
        assert _order_state(conn, placed_order) == "placed"

    def test_an_orderer_of_another_organisation_may_not_cancel_it(self, dao, conn, orderer_b, placed_order):
        with pytest.raises(NotFoundError):
            dao.cancel_order(orderer_b, placed_order)
        assert _order_state(conn, placed_order) == "placed"

    def test_wrong_role_and_wrong_organisation_may_not_cancel_it(self, dao, conn, interpreter_b, placed_order):
        with pytest.raises((AuthorizationError, NotFoundError)):
            dao.cancel_order(interpreter_b, placed_order)
        assert _order_state(conn, placed_order) == "placed"


class TestTheGateIsTheOrdererRoleSpecifically:
    """
    Rule 4's shape. Every refusal above would also be produced by a
    _require_role call naming the WRONG role -- "Approver", say -- because
    none of the refused sessions holds that either. These two tests are what
    make the assertions above mean "Orderer" rather than "some role this
    session lacks".
    """

    def test_a_session_holding_only_orderer_can_do_all_three(self, dao, conn, orderer_a, orderable_a):
        """
        The Orderer holds NOTHING else -- not Administrator, not Interpreter.
        If the gate named any other role this would fail.
        """
        held = {a.role for a in dao.get_user_roles(orderer_a)}
        assert held == {"Orderer"}, f"fixture drifted: {held}"

        order_id = _create(dao, orderer_a, orderable_a)
        dao.place_order(orderer_a, order_id)
        dao.cancel_order(orderer_a, order_id)
        assert _order_state(conn, order_id) == "cancelled"

    def test_holding_every_other_role_but_orderer_is_still_refused(self, dao, conn, admin_a, org_a, orderable_a):
        """
        The sharpest negative available: a session holding Administrator, Lab
        technician, Interpreter, Approver AND Auditor -- every assignable
        human role except the one that matters -- is still refused. That
        excludes "the gate just wants a role" and every hierarchy reading in
        which Administrator or Approver subsumes Orderer.
        """
        loaded = _role_session(
            dao,
            admin_a,
            org_a,
            "everything-but@org-a.test",
            "Administrator",
            "Lab technician",
            "Interpreter",
            "Approver",
            "Auditor",
        )
        with pytest.raises(AuthorizationError, match="Orderer"):
            _create(dao, loaded, orderable_a)
        assert _order_count(conn, org_a) == 0
