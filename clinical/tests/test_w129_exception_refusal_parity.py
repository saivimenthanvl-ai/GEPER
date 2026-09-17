"""
clinical/tests/test_w129_exception_refusal_parity.py
─────────────────────────────────────────────────────
w129 GAP-2 -- PATCH /exceptions/{id} was a cross-tenant existence oracle.

WHY A STATUS-ONLY TEST WOULD HAVE CALLED THIS ENDPOINT CORRECT. Measured at
9bc3abd, at the HTTP layer:

    === org B PATCHes org A's REAL exception id ===
    status=500
    body={"detail":"Error resolving exception: 500: Exception resolved but
          could not retrieve updated state"}

    === org B PATCHes an id that exists NOWHERE ===
    status=500
    body={"detail":"Error resolving exception: current transaction is aborted,
          commands ignored until end of transaction block"}

    same status: True
    same body:   False

Both 500. A test asserting on `response.status_code` calls those identical and
goes green. The difference is entirely inside the `detail` string -- which is
exactly where a leak lives -- so every assertion in this file is on
`response.content` (Rule 2b).

The two branches got there by different routes and that is the whole finding:

  - A REAL FOREIGN ID satisfied the old single-column foreign key (the row
    existed globally), so the INSERT succeeded, and only the org-scoped
    re-read afterwards came back empty -> "could not retrieve updated state".
  - AN ID THAT EXISTS NOWHERE failed the foreign key, aborting the
    transaction, and the handler echoed the driver's message back.

So the presence or absence of a UUID in ANOTHER organisation was readable off
the response body by any authenticated caller, and each correct guess also left
a contaminating event row in the victim's history (GAP-1).

SECOND, SMALLER DEFECT IN THE SAME LINES: `detail=f"...{str(e)}"` hands a raw
driver error to the client. clinical/app.py:118-121 is the settled pattern in
this repository and says why in one line -- the exception TYPE, never its text,
because "a libpq error message quotes the connection string back".
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import uuid

import pytest

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"

APP_PASSWORD = "test-app-password"
RETENTION_PASSWORD = "test-retention-password"
USER_PASSWORD = "password"
NOW = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)


@pytest.fixture()
def clinical_dsn(monkeypatch):
    """A bootstrapped database with the real LOGIN roles, and CLINICAL_DSN set."""
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

    monkeypatch.setenv("CLINICAL_DSN", DSN)
    return DSN


@pytest.fixture()
def two_orgs_http(clinical_dsn):
    """
    Organisation A with one open exception of its own, organisation B with one
    of its own, and a real login session for each.

    B gets its own exception so the same-tenant control in this file is B's, not
    a second session in A: the point of comparison is one caller, three ids.

    Returns (session_a, exception_a, session_b, exception_b).
    """
    import psycopg

    from clinical.data_access import BcryptHasher, DataAccess, SystemClock
    from clinical.models.exception import ExceptionCategory, ExceptionReasonCode

    connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
    dao = DataAccess(connection, clock=SystemClock(), password_hasher=BcryptHasher(rounds=4))

    def build(name: str, email: str):
        org_id = dao.create_organisation(name)
        user_id = dao.create_user(org_id, email, USER_PASSWORD)
        test_id = uuid.uuid4()
        with connection.cursor() as cur:
            cur.execute(
                "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                "VALUES (%s, %s, 'Administrator', %s, %s)",
                (user_id, org_id, user_id, NOW),
            )
            cur.execute(
                "INSERT INTO tests (test_id, org_id, name, assembly, status, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (test_id, org_id, "Test Gene Panel", "GRCh38", "active", NOW),
            )
        connection.commit()
        session = dao.login(email, org_id, USER_PASSWORD)
        patient_id = dao.create_patient(session, "Test Patient", datetime.date(1990, 1, 1), "M")
        consent_id = dao.record_consent(session, patient_id, "testing")
        order_id = dao.create_order(
            session,
            patient_id=patient_id,
            test_id=test_id,
            required_scope="testing",
            consent_id=consent_id,
            priority="routine",
        )
        exception_id = dao.create_or_reopen_exception(
            session,
            order_id,
            ExceptionCategory.PRECONDITION_FAILURE.value,
            ExceptionReasonCode.CONSENT_MISSING.value,
            f"{name} own failure",
            "orderer",
            str(session.user_id),
        )
        connection.commit()
        return session, exception_id

    session_a, exception_a = build("Org A", "admin@org-a.test")
    session_b, exception_b = build("Org B", "admin@org-b.test")
    connection.close()
    return session_a, exception_a, session_b, exception_b


@pytest.fixture()
def client(clinical_dsn):
    """A TestClient over the real application object, clinical.app.app."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    pytest.importorskip("httpx", reason="httpx not installed (starlette TestClient requires it)")
    from fastapi.testclient import TestClient

    from clinical.app import app

    with TestClient(app) as test_client:
        yield test_client


def _auth(session):
    return {"Authorization": f"Bearer {session.session_id}"}


def _patch(client, session, exception_id):
    return client.patch(
        f"/exceptions/{exception_id}",
        json={"resolution_action": "retry_check", "resolution_note": "probe"},
        headers=_auth(session),
    )


class TestTheThreeRefusalsAreOneRefusal:
    """
    Three behavioural requests from ONE caller -- organisation B -- against three
    ids: its own, organisation A's, and one that exists nowhere. The first must
    succeed; the other two must be indistinguishable in status, body and detail.
    """

    def test_own_tenant_identifier_succeeds(self, client, two_orgs_http):
        """
        The control. Without it, "the two refusals match" would be satisfied by
        an endpoint that refuses everything, which is Rule 4's exact trap.
        """
        _session_a, _exception_a, session_b, exception_b = two_orgs_http
        response = _patch(client, session_b, exception_b)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "resolved"
        assert [event["action"] for event in body["events"]] == ["open", "resolve"]

    def test_foreign_tenant_identifier_and_nonexistent_identifier_are_byte_identical(self, client, two_orgs_http):
        """
        THE ORACLE. Asserted on response.content, not on the status code -- both
        answers were already 500 before the fix, so a status-only assertion
        called them identical and that is exactly why this survived.

        Only the echoed id may differ between the two bodies, and it differs
        because the caller supplied it; everything else must match byte for byte.
        """
        _session_a, exception_a, session_b, _exception_b = two_orgs_http
        nowhere = uuid.uuid4()

        foreign = _patch(client, session_b, exception_a)
        invented = _patch(client, session_b, nowhere)

        assert foreign.status_code == invented.status_code

        foreign_body = foreign.content.decode().replace(str(exception_a), "X")
        invented_body = invented.content.decode().replace(str(nowhere), "X")
        assert foreign_body == invented_body, (
            "the two refusals differ in their body, which is a cross-tenant existence oracle:\n"
            f"  foreign : {foreign.content.decode()}\n"
            f"  nowhere : {invented.content.decode()}"
        )

        assert foreign.json()["detail"].replace(str(exception_a), "X") == invented.json()["detail"].replace(
            str(nowhere), "X"
        )

    def test_the_refusal_is_a_404_and_says_nothing_about_other_organisations(self, client, two_orgs_http):
        """
        The refusal's content, pinned. A 500 is not merely untidy here: it says
        "something went wrong inside", which is a different statement from
        "there is no such exception", and the 500 branch is where both leaks
        lived.
        """
        _session_a, exception_a, session_b, _exception_b = two_orgs_http
        response = _patch(client, session_b, exception_a)

        assert response.status_code == 404, response.text
        detail = response.json()["detail"]
        assert detail == f"Exception {exception_a} not found"
        for leak in ("organisation", "org_id", "transaction", "resolved but"):
            assert leak.lower() not in detail.lower(), f"refusal detail mentions {leak!r}: {detail!r}"

    def test_the_foreign_probe_leaves_nothing_behind_in_the_victim(self, client, two_orgs_http):
        """
        The HTTP-level pairing of GAP-1 with GAP-2: each correct guess used to
        cost organisation A a contaminating event row. A's own GET must show its
        exception exactly as it was.
        """
        session_a, exception_a, session_b, _exception_b = two_orgs_http

        _patch(client, session_b, exception_a)

        after = client.get(f"/exceptions/{exception_a}", headers=_auth(session_a))
        if after.status_code == 405 or after.status_code == 404:
            # There is no GET /exceptions/{id} route; read through the order
            # listing, which is the served surface that renders the history.
            listing = client.get("/exceptions/worklist", params={"owner": "orderer"}, headers=_auth(session_a))
            assert listing.status_code == 200, listing.text
            rows = [row for row in listing.json() if row["id"] == str(exception_a)]
            assert len(rows) == 1, "A's exception must still be open and on its worklist"
            row = rows[0]
        else:
            row = after.json()

        assert row["status"] == "open"
        assert [event["action"] for event in row["events"]] == ["open"]
        rendered = json.dumps(row)
        assert str(session_b.user_id) not in rendered
        assert "probe" not in rendered


class TestNoRawDatabaseErrorReachesAResponseBody:
    """
    The second, smaller defect in the same two lines. `detail=f"...{str(e)}"`
    returns the driver's text to the caller; clinical/app.py:118-121 settled the
    rule for this repository -- the exception TYPE, never its text, because a
    libpq error message quotes the connection string back.

    Injected rather than provoked: a DataAccess whose method raises a message
    shaped like the real leak. Provoking a genuine driver error would tie the
    test to one Postgres message and would not prove the general rule.
    """

    @staticmethod
    def _client_with_exploding_dao(session, message: str):
        from fastapi.testclient import TestClient

        from clinical.app import app
        from clinical.endpoints import _get_data_access, _get_session

        class _Exploding:
            def __getattr__(self, name):
                def _boom(*_args, **_kwargs):
                    raise RuntimeError(message)

                return _boom

        app.dependency_overrides[_get_data_access] = lambda: _Exploding()
        app.dependency_overrides[_get_session] = lambda: session
        return TestClient(app)

    _LEAK = 'connection to server at "db.internal" (10.0.0.9), port 5432 failed: password authentication failed'

    def test_resolve_does_not_echo_the_driver_message(self, clinical_dsn, two_orgs_http):
        _session_a, _exception_a, session_b, exception_b = two_orgs_http
        from clinical.app import app

        client = self._client_with_exploding_dao(session_b, self._LEAK)
        try:
            response = client.patch(
                f"/exceptions/{exception_b}",
                json={"resolution_action": "retry_check", "resolution_note": "probe"},
            )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 500
        body = response.content.decode()
        assert "password authentication failed" not in body, f"raw driver error echoed to the client: {body}"
        assert "db.internal" not in body
        assert "10.0.0.9" not in body
        # The positive twin: it must still say SOMETHING useful, and the type
        # name is what clinical/app.py chose.
        assert "RuntimeError" in body, f"the response says nothing diagnostic at all: {body}"

    def test_the_two_read_routes_do_not_echo_it_either(self, clinical_dsn, two_orgs_http):
        """
        Same leak, same file, same three lines of handler. Fixing only the route
        that the oracle was found on would leave the identical statement on the
        two neighbouring routes.
        """
        _session_a, _exception_a, session_b, _exception_b = two_orgs_http
        from clinical.app import app

        client = self._client_with_exploding_dao(session_b, self._LEAK)
        try:
            by_order = client.get(f"/exceptions/orders/{uuid.uuid4()}")
            worklist = client.get("/exceptions/worklist", params={"owner": "orderer"})
        finally:
            app.dependency_overrides.clear()

        for response in (by_order, worklist):
            body = response.content.decode()
            assert response.status_code == 500, body
            assert "password authentication failed" not in body, f"raw driver error echoed: {body}"
            assert "db.internal" not in body
            assert "RuntimeError" in body, f"the response says nothing diagnostic at all: {body}"
