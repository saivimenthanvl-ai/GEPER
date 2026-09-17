"""
clinical/tests/test_portal_endpoints_http.py
─────────────────────────────────────────────
w130 — the patient portal over HTTP, against the app the service actually
serves (`clinical.app`), not a test-local stand-in.

THE ONE QUESTION THIS FILE ANSWERS: can a patient id supplied IN THE REQUEST
change whose data comes back?

It must be asked with a DIFFERENT, REAL, SAME-ORGANISATION patient's id.
Asking with the session's own id proves nothing — both the right and the wrong
implementation answer it correctly. Asking with a cross-organisation id proves
nothing either — the org predicate refuses that in both. Bob is a real patient
in Alice's organisation, created by the same staff session, reachable by any
staff session in org_a. He is the control.

Every query-string and body shape below is asked against ALICE'S session while
naming BOB. All of them must return Alice.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib

import pytest

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"

APP_PASSWORD = "test-app-password"
RETENTION_PASSWORD = "test-retention-password"
STAFF_PASSWORD = "correct horse battery staple"
ALICE_PASSWORD = "a sufficiently long patient password"
BOB_PASSWORD = "a different sufficiently long password"

PATIENT_COOKIE = "clinical_patient_session"
STAFF_COOKIE = "clinical_session"


@pytest.fixture()
def clinical_dsn(monkeypatch):
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
def seeded(clinical_dsn):
    """
    One organisation, one staff administrator, TWO patients, both enrolled,
    both with a real portal session obtained through the real patient_login.

    Built on its own connection and committed, so the request-scoped
    connections the endpoints open see the data.
    """
    import psycopg

    from clinical.data_access import BcryptHasher, DataAccess

    connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
    dao = DataAccess(connection, password_hasher=BcryptHasher(rounds=4))

    org_id = dao.create_organisation("Org A")
    staff_id = dao.create_user(org_id, "admin@a.example", STAFF_PASSWORD)
    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Administrator', %s, %s)",
            (staff_id, org_id, staff_id, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
        )
    connection.commit()

    staff = dao.login("admin@a.example", org_id, STAFF_PASSWORD)
    alice = dao.create_patient(staff, "Alice Anderson", dt.date(1980, 1, 1), "F")
    bob = dao.create_patient(staff, "Bob Brown", dt.date(1975, 6, 15), "M")

    dao.enrol_patient_login(staff, alice, "alice@portal.example", ALICE_PASSWORD)
    dao.enrol_patient_login(staff, bob, "bob@portal.example", BOB_PASSWORD)

    alice_session = dao.patient_login("alice@portal.example", org_id, ALICE_PASSWORD)
    bob_session = dao.patient_login("bob@portal.example", org_id, BOB_PASSWORD)
    connection.commit()
    connection.close()

    return {
        "org_id": org_id,
        "staff_session_id": str(staff.session_id),
        "alice_patient_id": str(alice),
        "bob_patient_id": str(bob),
        "alice_session_id": str(alice_session.session_id),
        "bob_session_id": str(bob_session.session_id),
    }


@pytest.fixture()
def client(clinical_dsn):
    from fastapi.testclient import TestClient

    from clinical.app import app

    return TestClient(app)


class TestThePortalIsMountedAndAnswers:
    def test_the_route_answers_for_the_authenticated_patient(self, client, seeded):
        response = client.get("/portal/me", cookies={PATIENT_COOKIE: seeded["alice_session_id"]})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["patient_id"] == seeded["alice_patient_id"]
        assert body["name"] == "Alice Anderson"

    def test_the_bearer_header_works_too(self, client, seeded):
        response = client.get("/portal/me", headers={"Authorization": f"Bearer {seeded['alice_session_id']}"})
        assert response.status_code == 200, response.text
        assert response.json()["patient_id"] == seeded["alice_patient_id"]

    def test_the_staff_routes_are_still_mounted(self, client, seeded):
        """
        Decision 11: preserve w128/w129. Mounting the portal must not displace
        the staff router, and the staff route must still authenticate exactly
        as it did.
        """
        unauthenticated = client.get("/exceptions/orders/00000000-0000-0000-0000-000000000000")
        assert unauthenticated.status_code == 401, (
            "the staff route must still authenticate; a 404 here would mean the staff router "
            "stopped being mounted rather than that the request was refused"
        )


class TestASuppliedPatientIdCannotOverrideTheSession:
    """
    THE TEST THIS WAVE EXISTS FOR, and the most easily faked one in it.

    Every request below carries ALICE'S session and names BOB — a different,
    real patient in the SAME organisation. Every one must return Alice.
    """

    def test_bob_is_a_real_reachable_patient_in_the_same_organisation(self, seeded, clinical_dsn):
        """
        THE CONTROL, and without it every assertion below is worthless: if Bob
        did not exist, or were in another organisation, "Alice's session does
        not return Bob" would be true of a completely broken implementation.

        Proved by a STAFF session really reading Bob's record through the
        method (Rule 2a), not by a SELECT.
        """
        import psycopg

        from clinical.data_access import BcryptHasher, DataAccess

        connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
        dao = DataAccess(connection, password_hasher=BcryptHasher(rounds=4))
        staff = dao.login("admin@a.example", seeded["org_id"], STAFF_PASSWORD)
        import uuid as _uuid

        record = dao.get_patient(staff, _uuid.UUID(seeded["bob_patient_id"]))
        connection.close()

        assert record is not None, "Bob must exist"
        assert record["name"] == "Bob Brown"
        assert seeded["bob_patient_id"] != seeded["alice_patient_id"]

    @pytest.mark.parametrize(
        "shape",
        ["query_patient_id", "query_patient", "query_id", "two_values"],
    )
    def test_a_query_string_patient_id_is_ignored(self, client, seeded, shape):
        bob = seeded["bob_patient_id"]
        url = {
            "query_patient_id": f"/portal/me?patient_id={bob}",
            "query_patient": f"/portal/me?patient={bob}",
            "query_id": f"/portal/me?id={bob}",
            "two_values": f"/portal/me?patient_id={bob}&patient_id={seeded['alice_patient_id']}",
        }[shape]

        response = client.get(url, cookies={PATIENT_COOKIE: seeded["alice_session_id"]})
        assert response.status_code == 200, response.text
        assert response.json()["patient_id"] == seeded["alice_patient_id"], (
            f"a patient id supplied as {shape} changed whose record came back"
        )
        assert bob not in response.text, "the other patient's identifier appears in the response"

    def test_a_request_body_patient_id_is_ignored(self, client, seeded):
        """A GET with a body is unusual and that is the point: it is the shape
        someone would reach for to 'just pass the id'."""
        response = client.request(
            "GET",
            "/portal/me",
            cookies={PATIENT_COOKIE: seeded["alice_session_id"]},
            content=json.dumps({"patient_id": seeded["bob_patient_id"]}),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["patient_id"] == seeded["alice_patient_id"]

    def test_a_header_patient_id_is_ignored(self, client, seeded):
        response = client.get(
            "/portal/me",
            cookies={PATIENT_COOKIE: seeded["alice_session_id"]},
            headers={"X-Patient-Id": seeded["bob_patient_id"]},
        )
        assert response.status_code == 200, response.text
        assert response.json()["patient_id"] == seeded["alice_patient_id"]

    def test_the_orders_route_follows_the_session_too(self, client, seeded):
        response = client.get(
            f"/portal/me/tests?patient_id={seeded['bob_patient_id']}",
            cookies={PATIENT_COOKIE: seeded["alice_session_id"]},
        )
        assert response.status_code == 200, response.text
        assert seeded["bob_patient_id"] not in response.text

    def test_the_positive_twin_bobs_own_session_returns_bob(self, client, seeded):
        """
        Rule 4. Without this, every assertion above is satisfied by a portal
        that returns Alice to everybody, or that returns nothing at all.
        """
        response = client.get("/portal/me", cookies={PATIENT_COOKIE: seeded["bob_session_id"]})
        assert response.status_code == 200, response.text
        assert response.json()["patient_id"] == seeded["bob_patient_id"]
        assert response.json()["name"] == "Bob Brown"

    def test_there_is_no_route_that_names_a_patient(self):
        """
        The structural form: no path in the portal router carries a patient
        parameter, so the URL-editing attack has no URL to edit. Derived from
        the router rather than from a list of paths somebody maintains.
        """
        from clinical.portal_endpoints import router

        paths = [route.path for route in router.routes]
        assert paths, "the portal router has no routes -- this guard would pass vacuously"
        offenders = [p for p in paths if "{" in p]
        assert not offenders, f"portal route(s) taking a path parameter: {offenders}"


class TestPortalAuthenticationRefusals:
    """
    Standing Rule 2b: the refusals must be indistinguishable, asserted on
    `response.content` and not on the status code. The detail string is exactly
    where a leak would be.
    """

    def _bodies(self, client, seeded):
        cases = {
            "no credential": client.get("/portal/me"),
            "malformed id": client.get("/portal/me", cookies={PATIENT_COOKIE: "not-a-uuid"}),
            "unknown id": client.get("/portal/me", cookies={PATIENT_COOKIE: "00000000-0000-0000-0000-000000000000"}),
            # A REAL, VALID staff session id. If the portal answered this
            # differently it would confirm the id names a live session.
            "valid staff session id": client.get("/portal/me", cookies={PATIENT_COOKIE: seeded["staff_session_id"]}),
        }
        return cases

    def test_every_refusal_is_byte_identical(self, client, seeded):
        cases = self._bodies(client, seeded)
        bodies = {name: response.content for name, response in cases.items()}
        distinct = set(bodies.values())
        assert len(distinct) == 1, f"portal refusals differ in their BODY: {bodies}"
        assert all(r.status_code == 401 for r in cases.values()), {n: r.status_code for n, r in cases.items()}

    def test_no_refusal_body_names_an_identifier(self, client, seeded):
        for name, response in self._bodies(client, seeded).items():
            text = response.text
            assert seeded["staff_session_id"] not in text, name
            assert seeded["alice_patient_id"] not in text, name
            assert seeded["bob_patient_id"] not in text, name

    def test_the_positive_twin_a_valid_patient_session_is_not_refused(self, client, seeded):
        """Without this, "every refusal is identical" is satisfied by a portal
        that refuses every request ever made to it."""
        response = client.get("/portal/me", cookies={PATIENT_COOKIE: seeded["alice_session_id"]})
        assert response.status_code == 200

    def test_a_patient_session_id_is_refused_by_the_STAFF_route(self, client, seeded):
        """
        The other direction, and decision 7 at the HTTP layer: a patient
        session id in the staff cookie is not a staff session.
        """
        response = client.get(
            "/exceptions/orders/00000000-0000-0000-0000-000000000000",
            cookies={STAFF_COOKIE: seeded["alice_session_id"]},
        )
        assert response.status_code == 401


class TestTheStaffDependencyWasNotWidened:
    """
    The design says do not widen `_get_session`, twice. This asserts it rather
    than trusting it, because widening it is a one-line change that makes the
    portal appear to work.
    """

    def test_the_portal_does_not_import_or_use_get_session(self):
        source = (pathlib.Path(__file__).resolve().parent.parent / "portal_endpoints.py").read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.strip().startswith(("#", "*")))
        assert "_get_session" not in code.split('"""')[-1], (
            "the portal router reaches clinical.endpoints._get_session -- a patient session must "
            "reach a different dependency and a different handler"
        )

    def test_get_session_still_returns_a_staff_session_only(self):
        """
        Read from the source of `_get_session` itself: it must still call
        `session_valid` and must not have grown a patient branch.
        """
        source = (pathlib.Path(__file__).resolve().parent.parent / "endpoints.py").read_text(encoding="utf-8")
        body = source[source.index("def _get_session(") :]
        body = body[: body.index("\n@router.")]
        assert "dao.session_valid(" in body
        assert "patient_session_valid" not in body, "_get_session was widened to accept a patient session"
        assert "PatientSession" not in body
