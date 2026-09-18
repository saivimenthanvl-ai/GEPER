"""
clinical/tests/test_w132_database_state_is_not_disclosed.py
────────────────────────────────────────────────────────────
w132 fixes B and C, on the five authenticated routes that already existed.

THE DEFECT, stated as it actually was. `_get_session` took `_get_data_access`
as a SUB-dependency, so the data layer resolved before any credential was
examined, and it had two observable failure modes of its own:

    CLINICAL_DSN unset       -> 503, body naming the environment variable
    CLINICAL_DSN set, down   -> uncaught psycopg exception -> 500
    database up, bad cookie  -> 401 "Authentication failed."

The BODY was already generic in the third case. The STATUS was the leak. An
anonymous caller could read the state of the clinical database off the status
code, from any authenticated route, holding no credential at all.

STANDING RULE 8 IS WHY THIS FILE ASSERTS PAIRS AND SETS. The cross-tenant
oracle w129b fixed was the mirror image: both refusals were 500 and only the
body differed. A body-only assertion misses this one; a status-only assertion
misses that one; and `assert response == GENERIC`, case by case, passes
against a leak in a case nobody thought to list. So every row collects
`(status_code, content)` for every refusal case it can construct and asserts
THE SET HAS SIZE ONE.

WHAT IS AND IS NOT CLAIMED ABOUT ORDERING — the honest version, because the
obvious reading of "authenticate before the database dependency" is
impossible for a session-authenticated route: validating a session IS a
database read. Two different things were done and they are tested separately:

  1. A GENUINE REORDERING, and it covers the whole anonymous-scanner case: a
     request with NO credential, or one whose credential is not a UUID, is
     refused by `_presented_session_id` / `_presented_patient_session_id`
     BEFORE `_get_data_access` runs. `TestNoConnectionIsOpened` proves it by
     COUNTING `psycopg.connect` calls, not by reading a signature.
  2. UNIFORM REFUSAL for everybody else: a caller presenting a well-formed
     credential cannot be refused without a SELECT, so the three database
     states were made indistinguishable rather than reordered. That is
     `TestEveryRefusalIsOneAnswer`.
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
PATIENT_PASSWORD = "a sufficiently long patient password"

STAFF_COOKIE = "clinical_session"
PATIENT_COOKIE = "clinical_patient_session"

# Port 1 is reserved and nothing listens there: a refused connection, fast,
# and not dependent on a firewall dropping packets.
UNREACHABLE_DSN = "postgresql://nobody:nobody@127.0.0.1:1/nothing"

_UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000"

# The one answer, written as a literal rather than imported from
# `data_access`, so that renaming the constant cannot silently redefine what
# "indistinguishable" means.
THE_REFUSAL = (401, json.dumps({"detail": "Authentication failed."}, separators=(",", ":")).encode())


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
    """One organisation, one staff session, one patient session — the two
    valid credentials the positive twins need, and the two ids each principal
    must be refused when presenting the other's."""
    import psycopg

    from clinical.data_access import BcryptHasher, DataAccess

    connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
    dao = DataAccess(connection, password_hasher=BcryptHasher(rounds=4))

    org_id = dao.create_organisation("Org A")
    staff_id = dao.create_user(org_id, "staff@a.example", STAFF_PASSWORD)
    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Administrator', %s, %s)",
            (staff_id, org_id, staff_id, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
        )
    connection.commit()

    staff = dao.login("staff@a.example", org_id, STAFF_PASSWORD)
    patient_id = dao.create_patient(staff, "Alice Anderson", dt.date(1980, 1, 1), "F")
    dao.enrol_patient_login(staff, patient_id, "alice@portal.example", PATIENT_PASSWORD)
    patient_session = dao.patient_login("alice@portal.example", org_id, PATIENT_PASSWORD)
    connection.commit()
    connection.close()

    return {
        "org_id": str(org_id),
        "staff_session_id": str(staff.session_id),
        "patient_session_id": str(patient_session.session_id),
        "patient_id": str(patient_id),
    }


@pytest.fixture()
def client(clinical_dsn):
    from fastapi.testclient import TestClient

    from clinical.app import app

    return TestClient(app)


def authenticated_route_probes(client, credential):
    """
    NINE mounted routes that require a principal, exercised with `credential`
    (a cookie dict, possibly empty).

    ── RULE 3 APPLIED TO THIS DOCSTRING (w152): IT USED TO SAY "EVERY". ────
    It was true when written and had already gone false twice before anybody
    edited it — `POST /auth/logout` and `POST /portal/logout` landed in w132c
    and were never added here (the same omission
    `test_w132_login_refusal_parity.py::_authenticated_route_probes` records
    finding in itself), and w152 added four administrative routes. The four
    administrative ones are added below because the DATABASE-STATE channel is
    exactly the one a new surface reopens: a route that let an anonymous
    caller tell "DSN unset" from "database down" would be the w132 defect
    back again, on a surface w132 never saw.
    The two logout routes are still deliberately NOT here — they consume a
    session, and their refusal parity is proved over eight session-lifecycle
    cases in `test_w139_remaining_w132_items.py` and
    `test_w138_patient_portal_api.py`, which is a stronger set than this one.
    So the honest count is NINE, and which nine is written out.

    `owner` is supplied on the worklist here deliberately; whether a MISSING
    required query parameter yields 422 before the 401 is settled in its own
    row below rather than allowed to contaminate this one.
    """
    return {
        "GET /exceptions/worklist": client.get("/exceptions/worklist?owner=someone", cookies=credential),
        "GET /exceptions/orders/{id}": client.get(f"/exceptions/orders/{_UNKNOWN_UUID}", cookies=credential),
        "PATCH /exceptions/{id}": client.patch(
            f"/exceptions/{_UNKNOWN_UUID}",
            json={"resolution_action": "retry_check", "resolution_note": "x"},
            cookies=credential,
        ),
        "GET /portal/me": client.get("/portal/me", cookies=credential),
        "GET /portal/me/tests": client.get("/portal/me/tests", cookies=credential),
        # w152. The administrative surface, on the database-state channel.
        "POST /admin/users/{id}/roles": client.post(
            f"/admin/users/{_UNKNOWN_UUID}/roles", json={"role": "Orderer"}, cookies=credential
        ),
        "POST /admin/users/{id}/disabled": client.post(
            f"/admin/users/{_UNKNOWN_UUID}/disabled", json={"disabled": True}, cookies=credential
        ),
        "POST /admin/patient-logins/{id}/disabled": client.post(
            f"/admin/patient-logins/{_UNKNOWN_UUID}/disabled", json={"disabled": True}, cookies=credential
        ),
        "GET /admin/audit": client.get("/admin/audit", cookies=credential),
    }


class TestEveryRefusalIsOneAnswer:
    def test_the_three_database_states_and_every_credential_state_are_one_answer(self, client, seeded, monkeypatch):
        """
        THE ROW THIS WAVE EXISTS FOR. Eight refusal situations across nine
        routes — seventy-two responses — collapsed into a set that must have
        exactly one member, in BOTH channels at once. (Seven situations across
        five routes until w152 added the administrative surface to the probe
        set; the count is stated so that a route silently leaving the set is
        visible rather than invisible.)

        Before w132 this set had three members: (503, "...CLINICAL_DSN is not
        configured..."), (500, an uncaught exception) and (401, the generic
        refusal).
        """
        observed = {}

        def record(prefix, credential):
            for name, response in authenticated_route_probes(client, credential).items():
                observed[f"{prefix} | {name}"] = (response.status_code, response.content)

        well_formed_unknown = {STAFF_COOKIE: _UNKNOWN_UUID, PATIENT_COOKIE: _UNKNOWN_UUID}

        monkeypatch.delenv("CLINICAL_DSN", raising=False)
        record("dsn unset, no credential", {})
        record("dsn unset, well-formed credential", well_formed_unknown)

        monkeypatch.setenv("CLINICAL_DSN", UNREACHABLE_DSN)
        record("dsn unreachable, no credential", {})
        record("dsn unreachable, well-formed credential", well_formed_unknown)

        monkeypatch.setenv("CLINICAL_DSN", DSN)
        record("dsn up, no credential", {})
        record("dsn up, malformed credential", {STAFF_COOKIE: "not-a-uuid", PATIENT_COOKIE: "not-a-uuid"})
        record("dsn up, unknown credential", well_formed_unknown)
        # The other principal's REAL, VALID session id. Answering this
        # differently would confirm that the id names a live session.
        record(
            "dsn up, the other principal's valid session",
            {STAFF_COOKIE: seeded["patient_session_id"], PATIENT_COOKIE: seeded["staff_session_id"]},
        )

        distinct = set(observed.values())
        assert len(distinct) == 1, (
            "the refusal is not one answer -- an anonymous caller can read the database's state "
            "or the credential's kind off it: "
            f"{ {k: (s, b[:120]) for k, (s, b) in observed.items()} }"
        )
        assert distinct.pop() == THE_REFUSAL

    def test_no_refusal_names_the_environment_variable_the_dsn_or_the_driver(self, client, seeded, monkeypatch):
        """
        The body channel specifically. The 503 that used to answer an
        unconfigured service read `CLINICAL_DSN is not configured; the
        clinical database is unavailable.` — a stranger learned the internal
        name of the setting from a route whose only job is to say
        "Authentication failed."
        """
        for dsn_state in (None, UNREACHABLE_DSN):
            if dsn_state is None:
                monkeypatch.delenv("CLINICAL_DSN", raising=False)
            else:
                monkeypatch.setenv("CLINICAL_DSN", dsn_state)
            for name, response in authenticated_route_probes(client, {}).items():
                for leak in ("CLINICAL_DSN", "postgresql://", "psycopg", "nobody", "Traceback", "5432"):
                    assert leak not in response.text, f"{name}, dsn={dsn_state!r}: leaks {leak!r}"


class TestThePositiveTwins:
    """
    Standing Rule 4. Every row above is satisfied by a service that refuses
    every request ever made to it. These are the rows that fail in that world.
    """

    def test_a_valid_staff_credential_is_not_refused(self, client, seeded):
        response = client.get("/exceptions/worklist?owner=someone", cookies={STAFF_COOKIE: seeded["staff_session_id"]})
        assert response.status_code == 200, response.text

    def test_a_valid_patient_credential_is_not_refused(self, client, seeded):
        response = client.get("/portal/me", cookies={PATIENT_COOKIE: seeded["patient_session_id"]})
        assert response.status_code == 200, response.text
        assert response.json()["patient_id"] == seeded["patient_id"]


class TestNoConnectionIsOpened:
    """
    THE GENUINE REORDERING, AND THE ONLY PLACE ONE WAS ACHIEVED — measured,
    not asserted from a function signature.

    `_presented_session_id` is declared BEFORE `_get_data_access` in
    `_get_session`'s parameter list and touches nothing; FastAPI solves a
    dependant's sub-dependencies in declaration order, so a caller who
    presents no credential is refused before a connection is opened.

    Counted rather than read, because "the signature says so" is a claim
    about FastAPI's solve order and this is the thing that would break
    silently on a framework upgrade.
    """

    @pytest.fixture()
    def connect_calls(self, monkeypatch):
        import psycopg

        calls = []
        real = psycopg.connect

        def counting(*args, **kwargs):
            calls.append((args, kwargs))
            return real(*args, **kwargs)

        monkeypatch.setattr(psycopg, "connect", counting)
        return calls

    def test_a_caller_with_no_credential_opens_no_connection(self, client, seeded, connect_calls):
        for name, response in authenticated_route_probes(client, {}).items():
            assert response.status_code == 401, name
        assert connect_calls == [], (
            "an anonymous request opened a database connection before deciding the caller "
            f"was anonymous: {len(connect_calls)} connections"
        )

    def test_a_malformed_credential_opens_no_connection(self, client, seeded, connect_calls):
        credential = {STAFF_COOKIE: "not-a-uuid", PATIENT_COOKIE: "not-a-uuid"}
        for name, response in authenticated_route_probes(client, credential).items():
            assert response.status_code == 401, name
        assert connect_calls == []

    def test_the_twin_a_well_formed_credential_DOES_open_one(self, client, seeded, connect_calls):
        """
        Required by Standing Rule 4: without it, the two rows above are
        satisfied by a counter that never records anything, and by a service
        that has stopped talking to the database altogether.

        It is also the honest half of the claim. A well-formed credential
        cannot be refused without a read, so here the guarantee is
        indistinguishability, not ordering.
        """
        response = client.get("/portal/me", cookies={PATIENT_COOKIE: _UNKNOWN_UUID})
        assert response.status_code == 401
        assert len(connect_calls) == 1, connect_calls


class TestTheRequestPathHasAConnectTimeout:
    """
    w132 fix C. The readiness probe has passed `connect_timeout=3` since it
    was written; the request path passed nothing, so libpq's default applied
    and an anonymous request could hold a worker until the OS gave up on the
    TCP connection.

    WHAT THIS CLOSES AND WHAT IT DOES NOT: it BOUNDS the resource-exhaustion
    path, it does not close it. Every anonymous request carrying a well-formed
    credential still opens a real connection and still takes a Postgres
    connection slot for the length of the request. What changed is that no
    single one can hold one for longer than the timeout while the database is
    unreachable. Closing it needs a bounded pool, which is an availability
    change to a path w128/w129 pinned and is not in this wave.
    """

    def test_the_connect_call_passes_a_bounded_timeout(self, client, seeded):
        """
        Asserted on the ARGUMENTS of the real call rather than on elapsed
        time: a timing assertion on a shared runner is flaky, and a flaky
        security test gets deleted.
        """
        import psycopg

        from clinical.endpoints import _REQUEST_CONNECT_TIMEOUT_SECONDS

        seen = []
        real = psycopg.connect

        def capturing(*args, **kwargs):
            seen.append(kwargs)
            return real(*args, **kwargs)

        psycopg.connect = capturing
        try:
            client.get("/portal/me", cookies={PATIENT_COOKIE: _UNKNOWN_UUID})
        finally:
            psycopg.connect = real

        assert seen, "no connection was opened, so this row proved nothing"
        assert seen[0].get("connect_timeout") == _REQUEST_CONNECT_TIMEOUT_SECONDS
        assert 0 < _REQUEST_CONNECT_TIMEOUT_SECONDS <= 30


class TestTheOpenQuestionTheAuditCouldNotSettle:
    def test_the_401_precedes_the_422_on_a_missing_required_query_parameter(self, client, seeded):
        """
        Audit NOT-ESTABLISHED #8: `/exceptions/worklist` declares `owner` as a
        required query parameter, and whether a missing one yields 422 BEFORE
        the 401 depends on FastAPI's solve order. Recorded as unsettled
        because settling it needs a running app.

        Settled: the dependency wins, so an anonymous caller cannot learn a
        route's parameter names by omitting them. Pinned because the other
        answer would be a small oracle and a framework upgrade could change it
        silently.
        """
        response = client.get("/exceptions/worklist")
        assert (response.status_code, response.content) == THE_REFUSAL, response.text

    def test_the_twin_a_valid_session_does_reach_the_422(self, client, seeded):
        """The validation is still there and still reachable — the row above
        is about ORDER, not about the parameter having become optional."""
        response = client.get("/exceptions/worklist", cookies={STAFF_COOKIE: seeded["staff_session_id"]})
        assert response.status_code == 422, response.text


class TestReadyzStillReportsWhatItExistsToReport:
    """
    The configuration state did not become unreportable — it stopped being
    told to strangers on routes that are not about it. `/readyz` is the route
    that exists to disclose it, its disclosure is documented, and the audit's
    verdict was: do not authenticate it and do not weaken it. These rows are
    here so that "we stopped leaking it" cannot quietly become "we stopped
    reporting it".
    """

    def test_readyz_still_names_the_unconfigured_state(self, client, monkeypatch):
        monkeypatch.delenv("CLINICAL_DSN", raising=False)
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["reason"] == "dsn_not_configured"

    def test_readyz_still_reports_an_unreachable_database(self, client, monkeypatch):
        monkeypatch.setenv("CLINICAL_DSN", UNREACHABLE_DSN)
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["reason"] == "database_unreachable"
