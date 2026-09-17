"""
clinical/tests/test_w132_login_refusal_parity.py
─────────────────────────────────────────────────
w132 — ONE REFUSAL, ACROSS EVERY WAY THIS SERVICE CAN DECLINE, now that both
login routes exist.

The database-state half of this property is pinned for the five
pre-existing authenticated routes in
`test_w132_database_state_is_not_disclosed.py` (commit 2). THIS file is the
one that can only exist once BOTH login routes do: it adds all eight of
`login()`'s failure reasons, all six of `patient_login()`'s, and the two
cross-principal rows — a staff address at `/portal/login`, a patient address
at `/auth/login` — to the same set.

THE DEFECT, stated as it actually was rather than as it is usually described.
`_get_session` took `_get_data_access` as a SUB-dependency, so the data layer
resolved before any credential was examined, and it had two failure modes of
its own:

    CLINICAL_DSN unset       -> 503, body naming the environment variable
    CLINICAL_DSN set, down   -> uncaught psycopg exception -> 500
    database up, bad cookie  -> 401 "Authentication failed."

The BODY was already generic in the third case. The STATUS was the leak. An
anonymous caller could read the state of the clinical database off the status
code from any authenticated route, holding no credential at all.

STANDING RULE 8 IS WHY THIS FILE ASSERTS PAIRS AND SETS. The cross-tenant
oracle w129b fixed was the mirror image: both refusals were 500 and only the
body differed. A test that asserts only the body misses this one; a test that
asserts only the status misses that one; and a test that asserts
`response == GENERIC` case by case passes against a leak in a case nobody
thought to list. So every row below collects `(status_code, content)` for
EVERY refusal case it can construct and asserts THE SET HAS SIZE ONE.

WHAT IS AND IS NOT CLAIMED ABOUT ORDERING. The ruling says authentication must
be evaluated before protected database dependencies reveal their state. Taken
literally for a session-authenticated route that is impossible: validating a
session IS a database read. What is achieved is two things, and this file
tests both separately because they are different claims:

  1. A GENUINE REORDERING, for the callers it covers: a request with NO
     credential, or one that is not a UUID, is refused by
     `_presented_session_id` / `_presented_patient_session_id` before
     `_get_data_access` runs — proven in
     `test_w132_database_state_is_not_disclosed.py` by COUNTING
     `psycopg.connect` calls, not by reading the signature.
  2. UNIFORM REFUSAL, for everyone else: a caller presenting a well-formed
     credential cannot be refused without a SELECT, so the three database
     states are made indistinguishable instead of reordered. That is this
     file.
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
# with no dependence on a firewall dropping packets.
UNREACHABLE_DSN = "postgresql://nobody:nobody@127.0.0.1:1/nothing"

# The one answer. Asserted as a literal rather than imported from
# data_access, so that renaming the constant cannot silently redefine what
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


@pytest.fixture(autouse=True)
def reset_the_login_throttle():
    """
    The in-process login throttle is module state and these tests make dozens
    of login attempts from one client. Cleared before AND after every test, so
    a 429 can never be mistaken for a refusal — and so that this file cannot
    leave state behind for another.
    """
    from clinical.auth_endpoints import _LOGIN_THROTTLE

    _LOGIN_THROTTLE.reset()
    yield
    _LOGIN_THROTTLE.reset()


@pytest.fixture()
def seeded(clinical_dsn):
    """
    Everything needed to drive ALL of `login()`'s eight failure reasons and
    `patient_login()`'s six through the real HTTP surface, plus the fixtures
    the cross-principal rows need.

    The three states that cannot be reached through a public method — a
    disabled organisation, a system account, and an MFA-enrolled account —
    are written with SQL HERE, IN THE SEED. That is not the Rule 2a hazard:
    2a forbids building an EXPECTATION with a raw query. Every assertion in
    this file is made on an HTTP response.
    """
    import psycopg

    from clinical.data_access import BcryptHasher, DataAccess

    connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
    dao = DataAccess(connection, password_hasher=BcryptHasher(rounds=4))

    org_id = dao.create_organisation("Org A")
    disabled_org_id = dao.create_organisation("Org Disabled")

    staff_id = dao.create_user(org_id, "staff@a.example", STAFF_PASSWORD)
    disabled_staff_id = dao.create_user(org_id, "disabled@a.example", STAFF_PASSWORD)
    system_id = dao.create_user(org_id, "system@a.example", STAFF_PASSWORD)
    locked_id = dao.create_user(org_id, "locked@a.example", STAFF_PASSWORD)
    mfa_id = dao.create_user(org_id, "mfa@a.example", STAFF_PASSWORD)

    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Administrator', %s, %s)",
            (staff_id, org_id, staff_id, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
        )
        cur.execute("UPDATE organisations SET disabled = true WHERE org_id = %s", (disabled_org_id,))
        cur.execute("UPDATE users SET disabled = true WHERE user_id = %s", (disabled_staff_id,))
        cur.execute("UPDATE users SET is_system_account = true WHERE user_id = %s", (system_id,))
        cur.execute(
            "UPDATE users SET locked_until = %s, failed_login_attempts = 5 WHERE user_id = %s",
            (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30), locked_id),
        )
        # THE ONLY WAY AN MFA-ENROLLED ACCOUNT CAN EXIST. `enrol_totp` raises
        # before it writes on every DataAccess construction in this
        # repository (no SecretCipher implementation exists), which is exactly
        # why the 500 this seeds for was invisible.
        cur.execute("UPDATE users SET totp_secret = 'not-a-real-secret' WHERE user_id = %s", (mfa_id,))
    connection.commit()

    staff = dao.login("staff@a.example", org_id, STAFF_PASSWORD)
    patient_id = dao.create_patient(staff, "Alice Anderson", dt.date(1980, 1, 1), "F")
    dao.enrol_patient_login(staff, patient_id, "alice@portal.example", PATIENT_PASSWORD)
    patient_session = dao.patient_login("alice@portal.example", org_id, PATIENT_PASSWORD)
    connection.commit()
    connection.close()

    return {
        "org_id": str(org_id),
        "disabled_org_id": str(disabled_org_id),
        "staff_session_id": str(staff.session_id),
        "patient_session_id": str(patient_session.session_id),
        "patient_id": str(patient_id),
    }


@pytest.fixture()
def client(clinical_dsn):
    from fastapi.testclient import TestClient

    from clinical.app import app

    return TestClient(app)


# ─── the refusal cases, built once and reused by every row ───────────────────

_UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000"


def _authenticated_route_probes(client, credential):
    """
    FIVE of the seven mounted routes that require a principal, exercised with
    `credential` (a dict of cookies, possibly empty).

    ── CORRECTED IN w138. THIS USED TO SAY "Every mounted route that ───────
    requires a principal". It was true when written and is FALSE at
    a931869: `POST /auth/logout` and `POST /portal/logout` were added in the
    same wave as this file, both require a principal, and NEITHER IS IN ANY
    REFUSAL-PARITY SET IN THIS REPOSITORY. A logout route is an easy one to
    omit precisely because its success is a 204 rather than a 200.

    The patient half of that is closed by
    `test_w138_patient_portal_api.py::TestEveryPortalRefusalIsOnePairOn
    EveryRoute`, which collects eight credential states across all three
    authenticated PORTAL routes -- `/portal/logout` included. The STAFF half
    (`POST /auth/logout`) is still in no set; it is carded in
    `w138-patient-portal-api-audit.md` as C-16 for the wave that owns the
    remaining w132 items, because widening this dict changes the staff
    refusal surface and that is not Wave 4's to change.

    DO NOT re-widen the claim above without adding the two routes.
    ────────────────────────────────────────────────────────────────────────

    `owner` is supplied on the worklist deliberately: whether a missing
    required query parameter yields 422 BEFORE the 401 was an open question
    in the audit. It is settled in its own row below rather than left to
    contaminate this one.
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
    }


def _login_probes(client, seeded, throttle):
    """
    All eight of `login()`'s failure reasons and FOUR OF SIX of
    `patient_login()`'s, driven through the real routes.

    ── CORRECTED IN w138. THIS DOCSTRING USED TO SAY "all six". ────────────
    It was false, and it was the kind of false that hides a hole: the dict
    below posts five bodies to `/portal/login`, of which one
    ("staff address at /portal/login") is a CROSS-PRINCIPAL row and not one
    of the six reasons at all. The four reasons actually exercised here are
    unknown_organisation, organisation_disabled, unknown_patient_login and
    invalid_password.

    THE TWO THAT WERE MISSING ARE `locked_out` AND `patient_login_disabled`
    — a credential that EXISTS and is locked, and one that EXISTS and has
    been revoked. They are exactly the two that separate an UNAUTHORISED
    patient from a NONEXISTENT one, and the staff half of this same dict
    carries both of its equivalents ("staff locked out", "staff disabled
    account"), so the gap was patient-only.

    THEY ARE NOW IN A SET OF SIZE ONE IN
    `test_w138_patient_portal_api.py::TestTheLoginRefusalIsOneAnswerOver
    AllSixReasons`, whose case list is DERIVED FROM `patient_login`'s own
    source rather than typed out — which is the defence this docstring
    turned out to need. DO NOT re-widen the claim here without moving the
    probes; the two files are meant to be read together.
    ────────────────────────────────────────────────────────────────────────

    The throttle is cleared between attempts: this function makes more
    requests from one source than the limiter allows, and a 429 here would be
    a different refusal for a reason that has nothing to do with credentials.
    That IS the limiter working; it is measured in its own file.
    """
    org = seeded["org_id"]

    def post(path, body):
        throttle.reset()
        return client.post(path, json=body)

    return {
        # login(): unknown_organisation
        "staff unknown org": post(
            "/auth/login", {"email": "staff@a.example", "org_id": _UNKNOWN_UUID, "password": STAFF_PASSWORD}
        ),
        # login(): organisation_disabled
        "staff disabled org": post(
            "/auth/login",
            {"email": "staff@a.example", "org_id": seeded["disabled_org_id"], "password": STAFF_PASSWORD},
        ),
        # login(): unknown_user
        "staff unknown address": post(
            "/auth/login", {"email": "nobody@a.example", "org_id": org, "password": STAFF_PASSWORD}
        ),
        # login(): locked_out
        "staff locked out": post(
            "/auth/login", {"email": "locked@a.example", "org_id": org, "password": STAFF_PASSWORD}
        ),
        # login(): invalid_password
        "staff wrong password": post("/auth/login", {"email": "staff@a.example", "org_id": org, "password": "wrong"}),
        # login(): user_disabled -- correct password, so it is the disabled
        # check that fires, and it fires AFTER the password on purpose.
        "staff disabled account": post(
            "/auth/login", {"email": "disabled@a.example", "org_id": org, "password": STAFF_PASSWORD}
        ),
        # login(): system_account
        "staff system account": post(
            "/auth/login", {"email": "system@a.example", "org_id": org, "password": STAFF_PASSWORD}
        ),
        # login(): invalid_totp, the AuthenticationError branch -- an enrolled
        # account with no code supplied.
        "staff mfa enrolled, no code": post(
            "/auth/login", {"email": "mfa@a.example", "org_id": org, "password": STAFF_PASSWORD}
        ),
        # THE ConfigurationError BRANCH. An enrolled account WITH a code
        # supplied reaches _verify_second_factor, which raises
        # ConfigurationError because no cipher is configured -- which is every
        # construction that exists. Uncaught, this is a 500 where every other
        # address is a 401: a principal-classification oracle on the status
        # channel that no timing equalisation touches.
        "staff mfa enrolled, code supplied": post(
            "/auth/login",
            {"email": "mfa@a.example", "org_id": org, "password": STAFF_PASSWORD, "totp_code": "123456"},
        ),
        # patient_login(): the same six shapes against the other store.
        "patient unknown org": post(
            "/portal/login",
            {"email": "alice@portal.example", "org_id": _UNKNOWN_UUID, "password": PATIENT_PASSWORD},
        ),
        "patient disabled org": post(
            "/portal/login",
            {"email": "alice@portal.example", "org_id": seeded["disabled_org_id"], "password": PATIENT_PASSWORD},
        ),
        "patient unknown address": post(
            "/portal/login", {"email": "nobody@portal.example", "org_id": org, "password": PATIENT_PASSWORD}
        ),
        "patient wrong password": post(
            "/portal/login", {"email": "alice@portal.example", "org_id": org, "password": "wrong"}
        ),
        # THE CROSS-PRINCIPAL ROWS. A staff address at the portal, and a
        # patient address at the staff route. Each exists -- in the OTHER
        # store -- and must be refused exactly as an address existing nowhere
        # is.
        "staff address at /portal/login": post(
            "/portal/login", {"email": "staff@a.example", "org_id": org, "password": STAFF_PASSWORD}
        ),
        "patient address at /auth/login": post(
            "/auth/login", {"email": "alice@portal.example", "org_id": org, "password": PATIENT_PASSWORD}
        ),
    }


class TestEveryRefusalIsOneAnswer:
    """
    The set-of-size-one row, in both channels at once, over every refusal this
    service can produce without a valid credential.
    """

    def test_the_three_database_states_are_indistinguishable(self, client, seeded, monkeypatch):
        """
        NOT CONFIGURED, UNREACHABLE, and UP-WITH-A-BAD-CREDENTIAL, on every
        authenticated route and on both login routes. Before w132 these were
        503, 500 and 401.
        """
        observed = {}

        def record(prefix, responses):
            for name, response in responses.items():
                observed[f"{prefix} | {name}"] = (response.status_code, response.content)

        credential = {STAFF_COOKIE: _UNKNOWN_UUID, PATIENT_COOKIE: _UNKNOWN_UUID}
        valid_body = {"email": "staff@a.example", "org_id": seeded["org_id"], "password": STAFF_PASSWORD}
        patient_body = {
            "email": "alice@portal.example",
            "org_id": seeded["org_id"],
            "password": PATIENT_PASSWORD,
        }

        monkeypatch.delenv("CLINICAL_DSN", raising=False)
        record("dsn unset", _authenticated_route_probes(client, credential))
        record(
            "dsn unset",
            {
                "POST /auth/login": client.post("/auth/login", json=valid_body),
                "POST /portal/login": client.post("/portal/login", json=patient_body),
            },
        )

        monkeypatch.setenv("CLINICAL_DSN", UNREACHABLE_DSN)
        record("dsn unreachable", _authenticated_route_probes(client, credential))
        record(
            "dsn unreachable",
            {
                "POST /auth/login": client.post("/auth/login", json=valid_body),
                "POST /portal/login": client.post("/portal/login", json=patient_body),
            },
        )

        monkeypatch.setenv("CLINICAL_DSN", DSN)
        record("dsn up, unknown credential", _authenticated_route_probes(client, credential))

        distinct = set(observed.values())
        assert len(distinct) == 1, (
            "the refusal is not one answer -- an anonymous caller can read the database's state: "
            f"{ {k: (s, b[:120]) for k, (s, b) in observed.items()} }"
        )
        assert distinct.pop() == THE_REFUSAL

    def test_every_credential_state_and_every_login_failure_is_the_same_answer(self, client, seeded):
        """
        The whole refusal surface in one set: no credential, a malformed one,
        an unknown one, the OTHER principal's valid one, and all fourteen
        data-layer failure reasons through the two login routes.
        """
        from clinical.auth_endpoints import _LOGIN_THROTTLE

        observed = {}
        for credential_name, credential in {
            "no credential": {},
            "malformed": {STAFF_COOKIE: "not-a-uuid", PATIENT_COOKIE: "not-a-uuid"},
            "unknown uuid": {STAFF_COOKIE: _UNKNOWN_UUID, PATIENT_COOKIE: _UNKNOWN_UUID},
            "the other principal's valid session": {
                STAFF_COOKIE: seeded["patient_session_id"],
                PATIENT_COOKIE: seeded["staff_session_id"],
            },
        }.items():
            for name, response in _authenticated_route_probes(client, credential).items():
                observed[f"{credential_name} | {name}"] = (response.status_code, response.content)

        for name, response in _login_probes(client, seeded, _LOGIN_THROTTLE).items():
            observed[f"login | {name}"] = (response.status_code, response.content)

        distinct = set(observed.values())
        assert len(distinct) == 1, f"refusals differ: { {k: (s, b[:120]) for k, (s, b) in observed.items()} }"
        assert distinct.pop() == THE_REFUSAL

    def test_no_refusal_names_the_environment_variable_or_the_dsn(self, client, seeded, monkeypatch):
        """
        Body channel, specifically. The 503 that used to answer an
        unconfigured service said `CLINICAL_DSN is not configured; the
        clinical database is unavailable.` — a stranger learned the internal
        name of the setting from a route whose only job is to say
        "Authentication failed."
        """
        for dsn_state in (None, UNREACHABLE_DSN):
            if dsn_state is None:
                monkeypatch.delenv("CLINICAL_DSN", raising=False)
            else:
                monkeypatch.setenv("CLINICAL_DSN", dsn_state)
            for name, response in _authenticated_route_probes(client, {}).items():
                text = response.text
                for leak in ("CLINICAL_DSN", "postgresql://", "psycopg", "nobody", "Traceback"):
                    assert leak not in text, f"{name} with dsn={dsn_state!r} leaks {leak!r}: {text}"


class TestThePositiveTwins:
    """
    Standing Rule 4. Every row above is satisfied by a service that refuses
    every request ever made to it, and by one that cannot start. These are the
    rows that fail in that world.
    """

    def test_a_valid_staff_credential_is_not_refused(self, client, seeded):
        response = client.get("/exceptions/worklist?owner=someone", cookies={STAFF_COOKIE: seeded["staff_session_id"]})
        assert response.status_code == 200, response.text

    def test_a_valid_patient_credential_is_not_refused(self, client, seeded):
        response = client.get("/portal/me", cookies={PATIENT_COOKIE: seeded["patient_session_id"]})
        assert response.status_code == 200, response.text
        assert response.json()["patient_id"] == seeded["patient_id"]

    def test_a_correct_staff_login_is_not_refused(self, client, seeded):
        response = client.post(
            "/auth/login",
            json={"email": "staff@a.example", "org_id": seeded["org_id"], "password": STAFF_PASSWORD},
        )
        assert response.status_code == 204, response.text
        assert (response.status_code, response.content) != THE_REFUSAL

    def test_a_correct_patient_login_is_not_refused(self, client, seeded):
        response = client.post(
            "/portal/login",
            json={"email": "alice@portal.example", "org_id": seeded["org_id"], "password": PATIENT_PASSWORD},
        )
        assert response.status_code == 204, response.text


class TestTheTwoRoutesNeverConsultEachOthersStore:
    """
    THE STRUCTURAL FORM OF THE RULING, and what stops the two routes being
    merged back into one in six months by somebody who reads "one endpoint
    would be simpler".

    READ FROM THE AST, NOT FROM `inspect.signature`. This repository already
    has a recorded incident on that point: `auditable` does not apply
    `functools.wraps`, so a signature test written with `inspect` PASSED
    AGAINST THE WRONG IMPLEMENTATION (`test_patient_identity.py:733`'s own
    docstring).

    Behavioural tests cannot see this property. A combined handler that tried
    the patient store and fell back to the staff store would answer every row
    above IDENTICALLY — the leak is in the bcrypt work it spends, which is a
    timing channel, and a timing assertion on a shared runner is a flake, and
    a flaky security test gets deleted. So the property is asserted
    structurally, where it cannot flake.
    """

    @staticmethod
    def _handlers():
        import ast
        import pathlib as _pathlib

        source = (_pathlib.Path(__file__).resolve().parent.parent / "auth_endpoints.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        found = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                for arg in decorator.args:
                    if isinstance(arg, ast.Constant) and arg.value in ("/auth/login", "/portal/login"):
                        found[arg.value] = node
        return found

    @staticmethod
    def _attribute_calls(node):
        import ast

        return {
            call.func.attr
            for call in ast.walk(node)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
        }

    def test_the_guard_found_both_handlers(self):
        """
        Standing Rule 4, in the shape `test_patient_identity.py:834` already
        uses: without this row, a renamed decorator makes every assertion
        below pass vacuously.
        """
        handlers = self._handlers()
        assert set(handlers) == {"/auth/login", "/portal/login"}, sorted(handlers)

    def test_the_staff_handler_cannot_reach_patient_login(self):
        calls = self._attribute_calls(self._handlers()["/auth/login"])
        assert "login" in calls, calls
        assert "patient_login" not in calls, (
            "the staff login handler consults patient_logins -- a caller could then tell a "
            "patient address from an address that does not exist, by timing"
        )

    def test_the_patient_handler_cannot_reach_login(self):
        calls = self._attribute_calls(self._handlers()["/portal/login"])
        assert "patient_login" in calls, calls
        assert "login" not in calls, (
            "the patient login handler consults users -- the cross-principal existence oracle, "
            "arriving through the back door"
        )

    def test_neither_handler_mints_a_session_without_authenticating(self):
        """
        The census the wave inherits: no new `_create_system_session` call
        site. That method creates a real, valid bearer credential with no
        credential check, and this module is exactly the kind of place a fifth
        call site appears.

        NOT a substring search: this module's own docstring says "NO NEW
        `_create_system_session` CALL SITE", so `"_create_system_session" in
        source` is TRUE on the correct code. A grep-shaped guard here would
        fail green and be deleted. The AST distinguishes the sentence from
        the call.
        """
        import ast
        import pathlib as _pathlib

        tree = ast.parse(
            (_pathlib.Path(__file__).resolve().parent.parent / "auth_endpoints.py").read_text(encoding="utf-8")
        )
        called = set()
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            if isinstance(call.func, ast.Attribute):
                called.add(call.func.attr)
            elif isinstance(call.func, ast.Name):
                called.add(call.func.id)

        assert "_create_system_session" not in called, called
        # The non-vacuity twin: the walk finds the calls that ARE there, so a
        # matcher that always returns an empty set cannot pass this.
        assert {"login", "patient_login"} <= called, called


class TestTheCookiesAreKeptApart:
    def test_a_patient_login_sets_only_the_patient_cookie_scoped_to_the_portal(self, client, seeded):
        response = client.post(
            "/portal/login",
            json={
                "email": "alice@portal.example",
                "org_id": seeded["org_id"],
                "password": PATIENT_PASSWORD,
            },
        )
        assert response.status_code == 204, response.text
        headers = response.headers.get_list("set-cookie")
        assert len(headers) == 1, headers
        assert headers[0].startswith(f"{PATIENT_COOKIE}="), headers
        assert STAFF_COOKIE + "=" not in headers[0]
        assert "path=/portal" in headers[0].lower(), headers[0]

    def test_the_minted_patient_credential_works_at_the_portal(self, client, seeded):
        """
        Rule 2a in its strongest form: replayed through the REAL dependency,
        not checked against the `patient_sessions` table.
        """
        header = client.post(
            "/portal/login",
            json={
                "email": "alice@portal.example",
                "org_id": seeded["org_id"],
                "password": PATIENT_PASSWORD,
            },
        ).headers.get_list("set-cookie")[0]
        session_id = header.split("=", 1)[1].split(";", 1)[0]

        response = client.get("/portal/me", cookies={PATIENT_COOKIE: session_id})
        assert response.status_code == 200, response.text
        assert response.json()["patient_id"] == seeded["patient_id"]

    def test_the_minted_patient_credential_is_refused_by_the_STAFF_dependency(self, client, seeded):
        """Both directions, on the body and the status — closing the loop end
        to end against the ids the LOGIN ROUTES mint, not only against ids a
        fixture made."""
        header = client.post(
            "/portal/login",
            json={
                "email": "alice@portal.example",
                "org_id": seeded["org_id"],
                "password": PATIENT_PASSWORD,
            },
        ).headers.get_list("set-cookie")[0]
        session_id = header.split("=", 1)[1].split(";", 1)[0]

        response = client.get("/exceptions/worklist?owner=someone", cookies={STAFF_COOKIE: session_id})
        assert (response.status_code, response.content) == THE_REFUSAL

    def test_the_minted_staff_credential_is_refused_by_the_PORTAL_dependency(self, client, seeded):
        header = client.post(
            "/auth/login",
            json={"email": "staff@a.example", "org_id": seeded["org_id"], "password": STAFF_PASSWORD},
        ).headers.get_list("set-cookie")[0]
        session_id = header.split("=", 1)[1].split(";", 1)[0]

        response = client.get("/portal/me", cookies={PATIENT_COOKIE: session_id})
        assert (response.status_code, response.content) == THE_REFUSAL
