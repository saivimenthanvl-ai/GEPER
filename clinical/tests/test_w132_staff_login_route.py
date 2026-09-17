"""
clinical/tests/test_w132_staff_login_route.py
──────────────────────────────────────────────
w132 — `POST /auth/login`, through the real HTTP surface.

Before this wave there was NO HTTP authentication endpoint in this repository
for anyone: `DataAccess.login` had exactly one non-test caller and it was a
command-line tool, and `set_cookie` occurred ZERO times in the whole tree,
tests included. So the cookie flags asserted here are not "the defaults
somebody left" — they are the first decision anybody has made about them.

THE FOUR THINGS THIS FILE IS FOR, each of which fails differently:

  * THE ConfigurationError ROW. `login()` raises `ConfigurationError`, NOT
    `AuthenticationError`, for an account with a `totp_secret` when the layer
    has no cipher — which is every construction in this repository. A handler
    catching only `AuthenticationError` answers 500 for an MFA-enrolled
    address and 401 for every other: an existence-and-kind oracle on the
    STATUS channel that no timing equalisation touches. It is unreachable
    today only because nobody can enrol, and it would have become reachable
    silently.
  * THE COOKIE, asserted on the RAW `Set-Cookie` header. A cookie jar
    normalises attributes away, so a test that reads the jar passes while the
    header is wrong.
  * THE CREDENTIAL ACTUALLY WORKS. Perfect flags on a cookie that
    authenticates nothing is the failure the flag rows cannot see, so the
    cookie is replayed against a real staff route.
  * THE THROTTLE (fix D), including what it does NOT do.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import uuid

import pytest

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"

APP_PASSWORD = "test-app-password"
RETENTION_PASSWORD = "test-retention-password"
STAFF_PASSWORD = "correct horse battery staple"

STAFF_COOKIE = "clinical_session"
CLIENT_IP = "203.0.113.7"  # TEST-NET-3, and a valid INET value
USER_AGENT = "w132-test-agent/1.0"

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
    """Module state, cleared before and after every test, so that a 429 can
    never be mistaken for a credential refusal and this file cannot leave
    state behind for another."""
    from clinical.auth_endpoints import _LOGIN_THROTTLE

    _LOGIN_THROTTLE.reset()
    yield
    _LOGIN_THROTTLE.reset()


@pytest.fixture()
def seeded(clinical_dsn):
    """
    One organisation, one ordinary staff account, one second staff account
    (the lockout twin), and one MFA-ENROLLED account.

    The enrolment is written with SQL because nothing in this repository can
    do it any other way: `enrol_totp` raises before it writes on every
    `DataAccess` construction that exists, since no `SecretCipher`
    implementation exists anywhere. That is exactly why the 500 this file
    pins was invisible.
    """
    import psycopg

    from clinical.data_access import BcryptHasher, DataAccess

    connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
    dao = DataAccess(connection, password_hasher=BcryptHasher(rounds=4))

    org_id = dao.create_organisation("Org A")
    staff_id = dao.create_user(org_id, "staff@a.example", STAFF_PASSWORD)
    other_id = dao.create_user(org_id, "other@a.example", STAFF_PASSWORD)
    mfa_id = dao.create_user(org_id, "mfa@a.example", STAFF_PASSWORD)

    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Administrator', %s, %s)",
            (staff_id, org_id, staff_id, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
        )
        cur.execute("UPDATE users SET totp_secret = 'not-a-real-secret' WHERE user_id = %s", (mfa_id,))
    connection.commit()
    connection.close()

    return {
        "org_id": str(org_id),
        "staff_user_id": str(staff_id),
        "other_user_id": str(other_id),
        "mfa_user_id": str(mfa_id),
    }


@pytest.fixture()
def client(clinical_dsn):
    """
    A client with a REAL IP address and a known user agent, because
    `sessions.ip_address` is INET and TestClient's default peer name
    ("testclient") is not an address.
    """
    from fastapi.testclient import TestClient

    from clinical.app import app

    return TestClient(app, client=(CLIENT_IP, 45678), headers={"User-Agent": USER_AGENT})


def _login(client, seeded, **overrides):
    body = {"email": "staff@a.example", "org_id": seeded["org_id"], "password": STAFF_PASSWORD}
    body.update(overrides)
    return client.post("/auth/login", json=body)


class TestTheRouteAuthenticates:
    def test_a_correct_credential_returns_204_with_no_body(self, client, seeded):
        """
        The body is empty DELIBERATELY: no role list, no name, no
        organisation name. Anything that differed between accounts would be a
        classification oracle on a route anybody can call.
        """
        response = _login(client, seeded)
        assert response.status_code == 204, response.text
        assert response.content == b""

    def test_the_response_names_no_identifier_and_no_role(self, client, seeded):
        response = _login(client, seeded)
        blob = response.text + json.dumps(dict(response.headers))
        for leak in ("Administrator", "staff@a.example", seeded["staff_user_id"], seeded["org_id"]):
            assert leak not in blob, f"the login response discloses {leak!r}"


class TestTheCookie:
    """
    Asserted on the RAW `Set-Cookie` header, not on a parsed jar: httpx and
    TestClient normalise attributes away, so a jar-reading test passes while
    the header is wrong.
    """

    def _set_cookie_headers(self, response):
        return response.headers.get_list("set-cookie")

    def test_exactly_one_cookie_is_set_and_it_is_the_staff_one(self, client, seeded):
        """Catches the specific regression of a shared helper defaulting to
        one name, or setting both."""
        headers = self._set_cookie_headers(_login(client, seeded))
        assert len(headers) == 1, headers
        assert headers[0].startswith(f"{STAFF_COOKIE}="), headers
        assert "clinical_patient_session" not in headers[0]

    def test_the_flags_are_on_the_header(self, client, seeded):
        header = self._set_cookie_headers(_login(client, seeded))[0]
        lowered = header.lower()
        assert "httponly" in lowered, header
        assert "secure" in lowered, header
        assert "samesite=strict" in lowered, header
        assert "path=/" in lowered, header

    def test_it_is_a_session_cookie_and_host_only(self, client, seeded):
        """
        `max_age` and `domain` are OMITTED on purpose: the server-side
        `expires_at` is the authority on when a session ends, and a Domain
        attribute would widen the credential to every subdomain.
        """
        header = self._set_cookie_headers(_login(client, seeded))[0].lower()
        assert "max-age" not in header, header
        assert "expires=" not in header, header
        assert "domain=" not in header, header

    def test_the_value_is_a_real_session_id_the_route_minted(self, client, seeded):
        """
        Standing Rule 4: without this, a header with perfect flags and an
        empty or constant value passes every row above.
        """
        header = self._set_cookie_headers(_login(client, seeded))[0]
        value = header.split("=", 1)[1].split(";", 1)[0]
        minted = uuid.UUID(value)

        second = self._set_cookie_headers(_login(client, seeded))[0]
        second_value = uuid.UUID(second.split("=", 1)[1].split(";", 1)[0])
        assert minted != second_value, "two logins returned the same session id"


class TestTheCredentialActuallyWorks:
    def test_the_minted_cookie_authenticates_at_a_real_staff_route(self, client, seeded):
        """
        Standing Rule 2a in its strongest form: replayed through the REAL
        dependency, not checked against the `sessions` table. A test that
        looked at the row would prove the data is right, not that the route
        produced a usable credential.
        """
        header = _login(client, seeded).headers.get_list("set-cookie")[0]
        session_id = header.split("=", 1)[1].split(";", 1)[0]

        response = client.get("/exceptions/worklist?owner=someone", cookies={STAFF_COOKIE: session_id})
        assert response.status_code == 200, response.text

    def test_the_twin_a_credential_the_route_did_not_mint_is_refused(self, client, seeded):
        response = client.get(
            "/exceptions/worklist?owner=someone",
            cookies={STAFF_COOKIE: "00000000-0000-0000-0000-000000000000"},
        )
        assert (response.status_code, response.content) == THE_REFUSAL


class TestTheMfaEnrolledAccountIsRefusedAndNotCrashed:
    """
    The audit's single most concrete defect in the path this wave exposes.
    Asserts STATUS AND BODY TOGETHER, because this is the one case where the
    body was never the leak.
    """

    def test_an_enrolled_account_supplying_a_code_is_401_and_not_500(self, client, seeded):
        """
        A supplied code reaches `_verify_second_factor`, which raises
        `ConfigurationError` because no cipher is configured. Uncaught, this
        is a 500 where every other address is a 401.
        """
        response = client.post(
            "/auth/login",
            json={
                "email": "mfa@a.example",
                "org_id": seeded["org_id"],
                "password": STAFF_PASSWORD,
                "totp_code": "123456",
            },
        )
        assert (response.status_code, response.content) == THE_REFUSAL, response.text

    def test_an_enrolled_account_supplying_no_code_is_the_same_answer(self, client, seeded):
        """
        The other branch: with no code, `_verify_second_factor` returns False
        before it reaches the cipher, so this one was already an
        `AuthenticationError`. Both must be the same answer, or which branch
        fired is itself readable.
        """
        response = client.post(
            "/auth/login",
            json={"email": "mfa@a.example", "org_id": seeded["org_id"], "password": STAFF_PASSWORD},
        )
        assert (response.status_code, response.content) == THE_REFUSAL, response.text

    def test_the_twin_the_same_password_on_a_NON_enrolled_account_succeeds(self, client, seeded):
        """
        Standing Rule 4. Without this, both rows above are satisfied by a
        route that refuses every login attempt ever made — which would also be
        "indistinguishable".
        """
        assert _login(client, seeded).status_code == 204


class TestTheLockoutPolicyIsUnchanged:
    """
    The wave was told not to weaken the lockout. These rows prove the route
    did not: the policy still fires at the same threshold, through HTTP, and
    it still cannot be driven from one account onto another.
    """

    def test_five_wrong_passwords_through_the_route_lock_the_account(self, client, seeded):
        from clinical.auth_endpoints import _LOGIN_THROTTLE

        for _ in range(5):
            _LOGIN_THROTTLE.reset()  # isolate the lockout from the throttle
            assert _login(client, seeded, password="wrong").status_code == 401

        _LOGIN_THROTTLE.reset()
        # The CORRECT password now, which is the point: the account is locked
        # and the right credential no longer opens a session.
        locked = _login(client, seeded)
        assert (locked.status_code, locked.content) == THE_REFUSAL, locked.text

    def test_the_twin_another_account_in_the_same_organisation_is_untouched(self, client, seeded):
        """
        Standing Rule 4, and the property the schema comment on
        `users.failed_login_attempts` exists for: "an attacker holding one
        valid credential cannot keep a second account permanently unlocked",
        and its converse — one account's failures must not lock another's.
        """
        from clinical.auth_endpoints import _LOGIN_THROTTLE

        for _ in range(5):
            _LOGIN_THROTTLE.reset()
            _login(client, seeded, password="wrong")

        _LOGIN_THROTTLE.reset()
        other = _login(client, seeded, email="other@a.example")
        assert other.status_code == 204, other.text


class TestTheSessionRecordsWhoConnected:
    def test_the_route_fills_ip_address_and_user_agent_with_what_the_client_presented(
        self, client, seeded, clinical_dsn
    ):
        """
        Asserted on the VALUE, not on `is not None`: a fixture that hard-codes
        an address satisfies a non-null assertion. Paired below with a direct
        data-layer call proving the column can be NULL, so this row proves
        THE ROUTE is what fills it.
        """
        import psycopg

        header = _login(client, seeded).headers.get_list("set-cookie")[0]
        session_id = uuid.UUID(header.split("=", 1)[1].split(";", 1)[0])

        connection = psycopg.connect(clinical_dsn, autocommit=True, connect_timeout=10)
        with connection.cursor() as cur:
            cur.execute("SELECT ip_address, user_agent FROM sessions WHERE session_id = %s", (session_id,))
            ip_address, user_agent = cur.fetchone()
        connection.close()

        assert str(ip_address) == CLIENT_IP
        assert user_agent == USER_AGENT

    def test_the_twin_a_direct_data_layer_login_leaves_them_null(self, seeded, clinical_dsn):
        """The column can be NULL, and was NULL on every session a served
        request could produce before this wave — no handler passed either
        parameter, although both methods have accepted them all along."""
        import psycopg

        from clinical.data_access import BcryptHasher, DataAccess

        connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
        dao = DataAccess(connection, password_hasher=BcryptHasher(rounds=4))
        session = dao.login("other@a.example", uuid.UUID(seeded["org_id"]), STAFF_PASSWORD)
        connection.commit()
        with connection.cursor() as cur:
            cur.execute("SELECT ip_address, user_agent FROM sessions WHERE session_id = %s", (session.session_id,))
            assert cur.fetchone() == (None, None)
        connection.close()


class TestTheInProcessThrottle:
    """
    w132 fix D. NO NEW DEPENDENCY WAS ADDED, and the limits of what that buys
    are asserted here rather than only described: per-process, reset on
    restart, keyed on the socket peer and not on any header.
    """

    def test_the_eleventh_attempt_from_one_source_is_refused_by_RATE(self, client, seeded):
        from clinical.auth_endpoints import _LOGIN_THROTTLE

        _LOGIN_THROTTLE.reset()
        statuses = [_login(client, seeded, password="wrong").status_code for _ in range(10)]
        assert set(statuses) == {401}, statuses

        throttled = _login(client, seeded, password="wrong")
        assert throttled.status_code == 429, throttled.text
        assert throttled.headers.get("Retry-After"), throttled.headers

    def test_the_throttle_is_account_independent(self, client, seeded):
        """
        It must not become a second authentication policy: the limiter counts
        REQUESTS FROM A SOURCE and knows nothing about which address was
        tried. An address that does not exist trips it exactly as a real one
        does — otherwise the 429 itself would be an existence oracle.
        """
        from clinical.auth_endpoints import _LOGIN_THROTTLE

        _LOGIN_THROTTLE.reset()
        for _ in range(10):
            _login(client, seeded, email="nobody@a.example", password="wrong")
        assert _login(client, seeded, email="nobody@a.example", password="wrong").status_code == 429

        _LOGIN_THROTTLE.reset()
        for _ in range(10):
            _login(client, seeded, password="wrong")
        assert _login(client, seeded, password="wrong").status_code == 429

    def test_a_throttled_request_opens_no_database_connection(self, client, seeded, monkeypatch):
        """
        The limiter is declared BEFORE `_get_data_access`, so a refused
        attempt costs no connection, no row read and no bcrypt. If it ran
        after, it would limit the guessing and not the load.
        """
        from clinical.auth_endpoints import _LOGIN_THROTTLE

        _LOGIN_THROTTLE.reset()
        for _ in range(10):
            _login(client, seeded, password="wrong")

        import psycopg

        calls = []
        real = psycopg.connect
        monkeypatch.setattr(psycopg, "connect", lambda *a, **k: calls.append(1) or real(*a, **k))

        assert _login(client, seeded, password="wrong").status_code == 429
        assert calls == [], "a rate-limited request still opened a connection"

    def test_the_twin_a_fresh_window_allows_the_login_again(self, client, seeded):
        """
        Standing Rule 4: without it, every row above is satisfied by a route
        that returns 429 to everybody forever.
        """
        from clinical.auth_endpoints import _LOGIN_THROTTLE

        _LOGIN_THROTTLE.reset()
        for _ in range(10):
            _login(client, seeded, password="wrong")
        assert _login(client, seeded, password="wrong").status_code == 429

        _LOGIN_THROTTLE.reset()
        assert _login(client, seeded, password="wrong").status_code == 401

    def test_the_window_expires_on_its_own(self, client, seeded):
        """
        Driven on the throttle object with an injected clock rather than by
        sleeping: a test that waits sixty seconds gets deleted, and a test
        that sleeps for a shortened window is a flake on a loaded runner.
        """
        from clinical.auth_endpoints import _InProcessLoginThrottle

        throttle = _InProcessLoginThrottle(max_attempts=3, window_seconds=60, max_tracked_sources=8)
        assert [throttle.check("1.2.3.4", now=t) for t in (0.0, 1.0, 2.0)] == [None, None, None]
        assert throttle.check("1.2.3.4", now=3.0) is not None  # refused, still inside the window
        assert throttle.check("1.2.3.4", now=61.0) is None  # the first three have aged out

    def test_two_sources_have_two_windows(self, client, seeded):
        from clinical.auth_endpoints import _InProcessLoginThrottle

        throttle = _InProcessLoginThrottle(max_attempts=2, window_seconds=60, max_tracked_sources=8)
        assert throttle.check("1.2.3.4", now=0.0) is None
        assert throttle.check("1.2.3.4", now=0.1) is None
        assert throttle.check("1.2.3.4", now=0.2) is not None
        assert throttle.check("5.6.7.8", now=0.3) is None, "one source's window refused another's request"

    def test_the_table_is_bounded(self, client, seeded):
        """
        An unbounded dict keyed on an attacker-chosen source address is
        itself a denial-of-service lever: the fix for one must not be the
        other.
        """
        from clinical.auth_endpoints import _InProcessLoginThrottle

        throttle = _InProcessLoginThrottle(max_attempts=5, window_seconds=600, max_tracked_sources=16)
        for i in range(500):
            throttle.check(f"10.0.{i // 256}.{i % 256}", now=float(i))
        assert len(throttle._windows) <= 16, len(throttle._windows)

    def test_the_declared_weakness_a_second_instance_shares_nothing(self, client, seeded):
        """
        THE HONEST ROW. The comment on `_InProcessLoginThrottle` says it is
        per-process and does not hold across workers. This asserts that
        weakness rather than leaving it as prose, so nobody later reads the
        limiter as a distributed control: two instances — which is what two
        uvicorn workers are — share no state at all.
        """
        from clinical.auth_endpoints import _InProcessLoginThrottle

        worker_a = _InProcessLoginThrottle(max_attempts=1, window_seconds=60, max_tracked_sources=8)
        worker_b = _InProcessLoginThrottle(max_attempts=1, window_seconds=60, max_tracked_sources=8)
        assert worker_a.check("1.2.3.4", now=0.0) is None
        assert worker_a.check("1.2.3.4", now=0.1) is not None
        assert worker_b.check("1.2.3.4", now=0.2) is None, (
            "two instances shared state -- if that is now true, the comment on the class is wrong"
        )

    def test_the_forwarded_header_cannot_move_the_key(self, client, seeded):
        """
        `X-Forwarded-For` is deliberately not read: nothing validates it here,
        so reading it would let any caller forge the key and become
        unlimited. Asserted, because "we chose not to read a header" is
        exactly the kind of claim that quietly stops being true.
        """
        from clinical.auth_endpoints import _LOGIN_THROTTLE

        _LOGIN_THROTTLE.reset()
        for i in range(10):
            client.post(
                "/auth/login",
                json={"email": "staff@a.example", "org_id": seeded["org_id"], "password": "wrong"},
                headers={"X-Forwarded-For": f"198.51.100.{i}"},
            )
        throttled = client.post(
            "/auth/login",
            json={"email": "staff@a.example", "org_id": seeded["org_id"], "password": "wrong"},
            headers={"X-Forwarded-For": "198.51.100.200"},
        )
        assert throttled.status_code == 429, "a forged X-Forwarded-For bought a fresh window"
