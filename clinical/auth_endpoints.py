"""
clinical/auth_endpoints.py
──────────────────────────
THE HTTP AUTHENTICATION SURFACE (w132). Two login routes, one mechanism.

`POST /auth/login`   -> DataAccess.login          -> `sessions`         (staff)
`POST /portal/login` -> DataAccess.patient_login  -> `patient_sessions` (patient)

TWO ROUTES, AND THE ROUTE IS WHAT NAMES THE PRINCIPAL. Neither handler
consults the other's store, and that is the whole reason there are two of
them. A single endpoint that tried both stores could not avoid disclosing
which one an address lives in: the two methods each spend exactly ONE bcrypt
verification on an address absent from their own store
(`_equalise_password_work`), so "try A, then B" costs one unit for a patient
address and two for a staff address — a whole deliberate cost-12 work factor,
separable by one unrepeated request, with no statistics required. Equalising
that would mean a new combined authentication method inside
`data_access.py`, which is a second authentication policy wearing a different
hat. A request to `/portal/login` is a request to authenticate against
`patient_logins`, full stop.

WHY THIS MODULE AND NOT `portal_endpoints.py`. That file records "NO LOGIN
ROUTE" as a deliberate absence, with the reason: adding one for patients only
would make the patient surface the reference implementation for staff
authentication over HTTP. Both routes live here so that neither is the
other's precedent and so that anyone editing one reads the other.

NO PREFIX ON THE ROUTER, DELIBERATELY. Each route declares its full path, so
this file cannot silently acquire a patient route under `/auth/` or a staff
route under `/portal/`.

WHAT IS NOT HERE:
  * NO LOGOUT. `terminate_session` ends SOMEONE ELSE'S session and is
    Administrator-gated; self-logout needs a new data-layer method for each
    principal, and that is a separate, rulable piece of work. A login route
    with no logout is incomplete but coherent.
  * NO `/auth/me`. The login response is a 204 and a cookie. Anything in the
    body that differed between principals would be a classification oracle,
    and there is no UI to need it.
  * NO NEW `_create_system_session` CALL SITE. The four stay four. Sessions
    here are minted only by `login` / `patient_login`, which authenticate
    first.
  * NO CSRF TOKEN, NO ORIGIN CHECK, NO CORS. `SameSite=Strict` below is the
    control this wave ships; an Origin check needs a ruling on the portal's
    origin that does not exist. Stated so the absence is read as a gap with a
    reason, not as a box someone ticked.
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
import uuid
from typing import Deque, Dict, Optional

from collections import deque

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from clinical.data_access import (
    AuthenticationError,
    ConfigurationError,
    DataAccess,
)
from clinical.endpoints import _SESSION_COOKIE, _anonymous_refusal, _get_data_access
from clinical.portal_endpoints import _PATIENT_SESSION_COOKIE

router = APIRouter(tags=["authentication"])


# ─── the request bodies ──────────────────────────────────────────────────────
#
# `org_id` IS EXPLICIT, AND IT IS THE ONE OPEN RULING IN THIS FILE. An email
# is unique only WITHIN an organisation (`users_org_email_unique`,
# `patient_logins_org_email_unique`), so both data-layer methods require an
# org_id and a lookup keyed on the address alone would authenticate one
# tenant's user against another tenant's credential. Nothing in this
# repository derives an org_id from a hostname, a subdomain, a header or a
# path, so the body carries it: that is the only shape that needs no new
# lookup table and no new inference. If a deployment ruling later says "one
# organisation per hostname", it replaces this field and touches nothing else.
#
# It is NOT itself an oracle: `login` and `patient_login` both spend a full
# `_equalise_password_work` before refusing an unknown or disabled
# organisation, so a wrong org_id costs and answers exactly what a wrong
# password does.


class StaffLoginRequest(BaseModel):
    """
    `totp_code` is passed straight through to `DataAccess.login`, which uses
    it only when the account has a `totp_secret`. THIS IS NOT A CLAIM THAT MFA
    IS AVAILABLE: nothing in this repository can enrol anybody (there is no
    `SecretCipher` implementation and `enrol_totp` has no non-test caller).
    The field exists so that an account enrolled by some other means can still
    log in, not to advertise a feature.
    """

    email: str
    org_id: uuid.UUID
    password: str
    totp_code: Optional[str] = None


class PatientLoginRequest(BaseModel):
    """No second factor, and its absence is declared rather than forgotten —
    `data_access.py`'s patient-authentication header explains why patient MFA
    is a ruling and not an omission, and this wave does not make it."""

    email: str
    org_id: uuid.UUID
    password: str


# ─── the in-process login throttle ───────────────────────────────────────────


class _InProcessLoginThrottle:
    """
    A fixed-window attempt counter, keyed on the source address, IN THIS
    PROCESS ONLY.

    ╔═══════════════════════════════════════════════════════════════════════╗
    ║ WHAT THIS IS NOT. Read this before relying on it.                     ║
    ║                                                                       ║
    ║  * IT IS PER-PROCESS. Two uvicorn workers are two independent         ║
    ║    counters, so N workers multiply every limit below by N. It does    ║
    ║    NOT hold across workers and it does NOT hold across replicas.      ║
    ║  * IT RESETS ON RESTART. A deploy, a crash or an OOM kill clears      ║
    ║    every window. An attacker who can induce a restart clears it too.  ║
    ║  * IT TRUSTS THE SOCKET AND ONLY THE SOCKET. `X-Forwarded-For` is     ║
    ║    deliberately NOT read: nothing in this repository validates it, so ║
    ║    reading it would let any caller forge the key and become           ║
    ║    unlimited. The consequence is the other error: behind a reverse    ║
    ║    proxy every request appears to come from the proxy, so the limit   ║
    ║    becomes a GLOBAL cap on login attempts rather than a per-client    ║
    ║    one. Whoever puts a proxy in front of this service must decide     ║
    ║    which of the two is wanted; the choice is not made here.           ║
    ║  * IT IS NOT A RATE LIMITER FOR THE SERVICE. It guards the two login  ║
    ║    routes. Nothing else is throttled.                                 ║
    ║  * IPv6 IS KEYED PER ADDRESS, not per /64, so a caller with a routed  ║
    ║    prefix has as many buckets as they have addresses.                 ║
    ╚═══════════════════════════════════════════════════════════════════════╝

    WHAT IT IS FOR, precisely. Per-account lockout
    (MAX_FAILED_LOGIN_ATTEMPTS = 5, LOCKOUT_MINUTES = 30) counts the wrong
    thing for two attacks that a public login route creates:

      * CREDENTIAL STUFFING — one password against ten thousand addresses
        never reaches 5 on any single account, so the lockout never fires;
      * LOCKOUT ABUSE — five wrong passwords lock an account for thirty
        minutes, the counter resets only on a SUCCESSFUL login by that same
        account (so the victim cannot clear it), there is no administrative
        unlock anywhere in this repository, and nothing limits how often an
        attacker repeats it. In a clinical system that is an availability
        attack, and availability is a safety property.

    Both are attempts-per-source problems and this counts attempts per source.
    THE LOCKOUT POLICY IS UNCHANGED AND UNWEAKENED — this sits in front of it;
    it does not replace it, soften it, or add a second authentication policy.
    A caller who exhausts the window is refused by rate, not by credential,
    and no credential is examined and no database connection is opened for
    the refused request.

    NO NEW DEPENDENCY. `slowapi` and friends were not added: that is a
    dependency decision this wave was not given. The cost of that is
    everything in the box above. A limiter whose weaknesses are written down
    is worth more than one presented as complete.
    """

    def __init__(self, max_attempts: int, window_seconds: float, max_tracked_sources: int) -> None:
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._max_tracked_sources = max_tracked_sources
        # A lock, because uvicorn runs sync dependencies in a thread pool and
        # two threads pruning one deque is a mutation during iteration.
        self._lock = threading.Lock()
        self._windows: Dict[str, Deque[float]] = {}

    def check(self, source: str, now: Optional[float] = None) -> Optional[int]:
        """
        Record an attempt from `source`. Returns None to allow it, or the
        number of seconds until the window frees up to refuse it.

        The monotonic clock, not the wall clock: a clock step backwards must
        not hand out a free window, and one forwards must not lock anybody out
        for a day.
        """
        moment = time.monotonic() if now is None else now
        with self._lock:
            window = self._windows.setdefault(source, deque())
            while window and window[0] <= moment - self._window_seconds:
                window.popleft()
            if len(window) >= self._max_attempts:
                return max(1, int(window[0] + self._window_seconds - moment) + 1)
            window.append(moment)
            # AFTER the insert, not before: evicting first leaves room for the
            # new key and the table settles at the cap PLUS ONE, which is the
            # kind of off-by-one a bound is worthless with. The entry just
            # added has the newest timestamp, so it is never the one dropped.
            self._evict(moment)
            return None

    def _evict(self, moment: float) -> None:
        """
        Bound the memory. An unbounded dict keyed on an attacker-chosen source
        address is itself a denial-of-service lever — the fix for one must not
        be the other. Fully expired windows go first; if the table is still
        over its cap, the oldest are dropped, which at worst gives the dropped
        source a fresh window.
        """
        for key in [k for k, w in self._windows.items() if not w or w[-1] <= moment - self._window_seconds]:
            del self._windows[key]
        if len(self._windows) <= self._max_tracked_sources:
            return
        for key in sorted(self._windows, key=lambda k: self._windows[k][-1])[
            : len(self._windows) - self._max_tracked_sources
        ]:
            del self._windows[key]

    def reset(self) -> None:
        """For tests. Nothing in a request path calls this."""
        with self._lock:
            self._windows.clear()


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


# Ten attempts per source per minute. Chosen against the lockout policy rather
# than out of the air: five wrong passwords lock one account, so one source
# can cost at most two account-lockouts per minute, while a person mistyping a
# password twice is never touched.
_LOGIN_THROTTLE = _InProcessLoginThrottle(
    max_attempts=_int_env("CLINICAL_LOGIN_MAX_ATTEMPTS_PER_WINDOW", 10),
    window_seconds=_int_env("CLINICAL_LOGIN_WINDOW_SECONDS", 60),
    max_tracked_sources=_int_env("CLINICAL_LOGIN_MAX_TRACKED_SOURCES", 4096),
)


def _throttle_source(request: Request) -> str:
    """The socket peer, or a constant when there is none. NOT a header."""
    client = request.client
    return client.host if client and client.host else "unknown"


def _rate_limit_login(request: Request) -> None:
    """
    FastAPI dependency: the throttle, declared FIRST on both routes so it runs
    before `_get_data_access` — a refused request opens no connection, reads
    no row and costs no bcrypt.

    IT ANSWERS 429, NOT THE GENERIC 401, AND THAT IS DELIBERATE. The refusal
    parity this service holds to is about what an anonymous caller can learn
    about ACCOUNTS and about the DATABASE. A 429 discloses one fact — that
    this source has made too many requests — which the source already knows,
    which is independent of every account and of the database's state, and
    which a client needs in order to back off rather than hammer. Collapsing
    it into the 401 would make an honest client indistinguishable from a
    guessing one, to itself.
    """
    retry_after = _LOGIN_THROTTLE.check(_throttle_source(request))
    if retry_after is None:
        return
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many login attempts. Try again shortly.",
        headers={"Retry-After": str(retry_after)},
    )


# ─── the cookie ──────────────────────────────────────────────────────────────


def _set_session_cookie(response: Response, name: str, session_id: uuid.UUID, path: str) -> None:
    """
    THE ONLY PLACE IN THIS REPOSITORY THAT SETS A COOKIE, and before w132
    there was none at all — `set_cookie` occurred zero times in the whole
    tree, tests included. So these flags are not "the defaults someone left";
    they are the first decision anybody has made about them, and a second
    route setting its own cookie with its own flags is the regression the
    census test exists to catch.

    Each flag, with the reason from this system rather than from a checklist:

      httponly=True  The session id IS the entire bearer credential — both
                     dependencies accept it from an `Authorization: Bearer`
                     header as readily as from the cookie. A script that can
                     read it holds a full session.
      secure=True    Nothing in this repository terminates TLS. The flag does
                     not provide TLS; it stops the browser sending the
                     credential over a channel that has none. NOTE THE
                     CONSEQUENCE: over plain HTTP the cookie is set and never
                     sent back, so TLS termination and this flag are one
                     decision and must land together.
      samesite=      The CSRF control, and the only one this wave ships.
        "strict"     Affordable here because nothing cross-navigates into the
                     clinical service. It does NOT close login CSRF — a
                     cross-site POST that SETS a cookie is not governed by the
                     victim's cookie being withheld — and closing that needs
                     an Origin check, which needs a ruling on the portal's
                     origin that does not exist.
      path           `/` for staff, `/portal` for patient, so a browser
                     holding both does not send the patient credential to
                     staff routes at all.
      max_age        OMITTED, so it is a session cookie. The server-side
                     `expires_at` (SESSION_ABSOLUTE_HOURS = 24) is the
                     authority; a max_age that disagreed would be a second
                     answer to "when does this end".
      domain         OMITTED, so it is host-only. Setting it widens the cookie
                     to every subdomain, which is a decision nobody has made.
    """
    response.set_cookie(
        key=name,
        value=str(session_id),
        httponly=True,
        secure=True,
        samesite="strict",
        path=path,
    )


def _client_ip(request: Request) -> Optional[str]:
    """
    The socket peer, if it is an IP address; otherwise None.

    `sessions.ip_address` and `patient_sessions.ip_address` are INET, so a
    non-address peer name (a unix socket, a test client) must not be handed
    to the INSERT. NOT read from `X-Forwarded-For`: nothing validates that
    header here, so trusting it would let any caller write a chosen address
    into the session and audit records — poisoning exactly the attribution
    those columns exist to provide.
    """
    client = request.client
    if client is None or not client.host:
        return None
    try:
        return str(ipaddress.ip_address(client.host))
    except ValueError:
        return None


# ─── the two routes ──────────────────────────────────────────────────────────
#
# THE REFUSAL IS ONE OBJECT AND IT IS THE SAME OBJECT THE SESSION DEPENDENCIES
# USE. `_anonymous_refusal()` — 401, `{"detail": "Authentication failed."}`.
# `login()` has eight failure reasons and `patient_login()` six; all fourteen
# go to the audit log and none reaches the caller. The caller learns nothing;
# the audit log learns everything.


def _refuse_uniformly(call):
    """
    Run a data-layer authentication call and convert EVERY failure into the
    one refusal.

    `AuthenticationError` is the expected one. The other two are not
    decoration:

      * `ConfigurationError` — THE DEFECT THIS WAVE WAS TOLD NOT TO SHIP
        AROUND. `login()` raises it, not `AuthenticationError`, when an
        account has a `totp_secret` and the layer has no cipher or verifier
        — which is EVERY construction that exists, since no non-test
        `DataAccess(...)` passes either. A handler catching only
        `AuthenticationError` would answer 500 for an MFA-enrolled address
        and 401 for every other, which is an existence-and-kind oracle on the
        status channel that no timing equalisation touches. It is unreachable
        today only because nobody can enrol; it becomes reachable the moment
        anyone inserts a secret by hand, and it would have become reachable
        silently.
      * `Exception` — the backstop, and the reason is that a login route is
        the one place where "your credentials are wrong" and "something went
        wrong here" must be the same answer. A caller who can tell a crash
        from a refusal can hunt for inputs that crash. The cost is honest and
        is stated: a genuine bug on this path is reported to the caller as a
        401. The audit trail is where it is visible — every data-layer failure
        path logs before it raises — and `/readyz` is where infrastructure
        state is reported on purpose.
    """
    try:
        return call()
    except (AuthenticationError, ConfigurationError):
        raise _anonymous_refusal()
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 -- see the docstring; uniformity is the point
        raise _anonymous_refusal()


@router.post(
    "/auth/login",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Authenticate a STAFF user and open a session",
    responses={
        204: {"description": "Authenticated; the session cookie is set"},
        401: {"description": "Authentication failed"},
        429: {"description": "Too many login attempts from this source"},
    },
)
async def staff_login(
    payload: StaffLoginRequest,
    request: Request,
    _throttle: None = Depends(_rate_limit_login),
    dao: DataAccess = Depends(_get_data_access),
) -> Response:
    """
    Authenticate against `users` and mint a `sessions` row.

    THE RESPONSE BODY IS EMPTY, DELIBERATELY. No role list, no user name, no
    organisation name — nothing that differs between principals or between
    accounts, because anything that did would be a classification oracle on a
    route anybody can call. A 204 and a `Set-Cookie` is the whole answer.

    This handler calls `DataAccess.login` and nothing else. It does not, and
    must not, consult `patient_logins`.
    """
    session = _refuse_uniformly(
        lambda: dao.login(
            payload.email,
            payload.org_id,
            payload.password,
            payload.totp_code,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _set_session_cookie(response, _SESSION_COOKIE, session.session_id, path="/")
    return response


@router.post(
    "/portal/login",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Authenticate a PATIENT and open a portal session",
    responses={
        204: {"description": "Authenticated; the patient session cookie is set"},
        401: {"description": "Authentication failed"},
        429: {"description": "Too many login attempts from this source"},
    },
)
async def patient_login(
    payload: PatientLoginRequest,
    request: Request,
    _throttle: None = Depends(_rate_limit_login),
    dao: DataAccess = Depends(_get_data_access),
) -> Response:
    """
    Authenticate against `patient_logins` and mint a `patient_sessions` row.

    THE SAME MECHANISM OVER A SECOND PRINCIPAL TABLE: the same hasher, the
    same dummy-hash equalisation, the same MAX_FAILED_LOGIN_ATTEMPTS and
    LOCKOUT_MINUTES, the same GENERIC_AUTH_ERROR, the same session windows,
    the same throttle and the same cookie helper. What differs is the table,
    the cookie name and the cookie path — and that is the whole of the
    difference, which is what "not a second authentication system" means.

    THIS HANDLER CALLS `DataAccess.patient_login` AND NOTHING ELSE. It does
    not, and must not, consult `users`. An address that is a staff address
    and nothing else must be refused here exactly as an address that exists
    nowhere is — same status, same body — and a handler that fell back to
    `login()` would answer differently, in time if not in text.
    """
    session = _refuse_uniformly(
        lambda: dao.patient_login(
            payload.email,
            payload.org_id,
            payload.password,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _set_session_cookie(response, _PATIENT_SESSION_COOKIE, session.session_id, path="/portal")
    return response
