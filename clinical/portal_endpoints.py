"""
clinical/portal_endpoints.py
────────────────────────────
THE PATIENT PORTAL SURFACE (w130). A separate router, a separate dependency,
a separate cookie, a separate session table — and NO WIDENING of
`clinical.endpoints._get_session`.

WHY A SEPARATE DEPENDENCY, STATED FIRST BECAUSE IT IS THE CHEAP MOVE THAT
DESTROYS THE DESIGN. The quickest way to serve a patient would be to widen
`_get_session` to accept either principal, or to point a patient session at an
existing staff route such as the held `GET /patients/{patient_id}/
variant-trends`. Either yields a working portal in which patient A reads
patient B's data by editing a URL, because every staff route takes the
resource id from the caller and binds only `org_id`. That version passes
essentially every test anybody would think to write: measured on this wave,
the argument-bound data layer passed 41 of 46.

So: a patient session reaches a DIFFERENT dependency and a DIFFERENT handler,
and the handlers below take no patient identifier from the request in any
form — not from the path, not from the query string, not from a body, not from
a header.

WHAT IS NOT HERE, AND WHY EACH ABSENCE IS DELIBERATE:

  * NO LOGIN ROUTE **IN THIS FILE** — and the reason has changed, so it is
    rewritten rather than left standing (w138, Rule 3: fix the claim).

    WHAT THIS PARAGRAPH USED TO SAY, AND WHY IT IS NOW FALSE: "There is no
    HTTP authentication endpoint in this repository for ANYONE." That was
    true at w130 and is FALSE from w132 onwards — `POST /auth/login` and
    `POST /portal/login` are both served, from `clinical/auth_endpoints.py`.
    Leaving the old sentence here was the live hazard: this is the file an
    implementer opens to add a patient route, and its header told them the
    patient login route they were about to duplicate did not exist.

    THE ORIGINAL REASONING SURVIVED INTACT AND IS WHY THE ROUTE IS NOT HERE.
    Adding the first HTTP login for patients only would have made the patient
    surface the reference implementation for staff authentication over HTTP,
    which is a decision about the whole service. w132 did not do that: it
    added BOTH routes, in ONE module, over ONE mechanism, so that neither is
    the other's precedent. `auth_endpoints.py`'s own header records the rest —
    why a single combined route would be a timing oracle, and why the two
    handlers must never consult each other's store.

    WHAT REMAINS ABSENT HERE, unchanged: any route in THIS router that
    authenticates. A patient session arrives already minted.
  * NO REGISTRATION ROUTE. Enrolment is a staff act (decision 4), performed
    through `enrol_patient_login` by an authenticated staff Administrator.
    A public self-registration route would be the first session-free method
    ever reachable over HTTP in this repository.
  * STILL NO REPORT CONTENT, AND w135 ADDED TWO ROUTES WITHOUT CHANGING THAT
    — so the paragraph is rewritten rather than left standing (Rule 3: fix
    the claim), because what it says is still true and what it implies no
    longer is.

    UNCHANGED AND RE-COUNTED AT d6246cd: `reports` has no content column. Its
    columns are org_id, id, interpretation_id, created_at, created_by, state,
    approver_id, approved_at, content_hash, tombstoned_at, tombstoned_by and
    retention_days. A row there is a governance record ABOUT a document, not
    the document; the document is rendered outside this schema by
    geper/report/clinical_report_builder.py and stored nowhere in it.

    AND `get_interpretation` IS STILL NOT THE SUBSTITUTE, which is the whole
    reason this paragraph is kept: it returns the entire raw `run_document`
    with NO report-state check, so routing a patient through it would hand
    over the unapproved pipeline output of a DRAFT. Neither route below
    touches `interpretations`, `vcfs`, `variants` or `run_document`, and
    neither returns an `interpretation_id` — the handle that would make that
    bypass one route away instead of zero.

    WHAT w135 DID ADD: `GET /portal/me/reports` and
    `GET /portal/me/reports/{report_id}`, carrying metadata and release state
    and nothing else, because metadata and release state are the whole of what
    this model stores about a released report. No content storage was
    invented to make the surface look richer.
  * NO TRANSLITERATED STATUS. `orders.state` still does not appear here and
    never will: three of its seven values have no writer, and `sample_awaited`
    is written AFTER the specimen arrives, so the column's vocabulary is
    inverted as well as stalled. w134 adds a DERIVED `stages` list instead —
    six stages, each carrying a value the repository's writers support — and
    `clinical.data_access.derive_order_stages` records the census and the
    refusals value by value. No status column was added, no status table, and
    no transition: the derivation is a pure function over a tally of rows that
    already exist.
"""

from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel

from clinical.data_access import (
    GENERIC_AUTH_ERROR,
    AuthenticationError,
    AuthorizationError,
    DataAccess,
    NotFoundError,
    PatientSession,
)
from clinical.endpoints import _anonymous_refusal, _clear_session_cookie, _get_data_access

router = APIRouter(prefix="/portal", tags=["portal"])

# A DISTINCT COOKIE NAME. The staff cookie is `clinical_session`. The two id
# spaces are different TABLES, so presenting one where the other is expected
# already fails to find anything — the distinct name means the browser does not
# send a staff session to the portal by accident in the first place.
_PATIENT_SESSION_COOKIE = "clinical_patient_session"


class PortalPatientResponse(BaseModel):
    """
    The patient's own record. NO IDENTIFIER IS ACCEPTED TO PRODUCE THIS, and
    the fields are the whole of what a `patients` row holds.
    """

    patient_id: str
    name: str
    dob: str
    sex: str


class PortalStage(BaseModel):
    """
    One derived stage of one order, and the value derived for it.

    TWO PLAIN STRINGS, NOT AN ENUM CLASS, and not because an enum would be
    hard. The permitted values live in ONE place — `PORTAL_STAGES` and
    `PORTAL_STAGE_STATES` in `clinical.data_access`, beside the writer census
    that justifies each of them. A second enumeration here would be a second
    place to add a value, and the whole point of this wave is that a value is
    added only when a writer for it has been counted first.
    """

    stage: str
    state: str


class PortalOrderItem(BaseModel):
    """
    One of the patient's test orders.

    THERE IS STILL NO `status` FIELD, AND ITS ABSENCE IS STILL THE POINT — the
    same shape as ResolutionRequest's missing `actor` in clinical/endpoints.py.
    `orders.state` is not returned, not renamed and not transliterated: three
    of its seven declared values (in_progress, reported, closed) are written by
    no code anywhere, so an order stalls at `sample_awaited`; and w134 counted
    the sharper reason, which is that `sample_awaited` is itself written AFTER
    the specimen arrives. Rendering that column would tell a patient whose
    sample is already sequenced that the laboratory is still waiting for it.

    `stages` IS NOT THAT COLUMN UNDER ANOTHER NAME (w134). It is derived, by
    `clinical.data_access.derive_order_stages`, from counts of rows that
    already exist and two timestamps; every value it can emit has a writer
    counted in that function's header, and the seven writerless values appear
    nowhere in it. Where the underlying state does not support the three-state
    distinction, the stage does not emit the missing value: `sample` and
    `analysis` are NEVER `in_progress`, because this platform never observes
    them that way.
    """

    order_id: str
    created_at: str
    placed_at: Optional[str] = None
    cancelled_at: Optional[str] = None
    stages: List[PortalStage] = []


class PortalReportItem(BaseModel):
    """
    One RELEASED report of the patient's own — the whole of it.

    THREE FIELDS, AND THE SHORTNESS IS THE MEASUREMENT, NOT AN OMISSION.
    `reports` has no content column, so there is no document here to withhold
    half of: what this model stores about a released report is that it exists,
    which test it came from, and when it was first delivered. That is these
    three fields.

    NO `interpretation_id`, NO `content_hash`, NO APPROVER, NO `state`. Each
    refusal has its own reason and they are recorded beside the query, in
    `DataAccess.list_my_released_reports`, so the justification cannot ship
    separately from the thing it justifies. The first is the one that matters:
    an interpretation id addresses the raw `run_document`, and
    `get_interpretation` reads that with no report-state check whatsoever.

    `released_at` IS THE FIRST DELIVERY, not the most recent. Releasing the
    same report to a second consumer inserts a second `release_events` row
    (see `_release_report`) and must not change what the patient is told about
    when their own report was issued — the same anchor the retention clock
    uses, ruling D3.
    """

    report_id: str
    order_id: str
    released_at: str


def _presented_patient_session_id(
    authorization: str = Header(default=""),
    clinical_patient_session: str = Cookie(default="", alias=_PATIENT_SESSION_COOKIE),
) -> uuid.UUID:
    """
    The opaque patient session id the caller presented, or 401 — AND NOTHING
    ELSE HAPPENS HERE. w132 fix B, the patient mirror of
    `clinical.endpoints._presented_session_id`, and a mirror rather than an
    import for the same reason the dependency below is one: the staff module's
    version reads the staff cookie.

    NO DATABASE IS TOUCHED. Declared first in the dependency below, so a
    caller with no cookie and no bearer header is refused before a connection
    is opened. A caller who presents a well-formed id cannot be refused
    without a read, and for that caller the guarantee is that every refusal is
    the same `_anonymous_refusal` — same status, same body — whatever the
    database's state.
    """
    raw = clinical_patient_session
    if not raw and authorization.lower().startswith("bearer "):
        raw = authorization[len("bearer ") :].strip()
    if not raw:
        raise _anonymous_refusal()

    try:
        return uuid.UUID(raw)
    except ValueError:
        raise _anonymous_refusal()


def _get_patient_session(
    session_id: uuid.UUID = Depends(_presented_patient_session_id),
    dao: DataAccess = Depends(_get_data_access),
) -> PatientSession:
    """
    FastAPI dependency: the authenticated PATIENT session, or 401.

    A DELIBERATE MIRROR of `_get_session`, against `patient_session_valid` and
    a different cookie. EVERY FAILURE RETURNS THE SAME MESSAGE — the identical
    `GENERIC_AUTH_ERROR` constant staff authentication uses, so a malformed id,
    an unknown id, an expired one, a terminated one, AND A PERFECTLY VALID
    STAFF SESSION ID are indistinguishable to the caller.

    That last one matters: a portal that answered differently for a valid staff
    session id would confirm that the id names a real session somewhere.

    `_get_session` IS NOT IMPORTED AND IS NOT WIDENED. This function exists so
    that it does not have to be.
    """
    try:
        return dao.patient_session_valid(session_id)
    except AuthenticationError:
        raise _anonymous_refusal()


@router.get("/me", response_model=PortalPatientResponse, summary="The authenticated patient's own record")
async def get_my_record(
    patient_session: PatientSession = Depends(_get_patient_session),
    dao: DataAccess = Depends(_get_data_access),
) -> PortalPatientResponse:
    """
    THE HANDLER TAKES NO PATIENT IDENTIFIER. There is no path parameter, no
    query parameter and no body — so a caller has no way to name a patient, and
    a query string that invents one is ignored by construction rather than by a
    check somebody has to remember to write.
    """
    try:
        record = dao.get_my_patient_record(patient_session)
    except (NotFoundError, AuthorizationError):
        # Both collapse to the same 401-shaped refusal deliberately: a portal
        # session whose patient has gone, and a non-patient session that
        # reached here, are the same amount of information to give out.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_AUTH_ERROR)

    return PortalPatientResponse(
        patient_id=str(record["patient_id"]),
        name=record["name"],
        dob=record["dob"].isoformat(),
        sex=record["sex"],
    )


@router.get("/me/tests", response_model=List[PortalOrderItem], summary="The authenticated patient's own test orders")
async def list_my_tests(
    patient_session: PatientSession = Depends(_get_patient_session),
    dao: DataAccess = Depends(_get_data_access),
) -> List[PortalOrderItem]:
    """No patient identifier, for the same reason. See `get_my_record`."""
    try:
        orders = dao.list_my_test_orders(patient_session)
    except AuthorizationError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_AUTH_ERROR)

    return [
        PortalOrderItem(
            order_id=str(o["order_id"]),
            created_at=o["created_at"].isoformat(),
            placed_at=o["placed_at"].isoformat() if o["placed_at"] else None,
            cancelled_at=o["cancelled_at"].isoformat() if o["cancelled_at"] else None,
            # PASSED THROUGH, NOT RE-DERIVED. The derivation happens once, in
            # the data layer, beside the census that justifies it. A second
            # derivation here would be a second answer to maintain, and the two
            # would disagree the first time one of them was edited.
            stages=[PortalStage(stage=s["stage"], state=s["state"]) for s in o["stages"]],
        )
        for o in orders
    ]


@router.get(
    "/me/reports",
    response_model=List[PortalReportItem],
    summary="The authenticated patient's own RELEASED reports",
)
async def list_my_reports(
    patient_session: PatientSession = Depends(_get_patient_session),
    dao: DataAccess = Depends(_get_data_access),
) -> List[PortalReportItem]:
    """
    NO IDENTIFIER OF ANY KIND. Same shape as `list_my_tests`, same reason: a
    caller has no way to name a patient, so an invented one is ignored by
    construction rather than by a check somebody has to remember to write.

    AND NO RELEASE DECISION IS MADE HERE. The handler renders what the data
    layer returned; the release predicate lives once, in the SQL, shared by
    both report routes, so the two cannot come to disagree about what
    "released" and "mine" mean.
    """
    try:
        reports = dao.list_my_released_reports(patient_session)
    except AuthorizationError:
        # `_anonymous_refusal()` and the literal HTTPException used by
        # `list_my_tests` above produce the same object; this one is named so
        # that both w135 routes visibly answer with THE refusal rather than
        # with two independently-maintained copies of it.
        raise _anonymous_refusal()

    return [
        PortalReportItem(
            report_id=str(r["report_id"]),
            order_id=str(r["order_id"]),
            released_at=r["released_at"].isoformat(),
        )
        for r in reports
    ]


@router.get(
    "/me/reports/{report_id}",
    response_model=PortalReportItem,
    summary="One RELEASED report of the authenticated patient's own",
)
async def get_my_report(
    report_id: str,
    patient_session: PatientSession = Depends(_get_patient_session),
    dao: DataAccess = Depends(_get_data_access),
) -> PortalReportItem:
    """
    THE ONE ROUTE ON THIS SURFACE THAT TAKES AN IDENTIFIER FROM THE CALLER,
    and it is a RESOURCE identifier, never an IDENTITY one. The patient is
    still bound from the session alone; `report_id` narrows rows that the
    session's own patient and organisation predicates have ALREADY selected,
    so it can only ever pick from among the caller's own released reports. A
    `patient_id` parameter does not exist here any more than it exists
    anywhere else in this file.

    EVERY REFUSAL IS THE ANONYMOUS REFUSAL — 401, `GENERIC_AUTH_ERROR` — and
    that is deliberate rather than sloppy. `get_my_record` above already
    collapses `NotFoundError` onto the same 401-shaped answer for the same
    reason, and it makes the refusal set here a SET OF SIZE ONE that includes
    the anonymous case: an unauthenticated caller, a malformed session, a
    valid session asking for a nonexistent report, for another patient's
    report, for another organisation's report, and for the caller's OWN
    unreleased report all receive byte-identical answers. A 404 that differed
    from the 401 would tell an unauthenticated prober nothing new, but a 404
    that differed BETWEEN those last four would tell an authenticated one
    which report ids are real — and "my own report exists but is not released"
    is a clinical fact the release gate exists to withhold.

    `report_id` IS A `str` AND IS PARSED HERE, NOT DECLARED AS `uuid.UUID`.
    FastAPI's own path coercion answers a malformed id with a 422 whose body
    ECHOES THE INPUT BACK and differs in shape from every other refusal on
    this route — a second pair in a set that is supposed to have one member.
    Parsing it here, exactly as `_presented_patient_session_id` parses the
    session id, keeps the set at one.
    """
    try:
        wanted = uuid.UUID(report_id)
    except ValueError:
        raise _anonymous_refusal()

    try:
        report = dao.get_my_released_report(patient_session, wanted)
    except (NotFoundError, AuthorizationError):
        raise _anonymous_refusal()

    return PortalReportItem(
        report_id=str(report["report_id"]),
        order_id=str(report["order_id"]),
        released_at=report["released_at"].isoformat(),
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="End the calling PATIENT session",
    responses={
        204: {"description": "The session is terminated and the cookie cleared"},
        401: {"description": "Not authenticated"},
    },
)
async def patient_logout(
    patient_session: PatientSession = Depends(_get_patient_session),
    dao: DataAccess = Depends(_get_data_access),
) -> Response:
    """
    End the calling patient session and clear the portal cookie.

    THE MIRROR OF `/auth/logout`, and a mirror rather than a shared handler
    for the reason the whole portal is: `_get_patient_session` is not
    `_get_session`, the cookie is not the staff cookie, and the table is not
    `sessions`. A staff session id presented here is refused exactly as an
    unknown id is — same status, same body — so this route cannot be used to
    confirm that an id names a real session somewhere.

    NO BODY, NO PATH PARAMETER. See `/auth/logout`: there is nothing to name,
    so there is nothing to check.

    THE COOKIE IS CLEARED ON `/portal`, THE PATH IT WAS SET WITH. A deletion
    sent on `/` would add a second, empty cookie and leave the live one in the
    jar — harmless here because the server-side row is what actually ends the
    session, and still worth getting right, because a credential sitting in a
    browser that everyone believes was cleared is its own kind of hazard.
    """
    try:
        dao.terminate_my_patient_session(patient_session)
    except AuthorizationError:
        raise _anonymous_refusal()
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_session_cookie(response, _PATIENT_SESSION_COOKIE, path="/portal")
    return response
