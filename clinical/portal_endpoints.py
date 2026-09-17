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

  * NO LOGIN ROUTE. There is no HTTP authentication endpoint in this
    repository for ANYONE — `DataAccess.login` has exactly one non-test caller
    and it is a command-line tool. Adding the first one for patients only
    would make the patient surface the reference implementation for staff
    authentication over HTTP, which is a decision about the whole service and
    not about patient identity. `patient_login` is reachable from the data
    layer; wiring it to a route is a separate, deliberate piece of work.
  * NO REGISTRATION ROUTE. Enrolment is a staff act (decision 4), performed
    through `enrol_patient_login` by an authenticated staff Administrator.
    A public self-registration route would be the first session-free method
    ever reachable over HTTP in this repository.
  * NO REPORT CONTENT. `reports` has no content column — a row there is a
    governance record ABOUT a document, not the document. There is nothing
    stored to return, and `get_interpretation` is not the substitute: it
    returns the entire raw `run_document` with no report-state check, so it
    would hand a patient the unapproved pipeline output of a draft.
  * NO STATUS VOCABULARY. `orders.state` cannot carry one — three of its seven
    values are written by no code anywhere — so no field here transliterates
    it.
"""

from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, status
from pydantic import BaseModel

from clinical.data_access import (
    GENERIC_AUTH_ERROR,
    AuthenticationError,
    AuthorizationError,
    DataAccess,
    NotFoundError,
    PatientSession,
)
from clinical.endpoints import _get_data_access

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


class PortalOrderItem(BaseModel):
    """
    One of the patient's test orders.

    THERE IS NO `status` FIELD AND ITS ABSENCE IS THE POINT — the same shape as
    ResolutionRequest's missing `actor` in clinical/endpoints.py. `orders.state`
    has three declared values (in_progress, reported, closed) that no code
    anywhere writes, so an order stalls at `sample_awaited` however far the
    pipeline got. Rendering that column to a patient would show every completed
    case as awaiting a sample. What a patient is shown for progress is a
    ruling, and a field here would pre-empt it.
    """

    order_id: str
    created_at: str
    placed_at: Optional[str] = None
    cancelled_at: Optional[str] = None


def _get_patient_session(
    authorization: str = Header(default=""),
    clinical_patient_session: str = Cookie(default="", alias=_PATIENT_SESSION_COOKIE),
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
    raw = clinical_patient_session
    if not raw and authorization.lower().startswith("bearer "):
        raw = authorization[len("bearer ") :].strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_AUTH_ERROR)

    try:
        session_id = uuid.UUID(raw)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_AUTH_ERROR)

    try:
        return dao.patient_session_valid(session_id)
    except AuthenticationError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_AUTH_ERROR)


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
        )
        for o in orders
    ]
