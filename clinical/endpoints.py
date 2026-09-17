"""
clinical/endpoints.py
─────────────────────
Clinical platform exception workflow public API.

Three endpoints for exception management:
1. GET /orders/{id}/exceptions — list all exceptions for an order (open + resolved)
2. GET /exceptions/worklist — worklist of open exceptions by owner
3. PATCH /exceptions/{id} — resolve an exception

Exception workflow vocabulary is immutable after create time:
- category: PRECONDITION_FAILURE | VALIDATION_FAILURE | TRANSIENT_SUBMISSION_FAILURE | INTERPRETATION_FAILURE
- reason_code: closed vocabulary mapping to owners and categories (see models/exception.py)
- owner: orderer | lab_operator (determined by reason_code)
- status: open | resolved

NOTE: These endpoints assume a SessionMiddleware or equivalent has injected
an authenticated session into the request context. The session is used to
enforce organisation isolation (org-scoped queries).
"""

from __future__ import annotations

import os
import uuid
from typing import Iterator, Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, status
from pydantic import BaseModel

from clinical.data_access import (
    GENERIC_AUTH_ERROR,
    AuthenticationError,
    DataAccess,
    NotFoundError,
    Session,
)

router = APIRouter(prefix="/exceptions", tags=["exceptions"])


class ExceptionListItem(BaseModel):
    """Exception summary for list responses."""

    id: str
    order_id: str
    category: str
    reason_code: str
    error_message: Optional[str] = None
    status: str
    owner: str
    created_at: str
    last_resolved_by: Optional[str] = None
    last_resolved_at: Optional[str] = None
    resolution_action: Optional[str] = None
    resolution_note: Optional[str] = None


class ExceptionEventItem(BaseModel):
    """Exception event (open, resolve, reopen)."""

    id: str
    action: str
    actor: str
    timestamp: str
    action_note: Optional[str] = None


class ExceptionDetail(ExceptionListItem):
    """Exception with full event history."""

    events: list[ExceptionEventItem] = []


class WorklistFilters(BaseModel):
    """Optional filters for worklist query."""

    owner: Optional[str] = None
    category: Optional[str] = None


class ResolutionRequest(BaseModel):
    """
    Request body for PATCH /exceptions/{id}.

    THERE IS NO `actor` FIELD, AND ITS ABSENCE IS THE POINT. It used to carry
    one, and whatever the caller typed was written to `exceptions.
    last_resolved_by` and to the `exception_events` row -- so the same
    statement scoped the update by something trusted (`session.org_id`) and
    attributed it by something the caller supplied. Under ISO 15189 the record
    of who performed an action is evidence, and a claimed actor is
    indistinguishable in the log from a verified one, which makes it worse
    than a missing one: the audit trail looks complete.

    The actor is now derived from the authenticated session. Validating a
    caller-supplied actor would not have been enough -- a validated claim is
    still a claim -- so the field is removed rather than checked. This is the
    rule `Session`'s own docstring already states for `org_id`: read from the
    session and never from a caller argument, "which is what makes the
    isolation structural rather than remembered". The actor now obeys the rule
    the organisation already obeyed.
    """

    resolution_action: str  # "retry_check" or "accept_failure"
    resolution_note: str


class ErrorResponse(BaseModel):
    """Error response."""

    detail: str


_SESSION_COOKIE = "clinical_session"
_DSN_ENV = "CLINICAL_DSN"

# w132 fix C. The readiness probe has passed connect_timeout=3 since it was
# written, with the reason stated in clinical/app.py: "a readiness check that
# hangs is indistinguishable to an orchestrator from one that is slow to say
# yes". The REQUEST path passed nothing, so an anonymous request could hold a
# worker for libpq's default (no timeout at all on most builds; the OS TCP
# timeout is the only bound, minutes).
#
# Five seconds, not three: a probe may fail fast and be retried on a schedule,
# whereas a real request that fails has a person or a job behind it, and the
# same connection under load can legitimately take longer to establish than a
# probe's. Both are far below any TCP default.
#
# WHAT THIS DOES AND DOES NOT CLOSE, stated plainly because the difference
# matters: it BOUNDS the resource-exhaustion path, it does not close it. Every
# anonymous request that presents a well-formed credential still opens a real
# connection and still consumes a Postgres connection slot for the length of
# the request. What changed is that no single one of them can hold a slot for
# longer than five seconds while the database is unreachable, so an outage
# no longer converts into an unbounded pile-up of hung workers. The thing that
# would actually close it is a bounded connection pool, which
# `_get_data_access`'s docstring names as the production form and which this
# wave deliberately does not build (it is an availability change to a path
# w128/w129 pinned).
_REQUEST_CONNECT_TIMEOUT_SECONDS = 5


def _anonymous_refusal() -> HTTPException:
    """
    THE ONE REFUSAL. w132 fix B.

    Every way this service can decline to serve a caller who has not proved
    who they are returns THIS object: no credential, a malformed credential, a
    credential that names nothing, a credential that expired, a credential
    belonging to the other principal — and, since w132, a database that is not
    configured and a database that is not reachable.

    THE DEFECT IT CLOSES, and it is worth stating precisely because the fix is
    not what it first looks like. `_get_session` takes `_get_data_access` as a
    sub-dependency, so the data layer was reached before any credential was
    examined, and it had two observable failure modes of its own:

        CLINICAL_DSN unset      -> 503, with a body naming the variable
        CLINICAL_DSN set, down  -> uncaught psycopg exception -> 500
        database up, bad cookie -> 401 "Authentication failed."

    The BODY was already generic in the third case; the STATUS discriminated
    across all three. An anonymous caller could therefore read the state of
    the clinical database off the status code without holding a credential.
    That is the mirror image of the cross-tenant oracle w129b fixed, where
    both refusals were 500 and only the body differed — which is why the tests
    for this assert the (status, body) pair as a SET OF SIZE ONE across every
    refusal case, and not a per-case equality.

    WHAT IS NOT CLAIMED: that authentication now runs "before" the database in
    general. For a session-authenticated route, validating the session IS a
    database read, and no ordering can change that. What IS true, and is
    tested:

      * a caller presenting NO credential, or a credential that is not a UUID,
        is refused by `_presented_session_id` BEFORE `_get_data_access` runs,
        so no connection is opened at all — a genuine reordering, and the one
        that covers the entire anonymous-scanner case;
      * a caller presenting a well-formed credential cannot distinguish the
        three database states, because all three arrive here.
    """
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_AUTH_ERROR)


def _get_data_access() -> Iterator[DataAccess]:
    """
    FastAPI dependency: a DataAccess for the lifetime of ONE request.

    REQUEST-SCOPED, AND THAT IS A RULING, NOT A DEFAULT. This function used to
    raise NotImplementedError under a docstring saying "initialize DataAccess
    with postgres connection pool, cache as singleton". That plan cannot be
    safely executed with `DataAccess` as written, and implementing it
    faithfully would have shipped a correctness defect:

      `data_access.transactional` gates on INSTANCE state -- `if
      self._in_transaction: return func(...)`, documented as "nested calls
      within a transaction pass through". That is right for a call chain
      inside one request. With ONE instance shared across concurrent
      requests it is not: a second request arriving while the first holds the
      flag is treated as a nested call, opens no transaction of its own, and
      request A's `commit()` commits request B's half-finished work -- then
      `finally: self._in_transaction = False` clears the flag while B is
      still running, so the next request misjudges too. On the path whose
      entire purpose is recording who did what.

    Nothing in the suite would have caught that: no test exercises two
    concurrent requests. The decorator is not wrong; the singleton plan was,
    and it sat in a placeholder where it read as a decision someone had made.

    A connection pool is the production form of this same answer --
    `pool.connection()` per request -- so nothing here forecloses one. What
    must not come back is a shared, cached instance.
    """
    dsn = os.environ.get(_DSN_ENV)
    if not dsn:
        # w132 fix B. This used to be a 503 whose detail named CLINICAL_DSN.
        # It was a good operator error and a bad answer to an anonymous
        # caller, who learned both that the service is misconfigured and the
        # internal name of the setting, from a route whose only job is to say
        # "Authentication failed."
        #
        # The configuration state is still reported, in full, by /readyz —
        # which is the route that exists to report it, is documented as
        # disclosing it, and is placed behind the network rather than behind a
        # credential. Nothing was hidden from an operator; one thing stopped
        # being told to a stranger.
        raise _anonymous_refusal()

    try:
        import psycopg

        connection = psycopg.connect(
            dsn,
            autocommit=False,
            connect_timeout=_REQUEST_CONNECT_TIMEOUT_SECONDS,
        )
    except Exception:  # noqa: BLE001
        # w132 fix B, the second half. `psycopg.connect` was not wrapped, and
        # COUNTED at 9d5261b the clinical app registers no exception handler of
        # any kind — so an unreachable database reached the caller as FastAPI's
        # default 500. A 500 here and a 401 there is the status-channel oracle.
        #
        # The broad `except` is deliberate and is the narrower fix, not the
        # wider one: the alternative is a catch-all handler on the app, which
        # would also swallow genuine 500s on authenticated routes. This catches
        # only the failure to OBTAIN a connection, and only on the path where
        # the caller has not yet proved anything. Nothing after `yield` is
        # covered by it.
        raise _anonymous_refusal()

    try:
        yield DataAccess(connection)
    finally:
        connection.close()


def _presented_session_id(
    authorization: str = Header(default=""),
    clinical_session: str = Cookie(default="", alias=_SESSION_COOKIE),
) -> uuid.UUID:
    """
    The opaque session id the caller presented, or 401 — AND NOTHING ELSE
    HAPPENS HERE. w132 fix B.

    THIS FUNCTION TOUCHES NO DATABASE, and that is its entire purpose. It is
    declared BEFORE `_get_data_access` in `_get_session`'s signature, and
    FastAPI solves a dependant's sub-dependencies in declaration order, so a
    caller who presents no credential at all — or presents something that is
    not a UUID — is refused before a connection is opened.

    That is the part of "authenticate before the database reveals its state"
    that is actually achievable, and it is the part that covers the traffic
    that matters: an anonymous scanner sends no cookie. A caller who presents
    a well-formed id cannot be refused without a `SELECT`, because validating
    a session IS a database read; for that caller the guarantee is
    indistinguishability (`_anonymous_refusal`), not ordering.

    Split out of `_get_session` rather than left inline because inline it ran
    AFTER the sub-dependency resolved, which is the whole defect.
    """
    raw = clinical_session
    if not raw and authorization.lower().startswith("bearer "):
        raw = authorization[len("bearer ") :].strip()
    if not raw:
        raise _anonymous_refusal()

    try:
        return uuid.UUID(raw)
    except ValueError:
        raise _anonymous_refusal()


def _get_session(
    session_id: uuid.UUID = Depends(_presented_session_id),
    dao: DataAccess = Depends(_get_data_access),
) -> Session:
    """
    FastAPI dependency: the authenticated session, or 401.

    The opaque session id is read and shape-checked by
    `_presented_session_id`, which is declared FIRST and touches nothing --
    see its docstring, and w132 fix B. What is left here is the half that
    genuinely requires the database: validating the id through
    `DataAccess.session_valid`, which refreshes the idle window and raises for
    a session that is terminated, past its absolute cap, or idle too long.

    EVERY FAILURE RETURNS THE SAME MESSAGE. A malformed id, an unknown id, an
    expired one and a terminated one are indistinguishable to the caller --
    `data_access.GENERIC_AUTH_ERROR`, which that module already uses for
    exactly this reason. Distinguishing them would tell an unauthenticated
    caller which session ids exist. Since w132 the same object also answers an
    unconfigured and an unreachable database, so the STATUS does not
    discriminate either.

    Depends on `_get_data_access`, so within one request the session lookup
    and the endpoint body share one connection and one transaction: FastAPI
    caches a dependency's result per request, so this does not open a second.
    """
    try:
        return dao.session_valid(session_id)
    except AuthenticationError:
        raise _anonymous_refusal()


@router.get(
    "/orders/{order_id}",
    response_model=list[ExceptionDetail],
    responses={
        200: {"description": "List of exceptions (open and resolved)"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        404: {"model": ErrorResponse, "description": "Order not found in this organisation"},
        500: {"model": ErrorResponse, "description": "Server error"},
    },
)
async def get_exceptions_for_order(
    order_id: str,
    session: Session = Depends(_get_session),
    dao: DataAccess = Depends(_get_data_access),
) -> list[ExceptionDetail]:
    """
    Get all exceptions (open + resolved) for an order.

    Returns exceptions in created_at DESC order. Org-scoped: only returns
    exceptions for orders in the session's organisation.

    Args:
        order_id: UUID of the order

    Returns:
        List of ExceptionDetail objects (each with event history)

    Raises:
        401: Unauthenticated
        404: Order not found in this organisation
        500: Database error
    """
    try:
        order_uuid = uuid.UUID(order_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid order_id: {order_id}",
        )

    try:
        # Check order exists
        order = dao.get_order(session, order_uuid)
        if order is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Order {order_id} not found",
            )

        # Get exceptions with event history
        exception_dtos = dao.get_exceptions_for_order(session, order_uuid)

        # Convert DTOs to response models
        result = []
        for exc_dto in exception_dtos:
            result.append(
                ExceptionDetail(
                    id=exc_dto.id,
                    order_id=exc_dto.order_id,
                    category=exc_dto.category,
                    reason_code=exc_dto.reason_code,
                    error_message=exc_dto.error_message,
                    status=exc_dto.status,
                    owner=exc_dto.owner,
                    created_at=exc_dto.created_at,
                    last_resolved_by=exc_dto.last_resolved_by,
                    last_resolved_at=exc_dto.last_resolved_at,
                    resolution_action=exc_dto.resolution_action,
                    resolution_note=exc_dto.resolution_note,
                    events=[
                        ExceptionEventItem(
                            id=evt.id,
                            action=evt.action,
                            actor=evt.actor,
                            timestamp=evt.timestamp,
                            action_note=evt.action_note,
                        )
                        for evt in exc_dto.events
                    ],
                )
            )

        return result

    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Order not found",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving exceptions: {type(e).__name__}",
        )


@router.get(
    "/worklist",
    response_model=list[ExceptionDetail],
    responses={
        200: {"description": "Open exceptions for owner"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        400: {"model": ErrorResponse, "description": "Missing owner parameter"},
        500: {"model": ErrorResponse, "description": "Server error"},
    },
)
async def get_exceptions_worklist(
    owner: str,
    session: Session = Depends(_get_session),
    dao: DataAccess = Depends(_get_data_access),
) -> list[ExceptionDetail]:
    """
    Get open exceptions for a given owner role.

    Returns open (not resolved) exceptions owned by the specified role,
    sorted by created_at ASC (oldest first). Org-scoped: only returns
    exceptions from the session's organisation.

    Args:
        owner: Owner role (e.g., "orderer", "lab_operator")

    Returns:
        List of ExceptionDetail objects for open exceptions

    Raises:
        401: Unauthenticated
        400: Missing owner parameter
        500: Database error
    """
    if not owner or not owner.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="owner parameter is required",
        )

    try:
        # Get open exceptions by owner
        exception_dtos = dao.get_open_exceptions_by_owner(session, owner)

        # Convert DTOs to response models
        result = []
        for exc_dto in exception_dtos:
            result.append(
                ExceptionDetail(
                    id=exc_dto.id,
                    order_id=exc_dto.order_id,
                    category=exc_dto.category,
                    reason_code=exc_dto.reason_code,
                    error_message=exc_dto.error_message,
                    status=exc_dto.status,
                    owner=exc_dto.owner,
                    created_at=exc_dto.created_at,
                    last_resolved_by=exc_dto.last_resolved_by,
                    last_resolved_at=exc_dto.last_resolved_at,
                    resolution_action=exc_dto.resolution_action,
                    resolution_note=exc_dto.resolution_note,
                    events=[
                        ExceptionEventItem(
                            id=evt.id,
                            action=evt.action,
                            actor=evt.actor,
                            timestamp=evt.timestamp,
                            action_note=evt.action_note,
                        )
                        for evt in exc_dto.events
                    ],
                )
            )

        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving worklist: {type(e).__name__}",
        )


@router.patch(
    "/{exception_id}",
    response_model=ExceptionDetail,
    responses={
        200: {"description": "Exception resolved"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        404: {"model": ErrorResponse, "description": "Exception not found"},
        400: {"model": ErrorResponse, "description": "Invalid exception_id"},
        500: {"model": ErrorResponse, "description": "Server error"},
    },
)
async def resolve_exception(
    exception_id: str,
    body: ResolutionRequest,
    session: Session = Depends(_get_session),
    dao: DataAccess = Depends(_get_data_access),
) -> ExceptionDetail:
    """
    Resolve an exception, recording resolution action and note.

    Transitions exception from open to resolved, creates a RESOLVE event,
    and records the resolution action + note. Org-scoped: can only resolve
    exceptions in the session's organisation.

    Args:
        exception_id: UUID of the exception to resolve
        body: Resolution request with action and note

    Returns:
        Updated ExceptionDetail with resolved status and RESOLVE event

    Raises:
        401: Unauthenticated
        404: Exception not found in this organisation
        400: Invalid exception_id or request body
        500: Database error
    """
    try:
        exc_uuid = uuid.UUID(exception_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid exception_id: {exception_id}",
        )

    if not body.resolution_action:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="resolution_action is required",
        )

    if not body.resolution_note:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="resolution_note is required",
        )

    try:
        # Resolve the exception
        # The actor is the authenticated user, never a caller-supplied
        # string -- see ResolutionRequest for why the field was removed rather
        # than validated. The id and not an email: a display string can be
        # re-pointed at a different person, an id cannot, and this is evidence.
        dao.resolve_exception(
            session,
            exc_uuid,
            body.resolution_action,
            body.resolution_note,
            str(session.user_id),
        )

        # TODO: After resolution, re-run preconditions or submission
        # depending on the resolution_action. This is a separate workflow
        # that may trigger a retry or may mark the order as closed.

        # Retrieve updated exception to return
        resolved_exc = dao.get_exception_by_id(session, exc_uuid)
        if resolved_exc is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Exception resolved but could not retrieve updated state",
            )

        return ExceptionDetail(
            id=resolved_exc.id,
            order_id=resolved_exc.order_id,
            category=resolved_exc.category,
            reason_code=resolved_exc.reason_code,
            error_message=resolved_exc.error_message,
            status=resolved_exc.status,
            owner=resolved_exc.owner,
            created_at=resolved_exc.created_at,
            last_resolved_by=resolved_exc.last_resolved_by,
            last_resolved_at=resolved_exc.last_resolved_at,
            resolution_action=resolved_exc.resolution_action,
            resolution_note=resolved_exc.resolution_note,
            events=[
                ExceptionEventItem(
                    id=evt.id,
                    action=evt.action,
                    actor=evt.actor,
                    timestamp=evt.timestamp,
                    action_note=evt.action_note,
                )
                for evt in resolved_exc.events
            ],
        )

    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Exception {exception_id} not found",
        )
    except HTTPException:
        # Do not re-wrap. Wrapping turned the handler's own 404 and its own 500
        # into "Error resolving exception: 500: ...", which is how one half of
        # the existence oracle got its distinctive wording.
        raise
    except Exception as e:
        # w129 GAP-2, second half. THE TYPE, NEVER THE TEXT.
        #
        # This read f"...{str(e)}". Measured at 9bc3abd, that returned
        #   {"detail":"Error resolving exception: current transaction is
        #    aborted, commands ignored until end of transaction block"}
        # to an authenticated caller in a DIFFERENT organisation -- the driver's
        # own message, and the half of the existence oracle that told the caller
        # its guessed UUID belongs to nobody. clinical/app.py:118-121 settled
        # the rule for this repository and gives the reason in one line: "a
        # libpq error message quotes the connection string back".
        #
        # The same statement stood on the two neighbouring read routes in this
        # file and is changed there too; fixing only the route the oracle was
        # found on would have left the identical leak twice over.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error resolving exception: {type(e).__name__}",
        )
