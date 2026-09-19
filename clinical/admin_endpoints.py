"""
clinical/admin_endpoints.py
───────────────────────────
w152 (WAVE 2) — THE ADMINISTRATIVE HTTP SURFACE. The outermost layer, which
is the one that was missing.

WHY THIS FILE EXISTS, STATED AS THE MEASUREMENT AND NOT AS A STORY.
`w150-reachability-audit.md` counted fourteen unreachable capabilities and
found that in thirteen of them the broken link is the SAME one and it is the
outermost: no HTTP route and no CLI command. Not one of them is "a route
exists but nothing calls the domain method". Re-measured at `e1be7ab` by AST
(`ast.Call` nodes in production files, never grep — grep credits a docstring
as a caller, which is how `_release_report` came to be recorded as having
thirteen callers and zero calls): `assign_role`, `set_user_disabled`,
`set_patient_login_disabled` and `read_audit` each have ZERO production call
sites, and the seventeen production routes contain ZERO administrative ones.

So this is ONE MISSING SURFACE, not fourteen wiring problems, and this module
is that surface.

WHAT IS AND IS NOT IN IT.
Every handler below is a TRANSLATION — HTTP in, one existing domain method,
HTTP out. There is no business logic here, no second permission system, no
second session type, no second refusal vocabulary and no SQL. The role gate
is `DataAccess._require_role`, called from inside the domain method's own
body, exactly where it already was; this file never asks what roles a caller
holds and never decides. A handler that made that decision itself would be a
second authorisation system whose answer could drift from the first one's,
and the first one is the one the database's composite foreign keys back up.

Four capabilities are wired. The rest of the eleven are NOT, each for a
stated reason, and the reasons are in `WHAT IS DELIBERATELY NOT HERE` at the
bottom of this docstring. A capability that needs a product decision is
stopped and carded rather than guessed.

──────────────────────────────────────────────────────────────────────────
THE SECURITY MODEL, IN THE ORDER A REQUEST MEETS IT
──────────────────────────────────────────────────────────────────────────

1. AUTHENTICATION — `Depends(_get_session)`, imported from
   `clinical/endpoints.py` and NOT reimplemented. It is the same dependency
   the exception routes use: `_presented_session_id` reads the cookie or the
   bearer header and shape-checks it while touching no database, then
   `DataAccess.session_valid` validates it. Every failure — absent, malformed,
   unknown, expired, terminated, or a PATIENT session id presented to a staff
   route — is `_anonymous_refusal()`: 401, `GENERIC_AUTH_ERROR`, byte for
   byte. There is no route on this router without that dependency, and
   `test_w152_admin_surface.py` proves that by enumerating the router rather
   than by reading it.

2. ORGANISATION CONTEXT — DERIVED, NEVER SUPPLIED. `Session.org_id` comes
   out of the `sessions` row. Not one route below accepts an organisation in
   a path segment, a query parameter or a body field, and the request models
   set `extra="forbid"` so that a body which tries to carry one is REFUSED
   rather than silently ignored — a silent ignore is correct today and is one
   careless `**body` away from not being.

   THE HOUSE PATTERN IS DEFENCE BY ABSENT PARAMETER and it is preferred
   wherever it is expressible: `list_my_report_trend(self, patient_session)`
   takes no patient identifier, so the wrong version is UNWRITABLE. An
   administrative route cannot be quite that shape — administration is by
   definition acting on somebody else — so the weaker form is used and it is
   the same rule one level down: the caller may name a TARGET, and the
   ORGANISATION that target is looked up in comes from the principal. Every
   domain method below binds `org_id = session.org_id` in its own SQL, and
   the schema's composite foreign keys refuse the row even if that layer were
   wrong.

3. ROLE AUTHORISATION — `_require_role`, inside the domain method, FIRST.
   Administrator for the three writes, Auditor for the audit read. The order
   is load-bearing and it is the domain layer's, not this file's:
   `assign_role`'s own docstring says "THE ORDER MATTERS: the Administrator
   check stays FIRST, so a caller without it learns nothing about which roles
   are assignable". Because the gate precedes every target read, a 403 from
   this surface is a function of the CALLER'S ROLES ALONE and carries no
   information whatever about whether the named target exists.

4. AUDIT ATTRIBUTION — `@auditable` on the domain method, unchanged and
   untouched. The actor is `session.user_id`, the organisation is
   `session.org_id`, the target is the `resource_id_param` the decorator
   already names. Nothing in this file writes an audit row.

   AND NOTHING IN THIS FILE COMPOSES TWO DECORATED METHODS INTO ONE
   OPERATION. `@auditable` COMMITS after each audit row it writes, so a
   handler assembled out of "check it, then do it" would commit the first
   half's audit row when the second half failed — an audit that records
   something that did not happen. Each handler calls EXACTLY ONE decorated
   domain method, which is why, for example, the disable routes do not
   read the user back to return it.

5. ERROR MODEL — THREE REFUSALS, EACH A SET OF SIZE ONE ACROSS THE WHOLE
   SURFACE. The precedent is `clinical/portal_endpoints.py`, whose refusals
   are one object, and `clinical/endpoints.py::_anonymous_refusal`, whose
   docstring explains why a per-case equality is not enough (Standing Rule 8:
   an oracle can live in the STATUS channel or the BODY channel, so both are
   pinned, as a set).

       401 + GENERIC_AUTH_ERROR   not authenticated, in any of its six ways
       403 + ADMIN_FORBIDDEN      authenticated, lacks the required role
       404 + ADMIN_NOT_FOUND      no such target IN THIS ORGANISATION

   `ADMIN_FORBIDDEN` and `ADMIN_NOT_FOUND` are module constants and are the
   same string on every route, so a caller cannot tell from a refusal WHICH
   administrative object it named, nor which role it was short of.

6. NO INFORMATION ORACLE. The 404 is the same object for an identifier that
   is malformed, an identifier that exists nowhere, and an identifier that
   names a REAL ROW IN ANOTHER ORGANISATION. That last case is the one a
   behavioural test cannot reach by accident — two randomly generated UUIDs
   never collide — so `test_w152_admin_surface.py` CONSTRUCTS the collision:
   it plants a real user, and a real patient credential, in organisation B
   and names them from an organisation A session. Without that row a missing
   `org_id` predicate is invisible to every other test in the file.

   THE 403/404 DISTINCTION IS NOT AN ORACLE, and this is the reasoning rather
   than an assertion. A distinction leaks only if it varies with something the
   caller is not entitled to know. Here 403 depends on the caller's own roles
   and NOTHING else — the gate runs before any target is read, so a
   non-Administrator gets the identical 403 whether the target is real,
   invented, or in another tenant. And 404 depends on existence-within-the-
   caller's-own-organisation and nothing else. Neither varies with the
   existence of another tenant's row. Collapsing 403 into 404 as well would
   cost an Administrator any way to tell "I am not an Administrator" from "no
   such user" and buy nothing.

──────────────────────────────────────────────────────────────────────────
WHAT THIS SURFACE DOES NOT CLAIM — READ THIS BEFORE BELIEVING ANY OF IT
──────────────────────────────────────────────────────────────────────────

NO ROUTE IN THIS FILE IS REACHABLE BY A REAL DEPLOYMENT TODAY. Every one of
them requires a session holding Administrator or Auditor, and `assign_role`
is the only production writer of a human role assignment while itself
requiring an existing Administrator. A fresh deployment has none: measured at
`e1be7ab`, `INSERT INTO role_assignments` occurs at exactly two production
sites, one inside `assign_role` and one that writes `'System'`, which w141
made unassignable to people. That is the first-administrator deadlock and it
is WAVE 3's, not this wave's.

So these routes are IMPLEMENTED + UNREACHABLE, in the report's own
vocabulary, and they are classified that way rather than as complete. The
tests provision their Administrator BY INSERTING THE ROLE ROW DIRECTLY, the
same way `test_identity.py::admin_session` and
`test_w133_staff_revocation.py::_staff_session` already do — a FIXTURE, not
a bootstrap. No bootstrap was invented here to make this file's own tests
pass; inventing one would be doing Wave 3's work badly and would have to be a
permanent part of the product.

──────────────────────────────────────────────────────────────────────────
WHAT IS DELIBERATELY NOT HERE, AND WHY — each of these is a card, not an
oversight. See `hive/agents/god/w152-decision-cards.md`.
──────────────────────────────────────────────────────────────────────────

* ORGANISATION CREATION (`create_organisation`) and STAFF CREATION
  (`create_user`). Both are `@auditable(requires_session=False)` and neither
  has a `_require_role` call anywhere in its body — AST-confirmed, not read
  off the docstring. A route onto either would therefore be an UNAUTHENTICATED
  route that creates a tenant or a principal, or it would need an
  authorisation rule invented at the HTTP layer, which is the second
  permission system this wave is forbidden to build. Which principal may
  create an organisation, and may create a user, is a product decision nobody
  has made. STOPPED.

* FIRST ADMINISTRATOR PROVISIONING. The deadlock above. WAVE 3.

* ROLE REVOCATION. ABSENT AT `e1be7ab`, WHERE THIS BULLET WAS WRITTEN, AND
  BUILT AT w154 (WAVE 4). The measurement that made it absent was right: no
  `DataAccess` method had `revoke` in its name and `revoked_at`/`revoked_by`
  appeared only in `revoked_at IS NULL` read predicates, so the enforcement
  model was continuous and strong and the state it enforced on had no writer.
  `DataAccess.revoke_role` is now that writer and `DELETE
  /admin/users/{user_id}/roles/{role}` is its route. It ends no sessions, and
  that is a measurement rather than an omission -- see the method's own
  docstring, and `revoke_role` below.

* PATIENT ENROLMENT (`create_patient`, `record_consent`, `withdraw_consent`).
  Session-bound but UNGATED — no `_require_role` in any of the three bodies.
  Wiring them as they stand would let any authenticated staff session in the
  organisation create patients and record consent. Adding the gate in the
  handler would be the second permission system. Which role owns patient
  enrolment is a ruling nobody has made. STOPPED, and it is WAVE 5's subject.

* PATIENT CREDENTIAL ISSUANCE (`enrol_patient_login`). Administrator-gated
  and audited, so it is mechanically pure wiring — and it is stopped anyway,
  on the one ground this wave is not allowed to resolve.
  `GEPER_CLINICAL_PLATFORM_SPEC.md` §16 reads "**Recommendation: no patient
  access in v1**", and carries an unanswered EXPERT call-out about what
  counselling provision must accompany patient access. Seven `/portal/`
  routes are nevertheless mounted and tested, and the tension is reported and
  unresolved. Issuing the credential is the act that converts that
  recommendation into a live patient-facing deployment — nothing else can,
  because there is no self-registration path of any kind. That is a product
  decision, and this wave does not silently reinterpret the product spec.
  STOPPED.

  REVOCATION IS WIRED AND ISSUANCE IS NOT, and the asymmetry is the point
  rather than an inconsistency: revocation only ever CONTRACTS patient access
  and no citation anywhere opposes contracting it, while issuance expands it
  and §16 speaks directly to that. The safe half of a carded pair is not held
  hostage by the half that needs the ruling.

* EXCEPTION AMENDMENT and REPORT RETRACTION. `create_amendment` exists and is
  Approver-gated; the exception-amendment verb does not — `ExceptionEventAction`
  is still exactly open/resolve/reopen and `amends_event_id` has zero writers.
  `retract_report` does not exist at all: the `0003` schema landed and the
  domain method did not. WAVE 6, and one of them is ABSENT rather than
  unreachable.
"""

from __future__ import annotations

import uuid
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict

from clinical.data_access import (
    AuthorizationError,
    DataAccess,
    NotFoundError,
    Session,
)
from clinical.endpoints import _get_data_access, _get_session

# PREFIXED, so that every administrative path is visibly administrative in
# the route census and in any access log, and so that a reverse proxy or a
# future network policy can speak about the whole surface in one rule.
router = APIRouter(prefix="/admin", tags=["administration"])


# ─── THE TWO REFUSALS THIS FILE OWNS ─────────────────────────────────────────
#
# The third one, 401, is `clinical.endpoints._anonymous_refusal` and is not
# re-declared here; this surface authenticates with the staff dependency and
# must not grow a second answer to "who are you".
#
# ONE STRING EACH, FOR EVERY ROUTE AND EVERY TARGET TYPE. "User not found"
# next to "Credential not found" would tell a caller which kind of object its
# guessed identifier named, which is the same class of disclosure as telling
# it the object exists.

ADMIN_FORBIDDEN = "Not permitted."
ADMIN_NOT_FOUND = "Not found."


def _forbidden() -> HTTPException:
    """403. The caller is authenticated and does not hold the required role.

    Carries no information about the target: the role gate runs FIRST, inside
    the domain method, before any row is read.
    """
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=ADMIN_FORBIDDEN)


def _not_found() -> HTTPException:
    """404. THE SAME OBJECT for a malformed identifier, an identifier that
    exists nowhere, and an identifier naming a real row in ANOTHER
    organisation. The third case is the one that matters and the one a test
    has to construct on purpose."""
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=ADMIN_NOT_FOUND)


def _target(raw: str) -> uuid.UUID:
    """
    A path identifier, parsed — and a MALFORMED one becomes an identifier
    that names nothing, rather than a refusal of its own.

    DECLARED `str` AND PARSED HERE, NOT DECLARED `uuid.UUID`, and the portal
    made the same choice for the same reason: FastAPI's own path coercion
    answers a malformed id with a 422 whose body names the parameter and the
    error, which makes "not a UUID" distinguishable from "a UUID that names
    nothing". That is a second refusal shape on a surface whose whole claim is
    that it has one.

    AND IT DOES NOT RAISE, WHICH IS THE PART THAT IS EASY TO GET WRONG — the
    first version of this function raised the 404 directly, and that was a
    measurable defect rather than a stylistic one. `_target` runs in the
    HANDLER BODY, which is AFTER the dependencies and BEFORE the domain
    method, so a raising version answered a caller who holds no Administrator
    role with 404 for a malformed id and 403 for a well-formed one. The
    refusal would then have varied with the SHAPE of the identifier at a point
    where the caller's authorisation had not yet been evaluated — the 403 set
    would no longer have been a function of the caller's roles alone, which is
    the whole argument for why a 403 and a 404 may differ here at all.

    Substituting a fresh random identifier makes the malformed case take the
    SAME path as "an id that exists nowhere": the role gate runs first, and
    only an authorised caller reaches the lookup that answers 404. A `uuid4`
    rather than a fixed sentinel because a constant is a value somebody could
    one day insert; a random 122-bit value colliding with a real row is not a
    risk anyone needs to reason about.
    """
    try:
        return uuid.UUID(raw)
    except ValueError:
        return uuid.uuid4()


# ─── request and response models ─────────────────────────────────────────────
#
# `extra="forbid"` ON EVERY REQUEST MODEL. Pydantic's default is to ignore an
# unknown field, which is safe and silent; forbidding it is safe and LOUD. The
# field nobody must ever be able to send is an organisation, and a caller who
# tries gets a 422 rather than a success that quietly did the right thing for
# a reason no test would notice if it stopped being true.


class RoleAssignmentRequest(BaseModel):
    """
    THERE IS NO `org_id` FIELD AND NO `assigned_by` FIELD, and both absences
    are the design. The organisation comes from the session; the assigning
    actor is `session.user_id`, written by `assign_role` itself. A validated
    caller-supplied actor is still a claim, and `ResolutionRequest` in
    `clinical/endpoints.py` already settled that rule for this repository:
    the field is removed rather than checked.
    """

    model_config = ConfigDict(extra="forbid")

    role: str
    # Mandatory for Approver — ISO 15189 7.4.1.5 c) requires the reviewer's
    # authority to be retrievable, and both `assign_role` and the schema CHECK
    # refuse the row without it. NOT re-validated here: that rule lives in the
    # domain method and a copy of it here is a second answer to maintain.
    basis: Optional[str] = None


class DisabledRequest(BaseModel):
    """
    ONE ROUTE FOR BOTH DIRECTIONS, mirroring the one domain method that takes
    a boolean. Two routes (`/disable` and `/enable`) would be two handlers
    around one method and would invite the pair to drift; the audit action is
    already a lambda on this same boolean (`user_disabled` / `user_enabled`),
    so the record distinguishes them without the URL having to.
    """

    model_config = ConfigDict(extra="forbid")

    disabled: bool


class RoleAssignmentCreated(BaseModel):
    assignment_id: str


class RoleRevoked(BaseModel):
    """
    HOW MANY LIVE ASSIGNMENTS OF THAT ROLE THIS CALL WITHDREW.

    A RESPONSE model, so it declares no `extra="forbid"` and is deliberately
    outside the inbound scan in `test_w152_admin_surface.py`: there is no
    request body on this route at all.

    The count is here rather than a 204 because zero and one are genuinely
    different outcomes and only one of them changed anything -- revoking a
    role the user never held is not a refusal (the post-condition asked for
    is already true) and a caller is entitled to know which of the two
    happened. It discloses nothing: only an Administrator of the target's own
    organisation ever sees it, and it counts rows in that organisation.
    """

    revoked: int


class AuditEntry(BaseModel):
    """
    The columns `read_audit` selects, PASSED THROUGH AND NOT RE-DERIVED.

    `org_id` is in the shape even though it can only ever be the caller's own
    organisation — the method binds `WHERE org_id = %s` from the session. It
    is kept because it lets a test assert that invariant on the response
    itself rather than on the SQL, and a value that can only be one thing is
    not a disclosure.

    `ip_address` reaches an Auditor because the domain method selects it and
    the Auditor role is the one this platform defines for reading the audit
    trail. That is the existing decision, not a new one; this file discloses
    no column `read_audit` does not return.
    """

    log_id: int
    org_id: Optional[str] = None
    user_id: Optional[str] = None
    action: str
    details: Any = None
    ip_address: Optional[str] = None
    timestamp: str


class ErrorResponse(BaseModel):
    detail: str


# ─── the routes ──────────────────────────────────────────────────────────────


@router.post(
    "/users/{user_id}/roles",
    status_code=status.HTTP_201_CREATED,
    response_model=RoleAssignmentCreated,
    summary="Grant a role to a user in the CALLER'S OWN organisation",
    responses={
        201: {"description": "The role is assigned"},
        400: {"model": ErrorResponse, "description": "Unknown, unassignable, or under-justified role"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Not permitted"},
        404: {"model": ErrorResponse, "description": "Not found"},
    },
)
async def assign_role(
    user_id: str,
    body: RoleAssignmentRequest,
    session: Session = Depends(_get_session),
    dao: DataAccess = Depends(_get_data_access),
) -> RoleAssignmentCreated:
    """
    `DataAccess.assign_role`, and nothing else.

    The Administrator check, the `ROLES` vocabulary check, the
    `HUMAN_ASSIGNABLE_ROLES` check that makes `'System'` ungrantable (w141),
    the Approver-needs-a-basis rule and the organisation predicate are all in
    the domain method. NONE of them is repeated here. If this handler
    validated the role name too, there would be two vocabularies and the day
    they disagreed the HTTP one would win silently.

    THE 400 CARRIES THE DOMAIN'S OWN MESSAGE and that is safe: every
    `ValueError` `assign_role` raises is about the ROLE VOCABULARY — a closed,
    public list of seven strings — and is raised strictly AFTER the
    Administrator gate, so only an Administrator of this organisation can see
    one. No identifier, no row and no other tenant appears in any of them.
    """
    target = _target(user_id)
    try:
        assignment_id = dao.assign_role(session, target, body.role, body.basis)
    except AuthorizationError:
        raise _forbidden()
    except NotFoundError:
        raise _not_found()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return RoleAssignmentCreated(assignment_id=str(assignment_id))


@router.delete(
    "/users/{user_id}/roles/{role}",
    response_model=RoleRevoked,
    summary="Withdraw a role from a user in the CALLER'S OWN organisation",
    responses={
        200: {"description": "Every live assignment of that role is withdrawn; the count is returned"},
        400: {"model": ErrorResponse, "description": "Unknown or unrevocable role"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Not permitted"},
        404: {"model": ErrorResponse, "description": "Not found"},
    },
)
async def revoke_role(
    user_id: str,
    role: str,
    session: Session = Depends(_get_session),
    dao: DataAccess = Depends(_get_data_access),
) -> RoleRevoked:
    """
    `DataAccess.revoke_role`, and nothing else.

    THE EXACT INVERSE OF THE ROUTE ABOVE, on the same collection. `POST
    /users/{id}/roles` grants; `DELETE /users/{id}/roles/{role}` withdraws.

    THE ROLE IS A PATH SEGMENT AND NOT A BODY FIELD, which is why this route
    adds no request model. A role name is a member of a closed, public
    vocabulary of seven strings, not an identifier -- it names no row, leaks
    nothing by being in a URL, and there is nothing else to send. It is also
    what makes the request idempotent in the way DELETE is supposed to be:
    the second call withdraws nothing and says so.

    NO VOCABULARY CHECK HAPPENS HERE. An unknown role, and "System", are
    both refused by the domain method, after its Administrator gate, with the
    same `ValueError` shape `assign_role` already uses -- so a
    non-Administrator sending a nonsense role still gets the plain 403 and
    learns nothing about the vocabulary. Validating the segment here would
    put a second copy of the role list in this file and would answer before
    the gate.

    NOTHING IS DONE ABOUT THE TARGET'S LIVE SESSIONS, and it is deliberate.
    Roles are resolved per request: `Session` carries no role, `session_valid`
    reads only the `sessions` row, and `_require_role` re-reads
    `role_assignments` on every gated call. The target's next administrative
    request is refused by the gate itself. Ending their sessions would be a
    second mechanism for an effect the first one already has -- and it would
    also log them out of everything they are still entitled to do.
    """
    target = _target(user_id)
    try:
        revoked = dao.revoke_role(session, target, role)
    except AuthorizationError:
        raise _forbidden()
    except NotFoundError:
        raise _not_found()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return RoleRevoked(revoked=revoked)


@router.post(
    "/users/{user_id}/disabled",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disable or re-enable a staff user in the CALLER'S OWN organisation",
    responses={
        204: {"description": "The user's disabled flag is set and, on disable, their live sessions end"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Not permitted"},
        404: {"model": ErrorResponse, "description": "Not found"},
    },
)
async def set_user_disabled(
    user_id: str,
    body: DisabledRequest,
    session: Session = Depends(_get_session),
    dao: DataAccess = Depends(_get_data_access),
) -> Response:
    """
    `DataAccess.set_user_disabled`, and nothing else.

    204 AND NO BODY, deliberately. Returning the updated user would mean a
    second decorated call (`get_user`) after the write — and `@auditable`
    commits after each audit row, so a composition is exactly the atomicity
    hazard w133 wrote this method as one body to avoid. An empty response is
    also the honest one: the method returns `None`.

    NO SELF-DISABLE RULE IS ADDED HERE. An Administrator disabling their own
    account ends their own sessions, because the domain method ends the
    target's sessions and the target is them. Whether that should be refused
    is a product decision; the existing rule is that there is no rule, and
    preserving an existing rule includes preserving its absence.
    """
    target = _target(user_id)
    try:
        dao.set_user_disabled(session, target, body.disabled)
    except AuthorizationError:
        raise _forbidden()
    except NotFoundError:
        raise _not_found()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/patient-logins/{patient_login_id}/disabled",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke or restore a patient portal credential in the CALLER'S OWN organisation",
    responses={
        204: {"description": "The credential's disabled flag is set and, on revoke, its live sessions end"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Not permitted"},
        404: {"model": ErrorResponse, "description": "Not found"},
    },
)
async def set_patient_login_disabled(
    patient_login_id: str,
    body: DisabledRequest,
    session: Session = Depends(_get_session),
    dao: DataAccess = Depends(_get_data_access),
) -> Response:
    """
    `DataAccess.set_patient_login_disabled`, and nothing else.

    THE TARGET IS A CREDENTIAL, NOT A PATIENT. The path segment is a
    `patient_login_id`, which is what the domain method takes and what the
    audit row records, and it is deliberately not a `patient_id`: revocation
    withdraws the thing that mints sessions, and every session that credential
    minted ends with it.

    THIS IS A STAFF ROUTE ON THE STAFF ROUTER, authenticated by the STAFF
    session dependency. It touches patient credentials and no patient
    principal can reach it: a patient session id presented here is refused by
    `_get_session` as the anonymous refusal, like any other non-staff
    credential.

    ISSUANCE IS NOT WIRED and revocation is; the module docstring gives the
    citation and the asymmetry. In a deployment where nothing can yet issue a
    credential this route has nothing to act on, and that is not a reason to
    leave the contracting half unbuilt.
    """
    target = _target(patient_login_id)
    try:
        dao.set_patient_login_disabled(session, target, body.disabled)
    except AuthorizationError:
        raise _forbidden()
    except NotFoundError:
        raise _not_found()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/audit",
    response_model=List[AuditEntry],
    summary="Read the CALLER'S OWN organisation's audit trail (Auditor)",
    responses={
        200: {"description": "Audit entries, oldest first"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Not permitted"},
    },
)
async def read_audit(
    action: Optional[List[str]] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    session: Session = Depends(_get_session),
    dao: DataAccess = Depends(_get_data_access),
) -> List[AuditEntry]:
    """
    `DataAccess.read_audit`, and nothing else.

    AUDITOR, NOT ADMINISTRATOR — the one route on this surface with a
    different gate, and the gate is the domain method's, unchanged. Reading
    the audit log is itself NOT audited (`@auditable(..., auditable=False)`,
    "audit access is not a resource action"); that is an existing decision and
    this route does not revisit it.

    THERE IS NO ORGANISATION PARAMETER AND NO ACTOR PARAMETER. The only
    filters are `action`, which is a vocabulary rather than an identifier, and
    `limit`. A caller cannot ask for another organisation's trail because
    there is nowhere to put the request, and the method's own
    `WHERE org_id = %s` is bound from the session regardless.

    `limit` IS BOUNDED AT THE EDGE (1..1000) because an unbounded one is an
    availability lever an authenticated Auditor should not have; the domain
    method's default of 100 is unchanged and the bound is a ceiling on the
    parameter, not a change to what the method does with it.

    ROWS ARE RENDERED, NOT INTERPRETED. `details` is passed through as the
    JSONB object the method returned; `ip_address` and the identifiers are
    stringified because a UUID and an `inet` are not JSON. Nothing is
    filtered, reordered or summarised here — a second view of the audit trail
    is a second answer to "what happened".
    """
    try:
        rows = dao.read_audit(session, action or None, limit)
    except AuthorizationError:
        raise _forbidden()

    return [
        AuditEntry(
            log_id=row[0],
            org_id=str(row[1]) if row[1] is not None else None,
            user_id=str(row[2]) if row[2] is not None else None,
            action=row[3],
            details=row[4],
            ip_address=str(row[5]) if row[5] is not None else None,
            timestamp=row[6].isoformat(),
        )
        for row in rows
    ]
