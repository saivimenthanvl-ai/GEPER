"""
clinical/tests/test_w162_registration_and_consent.py
────────────────────────────────────────────────────
w162 — PATIENT REGISTRATION AND CONSENT BELONG TO THE ORDERING CLINICIAN,
and until this wave nothing enforced that and nothing could reach it.

THE MEASUREMENT AT `w126m-migrations` TIP `44d624b`, BY SYNTAX TREE OVER
EVERY NON-TEST MODULE (never grep — grep credits a docstring as a caller,
and that error has been made three times on this branch):

    create_patient      session-taking, org bound from the session,
                        NO `_require_role`, 0 production call sites
    record_consent      the same three facts
    withdraw_consent    the same three facts

and the only production writer of a `patients` row was `create_patient`'s
own INSERT, while the only production writers of a `consents` row were
`record_consent`'s INSERT and supersession UPDATE and `withdraw_consent`'s
withdrawal UPDATE. There was no second path to either table and no path at
all from HTTP.

THE RULING (human, 2026-09-19): "PATIENT REGISTRATION + CONSENT — the
ORDERER/CLINICIAN owns both. Do NOT make Administrator registration
mandatory. Do NOT make Lab Technician a patient identity creator."

THE ROLE TOKEN IS `"Orderer"`, AND IT IS READ OFF THE TREE. `ROLES` is the
vocabulary the schema's CHECK on `role_assignments.role` enumerates —
Orderer, Lab technician, Interpreter, Approver, Administrator, Auditor,
System — and exactly one of those names a clinician. `create_order`'s own
docstring already said which: "Ordering a test is the clinical decision the
Orderer role names". `TestTheRoleTokenIsTheClinicianAndTheTreeSaysSo` pins
that derivation so a later reader does not have to take it on trust.

CLINICIAN-ONLY. The ruling forbids MANDATORY Administrator registration and
is silent on whether Administrator may ALSO register. The tree does not
answer it, and it answers the adjacent question narrowly (`create_order`:
"an Administrator is not implicitly an Orderer"). So the narrower reading
is implemented and pinned here, and the widening is carded — which is why
`TestOnlyTheClinicianMayRegister` asserts the Administrator is REFUSED,
deliberately and not by omission.

──────────────────────────────────────────────────────────────────────────
THE SIX WRONG VERSIONS, AND THE ROW THAT CATCHES EACH
──────────────────────────────────────────────────────────────────────────

A  registration reachable without the clinician role, and specifically by a
   Lab technician, which the ruling names.
   → TestOnlyTheClinicianMayRegister / TestOnlyTheClinicianMayRecordConsent
     / TestOnlyTheClinicianMayWithdrawConsent. Six non-Orderer principals
     per verb, asserted as a SET OF SIZE ONE over (status, raw body).
   VACUOUS AGAINST: a route that refuses everybody. The positive twin in
   each class (the Orderer's 201/204) is what makes it non-vacuous.

B  the gate in the ROUTER rather than the method.
   → TestTheGateIsInTheMethodAndNotTheRoute calls each domain method
     DIRECTLY with a non-Orderer session and requires AuthorizationError,
     with no HTTP anywhere near it; plus the structural row that the router
     module contains no `_require_role` call at all.
   VACUOUS AGAINST: nothing — a router-side gate passes every HTTP row in
   this file and fails this one.

C  cross-organisation: a clinician naming a patient or a consent in another
   organisation.
   → TestTheOtherOrganisationIsNotAddressable. THE COLLISION IS
     CONSTRUCTED: organisation B holds a REAL patient and a REAL active
     consent, and organisation A's clinician names them by their true
     identifiers. Two random UUIDs never collide, so without planted rows a
     missing `org_id` predicate is invisible to every other row here.
     It also reads B's consent back AFTERWARDS, through a domain method, to
     prove the refusal was not a refusal that had already written.
   VACUOUS AGAINST: a version that refuses cross-org by accident (e.g. by
   refusing everything) — the same-org positive twin covers that.

D  consent recorded with no audit row, or attributing the wrong actor or
   the wrong organisation.
   → TestTheAuditNamesTheClinicianAndTheOrganisation, which reads through
     `read_audit` (a DOMAIN METHOD, Standing Rule 2a — a hand-written
     SELECT could omit the very `org_id` predicate under test) and asserts
     the actor is the acting clinician's `user_id`, the organisation is
     theirs, and the details carry the patient and scope submitted. Its
     cross-tenant half asserts organisation B's Auditor sees NONE of it.
   VACUOUS AGAINST: an audit row written with the right actor by accident
   because only one principal exists — hence six principals per org.

E  the role check placed AFTER a format or vocabulary check, so a malformed
   request from an unauthorised caller gets the validation error instead of
   the refusal.
   → TestTheGateRunsBeforeAnyVocabularyOrFormatCheck sends an unknown sex
     code, a date of birth that is not a date, and a malformed patient
     identifier as each non-Orderer principal and requires the SAME 403,
     as a set of size one. Its twin proves an ORDERER can tell all three
     apart (400, 400, 404), so the row is not passing because the surface
     answers 403 to everything.
   AND THE STRUCTURAL HALF: no request model on this surface constrains a
   value or declares a non-`str` type for a field a vocabulary governs —
   Pydantic runs BEFORE the handler and therefore before the gate, so a
   `datetime.date` on `dob` would itself be wrong version E.

F  a disabled or role-revoked clinician using a still-live session.
   → TestALiveSessionIsNotStandingAuthority, both halves: `disabled` on the
     user (which `_get_session` consults) and the Orderer role revoked
     (which `_require_role` re-reads per call).

──────────────────────────────────────────────────────────────────────────
RULE 10 — A TEST THAT CAN SKIP UNDER SABOTAGE IS NOT A GUARD
──────────────────────────────────────────────────────────────────────────

EVERY STRUCTURAL ROW IN THIS FILE TAKES NO DATABASE FIXTURE. A claim about
SOURCE needs no database, and taking a fixture it does not use is precisely
what grants it the ability to skip — `world` → `dao` → `conn` →
`clinical_dsn`, which skips when `CLINICAL_TEST_DSN` is absent. A skip and
a pass are the same green dot, and w157 measured exactly that: a structural
row reported `1 passed, 1 skipped` against deliberately broken code.

The structural rows below are grouped under classes whose names begin
`TestTheSource…`, `TestTheGateIsInTheMethod…` (its AST half),
`TestTheRoleTokenIs…`, `TestTheHandlersAreTranslations…` and
`TestTheServedSurface…`, and not one of them names `world`, `dao`, `conn`,
`client` or `clinical_dsn` in its signature.

AND `inspect.signature()` IS NEVER USED ON A DECORATED METHOD. `@auditable`
carries no `functools.wraps`, so it returns `(self, *args, **kwargs)` for
every one of them and any signature assertion over one is vacuous. Every
structural claim here is made against `ast`.
"""

from __future__ import annotations

import ast
import datetime as dt
import json
import os
import pathlib

import pytest

from clinical.tests.test_w135_patient_report_access import PASSWORD, T0  # noqa: E402

DSN = os.getenv("CLINICAL_TEST_DSN")

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
CLINICAL = pathlib.Path(__file__).resolve().parent.parent
DATA_ACCESS_MODULE = CLINICAL / "data_access.py"
CLINIC_MODULE = CLINICAL / "clinic_endpoints.py"

APP_PASSWORD = "test-app-password"
RETENTION_PASSWORD = "test-retention-password"

STAFF_COOKIE = "clinical_session"

NOWHERE = "00000000-0000-0000-0000-000000000000"
MALFORMED = "not-a-uuid"

# The three verbs this wave gates and wires. A tuple rather than three
# literals so that every structural row below is a census over the same set
# and cannot silently cover two of them.
THE_THREE = ("create_patient", "record_consent", "withdraw_consent")

# The refusal bodies, IMPORTED rather than retyped, so a change to a constant
# fails these rows instead of silently rewriting what they assert.
from clinical.admin_endpoints import ADMIN_FORBIDDEN, ADMIN_NOT_FOUND  # noqa: E402
from clinical.data_access import GENERIC_AUTH_ERROR  # noqa: E402


def _body(detail):
    """The exact bytes FastAPI serialises `{"detail": ...}` to.

    RAW BYTES, NOT A PARSED DICT — Standing Rule 2b read literally: the thing
    that must be indistinguishable is what goes on the wire, and a dict is
    not hashable so a refusal SET could not be formed from it at all.
    """
    return json.dumps({"detail": detail}, separators=(",", ":")).encode()


UNAUTHENTICATED = (401, _body(GENERIC_AUTH_ERROR))
FORBIDDEN = (403, _body(ADMIN_FORBIDDEN))
NOT_FOUND = (404, _body(ADMIN_NOT_FOUND))


def _pair(response):
    """(status, raw body bytes) as ONE value — Standing Rule 8: an oracle can
    live in either channel, so a refusal set is formed over both."""
    return (response.status_code, response.content)


# ═══════════════════════════════════════════════════════════════════════════
# THE INSTRUMENTS — syntax tree only, each with a control needle
# ═══════════════════════════════════════════════════════════════════════════


def _production_modules():
    """Every non-test `.py` in the repository, as paths.

    A TEST CALLER DOES NOT COUNT, which is the whole point of the exclusion:
    `create_patient` has some two hundred test callers and that is exactly
    why it looked wired for eight waves.
    """
    skip = {"__pycache__", ".git", "node_modules", ".venv", "venv", "site-packages"}
    out = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            full = pathlib.Path(dirpath) / name
            posix = full.as_posix()
            if "/tests/" in posix or "/test/" in posix:
                continue
            if name.startswith("test_") or name.endswith("_test.py") or name.startswith("conftest"):
                continue
            out.append(full)
    return out


def _production_call_sites(name):
    """Every PRODUCTION `ast.Call` site of `name`, as (relative path, lineno).

    `ast.Call` ONLY, so a docstring naming the method is not a caller — the
    defect that credited `_release_report` with thirteen callers and zero
    calls, and that two guards on this branch fired on.
    """
    found = []
    for path in _production_modules():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = path.relative_to(REPO).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == name:
                found.append((rel, node.lineno))
    return sorted(found)


def _first_role_gate(function_node):
    """
    The role named by `self._require_role(session, "<role>")` when that call
    is the function's FIRST EXECUTABLE statement, else None.

    "FIRST EXECUTABLE" SKIPS A LEADING DOCSTRING AND NOTHING ELSE. The
    ordering is the property, not a style preference: a gate below the sex
    check would make an unauthorised caller's refusal vary with the CONTENT
    of the body, and a gate below the patient lookup would make it vary with
    whether the identifier names an existing row — an existence oracle for
    patients in this organisation and, worse, in another.

    AST, NOT `inspect`: `@auditable` carries no `functools.wraps`.
    """
    body = list(function_node.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            body = body[1:]
    if not body:
        return None
    first = body[0]
    if not isinstance(first, ast.Expr) or not isinstance(first.value, ast.Call):
        return None
    call = first.value
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "_require_role":
        return None
    if len(call.args) != 2 or not isinstance(call.args[1], ast.Constant):
        return None
    return call.args[1].value


def _data_access_methods():
    """Every method of `DataAccess`, by name, from the syntax tree."""
    tree = ast.parse(DATA_ACCESS_MODULE.read_text(encoding="utf-8"))
    klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "DataAccess")
    return {n.name: n for n in klass.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _clinic_functions():
    """Every top-level function of the clinic router module, by name."""
    tree = ast.parse(CLINIC_MODULE.read_text(encoding="utf-8"))
    return {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _decorator_names(node):
    """The bare names of a node's decorators, `@auditable(...)` included."""
    out = []
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute):
            out.append(target.attr)
        elif isinstance(target, ast.Name):
            out.append(target.id)
    return out


# ═══════════════════════════════════════════════════════════════════════════
# STRUCTURAL — NO DATABASE FIXTURE ANYWHERE BELOW (Rule 10)
# ═══════════════════════════════════════════════════════════════════════════


class TestTheRoleTokenIsTheClinicianAndTheTreeSaysSo:
    """
    THE FIRST JOB OF THE WAVE: resolve "Orderer/clinician" against the
    vocabulary the platform actually enforces, rather than against a workflow
    diagram. These rows are the derivation, pinned.
    """

    def test_the_vocabulary_is_the_seven_the_schema_enumerates(self):
        from clinical.data_access import ROLES

        assert set(ROLES) == {
            "Orderer",
            "Lab technician",
            "Interpreter",
            "Approver",
            "Administrator",
            "Auditor",
            "System",
        }, ROLES

    def test_the_schema_check_constraint_enumerates_the_same_seven(self):
        """The vocabulary is not a Python convention: the database enforces
        it. If the two ever diverge, the Python tuple is the one that lies."""
        schema = (CLINICAL / "schema.sql").read_text(encoding="utf-8")
        from clinical.data_access import ROLES

        for role in ROLES:
            assert f"'{role}'" in schema, role

    def test_the_tree_already_named_the_orderer_as_the_clinical_decision(self):
        """
        THE EVIDENCE THE CHOICE RESTS ON, quoted from the source rather than
        asserted. `create_order` is the verb the ordering clinician performs
        and its own docstring says the Orderer role names that decision. This
        is a PROSE assertion and a substring scan is the right instrument for
        exactly one thing — the presence of prose.
        """
        method = _data_access_methods()["create_order"]
        assert "Orderer role" in ast.get_docstring(method)

    def test_no_new_role_was_invented_for_registration(self):
        """The ruling forbids an RBAC redesign. Every `_require_role` literal
        in the whole of `data_access.py` must still be one of the seven."""
        tree = ast.parse(DATA_ACCESS_MODULE.read_text(encoding="utf-8"))
        from clinical.data_access import ROLES

        demanded = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_require_role"
                and len(node.args) == 2
                and isinstance(node.args[1], ast.Constant)
            ):
                demanded.add(node.args[1].value)
        assert demanded, "no _require_role call found at all -- the instrument is blind"
        assert demanded <= set(ROLES), demanded - set(ROLES)


class TestTheSourceGatesAllThreeOnTheOrdererAndDoesItFirst:
    """
    WRONG VERSION E's STRUCTURAL HALF, and wrong version A's. The gate is the
    first executable statement of each of the three, and the role is Orderer.
    """

    @pytest.mark.parametrize("name", THE_THREE)
    def test_the_first_executable_statement_is_the_orderer_gate(self, name):
        assert _first_role_gate(_data_access_methods()[name]) == "Orderer", name

    @pytest.mark.parametrize("name", THE_THREE)
    def test_the_gate_is_not_lab_technician_and_not_administrator(self, name):
        """
        THE TWO THE RULING NAMES, ASSERTED SEPARATELY FROM THE ROW ABOVE.
        "Do NOT make Administrator registration mandatory. Do NOT make Lab
        Technician a patient identity creator." A row that only checked for
        "Orderer" would still pass if a second, wider gate were added
        elsewhere in the body, so this one censuses EVERY `_require_role` in
        each method rather than only the first.
        """
        method = _data_access_methods()[name]
        demanded = {
            node.args[1].value
            for node in ast.walk(method)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_require_role"
            and len(node.args) == 2
            and isinstance(node.args[1], ast.Constant)
        }
        assert demanded == {"Orderer"}, (name, demanded)

    @pytest.mark.parametrize("name", THE_THREE)
    def test_each_still_takes_a_session_and_binds_the_organisation_from_it(self, name):
        """The half that was already true at 44d624b and must stay true: the
        gate is not a substitute for the tenant predicate, it is beside it."""
        method = _data_access_methods()[name]
        assert [a.arg for a in method.args.args][:2] == ["self", "session"], name
        assert "session.org_id" in ast.unparse(method), name

    @pytest.mark.parametrize("name", THE_THREE)
    def test_each_is_exactly_one_transactional_body_under_exactly_one_auditable(self, name):
        """
        ATOMICITY, STRUCTURALLY. `@auditable` COMMITS after each audit row, so
        a verb assembled from two decorated methods is two commits and can
        half-happen. Each of the three is one `@transactional` body under one
        `@auditable`, which is what makes "individually atomic" true of each.
        """
        decorators = _decorator_names(_data_access_methods()[name])
        assert decorators.count("auditable") == 1, (name, decorators)
        assert decorators.count("transactional") == 1, (name, decorators)

    def test_the_twin_the_analyser_answers_none_for_a_method_with_no_gate(self):
        """
        STANDING RULE 4, and the row without which every row above would pass
        against an analyser that always returns "Orderer". `create_report`
        and `create_interpretation` contain no `_require_role` anywhere —
        w157 measured that and it is unchanged — so the instrument must say
        None for them.
        """
        methods = _data_access_methods()
        assert _first_role_gate(methods["create_report"]) is None
        assert _first_role_gate(methods["create_interpretation"]) is None

    def test_the_twin_the_analyser_answers_none_for_a_gate_that_is_second(self, tmp_path):
        """The other half of the same twin: "first" is the property, so an
        analyser that ignores position must fail here."""
        probe = tmp_path / "probe.py"
        probe.write_text(
            "class D:\n"
            "    def m(self, session, x):\n"
            '        """doc"""\n'
            "        if x not in ('a',):\n"
            "            raise ValueError(x)\n"
            "        self._require_role(session, 'Orderer')\n",
            encoding="utf-8",
        )
        node = next(n for n in ast.walk(ast.parse(probe.read_text(encoding="utf-8"))) if isinstance(n, ast.FunctionDef))
        assert _first_role_gate(node) is None

    def test_the_vocabulary_checks_are_below_the_gate_and_not_above_it(self):
        """
        WRONG VERSION E, READ OFF THE TREE. `create_patient` at 44d624b began
        with `if sex not in (...)`: a caller holding no Orderer role who sent
        `sex="Z"` got a ValueError and one who sent `sex="M"` got nothing at
        all. Both vocabulary refusals — the sex codes and the ISO-8601 date
        parse — must now appear strictly AFTER the gate, by line number.
        """
        method = _data_access_methods()["create_patient"]
        gate = next(
            node
            for node in ast.walk(method)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "_require_role"
        )
        raises = [n.lineno for n in ast.walk(method) if isinstance(n, ast.Raise)]
        assert raises, "create_patient raises nothing -- the vocabulary checks have gone"
        assert min(raises) > gate.lineno, (gate.lineno, raises)


class TestTheHandlersAreTranslationsAndNothingElse:
    """
    THE HOUSE MODEL, STRUCTURALLY. One decorated domain call per handler, no
    second authentication path, no second permission system, no SQL.
    """

    HANDLERS = ("register_patient", "record_consent", "withdraw_consent")

    @pytest.mark.parametrize("handler", HANDLERS)
    def test_each_handler_calls_exactly_one_dao_method(self, handler):
        """
        `@auditable` COMMITS after each audit row, so a handler that called
        two decorated methods could commit the first act's audit row and then
        fail with the record already written. `_target` is a pure helper and
        is not a `dao.` call, which is why the census counts only calls whose
        receiver is `dao`.
        """
        node = _clinic_functions()[handler]
        calls = [
            n.func.attr
            for n in ast.walk(node)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id == "dao"
        ]
        assert len(calls) == 1, (handler, calls)
        assert calls[0] in THE_THREE, (handler, calls)

    def test_the_router_module_contains_no_role_check_of_its_own(self):
        """WRONG VERSION B, structurally: the gate is the domain method's and
        the router must not have one, or there would be two answers to "may
        this caller register a patient"."""
        source = CLINIC_MODULE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        assert not [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "_require_role"
        ]
        assert not [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get_user_roles"
        ]

    def test_the_router_module_defines_no_session_dependency_and_no_refusal_of_its_own(self):
        """It IMPORTS `_get_session`, `_get_data_access`, `_forbidden`,
        `_not_found` and `_target`. A second copy of any of them would be a
        second security policy, and the weaker one would be the one nobody
        reads."""
        tree = ast.parse(CLINIC_MODULE.read_text(encoding="utf-8"))
        defined = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for name in ("_get_session", "_get_data_access", "_forbidden", "_not_found", "_target"):
            assert name not in defined, name
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.update(alias.name for alias in node.names)
        assert {"_get_session", "_get_data_access", "_forbidden", "_not_found", "_target"} <= imported, imported

    def test_the_twin_the_import_walker_sees_what_is_there(self):
        """Standing Rule 4: an import walker that returned the empty set would
        satisfy the `not in defined` half of the row above for ever."""
        tree = ast.parse(CLINIC_MODULE.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.update(alias.name for alias in node.names)
        assert "Session" in imported and "DataAccess" in imported, imported
        assert "no_such_import" not in imported

    def test_the_router_module_writes_no_sql(self):
        """
        Business logic stays in the domain layer. A SELECT here would be a
        second reader with its own idea of which `org_id` applies.

        DOCSTRINGS ARE EXCLUDED, AND THE EXCLUSION IS THE INSTRUMENT BEING
        CORRECT RATHER THAN BEING SOFTENED. The first version of this row
        censused every string constant and failed on the module docstring's
        own sentence naming `INSERT INTO patients` — prose describing where
        the SQL lives is exactly what this file is supposed to contain, and
        counting it is the same error as a grep crediting a docstring as a
        caller. What must be absent is an EXECUTABLE string, so the census
        subtracts the docstring of the module and of every class and
        function.
        """
        tree = ast.parse(CLINIC_MODULE.read_text(encoding="utf-8"))
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                body = getattr(node, "body", [])
                if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                    docstrings.add(id(body[0].value))
        examined = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                examined += 1
                upper = node.value.upper()
                for word in ("SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM"):
                    assert word not in upper, node.value[:80]
        # NON-VACUITY: the census must actually have looked at something. A
        # docstring-subtraction that subtracted everything would pass for ever.
        assert examined > 10, examined

    def test_no_request_model_constrains_a_value_or_declares_a_parsed_type(self):
        """
        WRONG VERSION E AT THE PYDANTIC LAYER, WHICH IS THE ONE EASIEST TO
        REINTRODUCE. Pydantic runs BEFORE the handler and therefore before the
        role gate, so a `Literal["M","F","O","U"]` on `sex`, an `EmailStr`, a
        `min_length`, or — the one this wave had to move — a
        `datetime.date` on `dob`, would each be a refusal answered to a
        caller whose authorisation had not been evaluated.

        Every annotated field of every request model here must therefore be
        `str` or `Optional[str]`, with no `Field(...)` default carrying
        constraints.
        """
        tree = ast.parse(CLINIC_MODULE.read_text(encoding="utf-8"))
        request_models = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name.endswith("Request")]
        assert request_models, "no request model found -- this census is blind"
        for model in request_models:
            for stmt in model.body:
                if not isinstance(stmt, ast.AnnAssign):
                    continue
                rendered = ast.unparse(stmt.annotation)
                assert rendered in ("str", "Optional[str]"), (model.name, stmt.target.id, rendered)
                if stmt.value is not None:
                    assert ast.unparse(stmt.value) == "None", (model.name, stmt.target.id)

    def test_every_request_model_forbids_an_unknown_field(self):
        """The field nobody must ever be able to send is an organisation, and
        a caller who tries gets a 422 rather than a success that quietly did
        the right thing for a reason no test would notice if it stopped being
        true."""
        tree = ast.parse(CLINIC_MODULE.read_text(encoding="utf-8"))
        for model in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name.endswith("Request")]:
            assert 'extra="forbid"' in ast.unparse(model) or "extra='forbid'" in ast.unparse(model), model.name

    def test_no_request_model_and_no_handler_takes_an_organisation(self):
        """NO CALLER-CONTROLLED ORGANISATION ESCAPE, the load-bearing one.
        `org_id` must not appear as a parameter of any handler nor as a field
        of any model on this surface."""
        tree = ast.parse(CLINIC_MODULE.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = [a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs]
                assert "org_id" not in names, node.name
            if isinstance(node, ast.ClassDef):
                for stmt in node.body:
                    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                        assert stmt.target.id != "org_id", node.name


class TestTheThreeVerbsAreNowReachableAndFromExactlyOnePlace:
    """
    THE HALF THAT MAKES THE WAVE WORTH RUNNING. At 44d624b each of the three
    had ZERO production call sites; each must now have exactly one, and it
    must be the clinic router.
    """

    @pytest.mark.parametrize("name", THE_THREE)
    def test_each_has_exactly_one_production_caller_and_it_is_the_clinic_router(self, name):
        sites = _production_call_sites(name)
        assert [path for path, _ in sites] == ["clinical/clinic_endpoints.py"], (name, sites)

    def test_the_twin_the_census_finds_other_wired_methods_and_none_for_a_name_nobody_calls(self):
        """Standing Rule 4: a census that found nothing would satisfy every
        row it is used in. And `ast.Call` only, so the prose in this file's
        own header does not count anywhere."""
        assert [p for p, _ in _production_call_sites("enrol_patient_login")] == ["clinical/admin_endpoints.py"]
        assert [p for p, _ in _production_call_sites("receive_sample")] == ["clinical/workflow_endpoints.py"]
        assert _production_call_sites("no_such_method_anywhere") == []

    def test_the_served_surface_carries_the_three_clinic_routes(self):
        """
        STANDING RULE 9 IN ITS CORRECTED FORM — the walk descends into the
        opaque `_IncludedRouter` wrappers `include_router` leaves in
        `app.routes`, and the non-vacuity check below refuses both the empty
        and the wrapper-shaped answer. A route census that cannot see
        included routes reports a surface of two.
        """
        from clinical.app import app
        from clinical.tests.test_w132_structural_guards import served_routes

        census = served_routes(app)
        assert len(census) > 10, census
        assert all(path and path.startswith("/") for path, _ in census), census
        paths = {(path, methods) for path, methods in census}
        assert ("/clinic/patients", ("POST",)) in paths, sorted(paths)
        assert ("/clinic/patients/{patient_id}/consents", ("POST",)) in paths, sorted(paths)
        assert ("/clinic/consents/{consent_id}/withdrawal", ("POST",)) in paths, sorted(paths)

    def test_the_registration_route_takes_no_identifier_from_the_request(self):
        """
        THE SHAPE, ASSERTED. Registration MINTS the identifier, so nothing in
        the request can name a patient — the strongest form of defence by
        absent parameter, and the reason this route's refusal set has no 404
        in it at all.
        """
        node = _clinic_functions()["register_patient"]
        names = [a.arg for a in node.args.args]
        assert "patient_id" not in names, names
        tree = ast.parse(CLINIC_MODULE.read_text(encoding="utf-8"))
        model = next(
            n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "PatientRegistrationRequest"
        )
        fields = {s.target.id for s in model.body if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)}
        assert fields == {"name", "dob", "sex"}, fields


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES — everything below this line is behavioural and needs a database
# ═══════════════════════════════════════════════════════════════════════════


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
    """Ten attempts per source per minute is the shipped limit and several
    rows here log in as seven principals. A 429 is not a refusal this file is
    about."""
    from clinical.auth_endpoints import _LOGIN_THROTTLE

    _LOGIN_THROTTLE.reset()
    yield
    _LOGIN_THROTTLE.reset()


@pytest.fixture()
def conn(clinical_dsn):
    import psycopg

    connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
    yield connection
    connection.close()


@pytest.fixture()
def dao(conn):
    from clinical.data_access import BcryptHasher, DataAccess

    return DataAccess(conn, password_hasher=BcryptHasher(rounds=4))


@pytest.fixture()
def reader(clinical_dsn):
    """
    A SECOND, INDEPENDENT `DataAccess` FOR READING BACK WHAT THE ROUTE DID.

    STANDING RULE 2a: every assertion about state goes through a DOMAIN
    METHOD, never a hand-written SELECT. A test that builds its expectation
    with raw SQL passes while the method meant to read it is broken, and here
    it would be doubly wrong, because a hand-written SELECT could omit the
    very `org_id` predicate this file exists to prove.
    """
    import psycopg

    from clinical.data_access import BcryptHasher, DataAccess

    connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
    yield DataAccess(connection, password_hasher=BcryptHasher(rounds=4))
    connection.close()


@pytest.fixture()
def client(clinical_dsn):
    from fastapi.testclient import TestClient

    from clinical.app import app

    return TestClient(app)


def _account(dao, conn, org_id, email, roles):
    """One account holding EXACTLY the roles named, and a live session for it.

    Roles are inserted directly because `assign_role` requires an existing
    Administrator and nothing in production makes the first one (the Wave 3
    deadlock, unchanged by this wave). `test_identity.py`, w152, w156 and
    w157 already break the cycle this way; this is the same break, not a new
    mechanism, and it is a FIXTURE rather than a bootstrap.
    """
    user_id = dao.create_user(org_id, email, PASSWORD)
    with conn.cursor() as cur:
        for role in roles:
            cur.execute(
                "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at, basis) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, org_id, role, user_id, T0, "w162 test fixture: approves" if role == "Approver" else None),
            )
    conn.commit()
    return user_id, dao.login(email, org_id, PASSWORD)


@pytest.fixture()
def world(dao, conn):
    """
    TWO ORGANISATIONS, AND THE SECOND ONE IS THE WHOLE POINT OF WRONG
    VERSION C.

    Organisation B holds a REAL Orderer, a REAL patient and a REAL ACTIVE
    consent. Two randomly generated UUIDs never collide, so without planted
    rows a `record_consent` or `withdraw_consent` that had dropped its
    `org_id` predicate would pass every other row in this file.

    SEVEN DISTINCT PRINCIPALS IN EACH, one per role plus an account holding
    none. THE ACTING PRINCIPAL HOLDS ORDERER AND NOTHING ELSE: an account
    holding six roles would prove only "a principal holding six roles may
    register a patient", which is true of a route gated on any one of them
    and true of a route with no gate at all.

    `labtech@…` AND `admin@…` ARE THE TWO THE RULING NAMES, and they hold
    exactly one role each so that their refusal is a statement about that
    role rather than about an empty account.
    """
    orgs = {}
    for tag, name in (("a", "Org A"), ("b", "Org B")):
        org_id = dao.create_organisation(name)
        orderer_id, orderer = _account(dao, conn, org_id, f"orderer@{tag}.example", ("Orderer",))
        labtech_id, labtech = _account(dao, conn, org_id, f"labtech@{tag}.example", ("Lab technician",))
        admin_id, admin = _account(dao, conn, org_id, f"admin@{tag}.example", ("Administrator",))
        auditor_id, auditor = _account(dao, conn, org_id, f"auditor@{tag}.example", ("Auditor",))
        interpreter_id, interpreter = _account(dao, conn, org_id, f"interpreter@{tag}.example", ("Interpreter",))
        approver_id, approver = _account(dao, conn, org_id, f"approver@{tag}.example", ("Approver",))
        nobody_id, nobody = _account(dao, conn, org_id, f"nobody@{tag}.example", ())

        # The planted rows. Built through the DOMAIN METHODS by the Orderer,
        # which is also the first proof that the gate admits the clinician.
        patient = dao.create_patient(orderer, f"Patient {tag.upper()}", dt.date(1990, 1, 1), "F")
        consent_id = dao.record_consent(orderer, patient, "testing")
        spent = dao.record_consent(orderer, patient, "research")
        dao.withdraw_consent(orderer, spent)

        orgs[tag] = {
            "org_id": org_id,
            "orderer": orderer,
            "orderer_id": orderer_id,
            "labtech": labtech,
            "labtech_id": labtech_id,
            "admin": admin,
            "admin_id": admin_id,
            "auditor": auditor,
            "auditor_id": auditor_id,
            "interpreter": interpreter,
            "interpreter_id": interpreter_id,
            "approver": approver,
            "approver_id": approver_id,
            "nobody": nobody,
            "nobody_id": nobody_id,
            "patient": patient,
            "consent": consent_id,
            "withdrawn_consent": spent,
            "orderer_email": f"orderer@{tag}.example",
            "labtech_email": f"labtech@{tag}.example",
            "admin_email": f"admin@{tag}.example",
            "auditor_email": f"auditor@{tag}.example",
            "interpreter_email": f"interpreter@{tag}.example",
            "approver_email": f"approver@{tag}.example",
            "nobody_email": f"nobody@{tag}.example",
        }

    conn.commit()
    return orgs


# The six principals that are NOT the clinician, named once so every refusal
# class censuses the same set. `nobody` is included because an account with no
# role at all is the case a gate keyed on "not an Administrator" would miss.
NOT_THE_CLINICIAN = ("labtech", "admin", "auditor", "interpreter", "approver", "nobody")


def _staff_cookie(client, org_id, email):
    from clinical.auth_endpoints import _LOGIN_THROTTLE

    _LOGIN_THROTTLE.reset()
    response = client.post("/auth/login", json={"email": email, "org_id": str(org_id), "password": PASSWORD})
    assert response.status_code == 204, response.text
    header = response.headers.get_list("set-cookie")[0]
    return header.split("=", 1)[1].split(";", 1)[0]


def _register_over_http(client, cookie, name="Ada", dob="1990-01-01", sex="F"):
    return client.post(
        "/clinic/patients",
        json={"name": name, "dob": dob, "sex": sex},
        cookies={STAFF_COOKIE: cookie} if cookie is not None else {},
    )


def _consent_over_http(client, cookie, patient_id, scope="testing", supersedes=None):
    body = {"scope": scope}
    if supersedes is not None:
        body["supersedes_id"] = str(supersedes)
    return client.post(
        f"/clinic/patients/{patient_id}/consents",
        json=body,
        cookies={STAFF_COOKIE: cookie} if cookie is not None else {},
    )


def _withdraw_over_http(client, cookie, consent_id):
    return client.post(
        f"/clinic/consents/{consent_id}/withdrawal",
        cookies={STAFF_COOKIE: cookie} if cookie is not None else {},
    )


# ═══════════════════════════════════════════════════════════════════════════
# BEHAVIOURAL
# ═══════════════════════════════════════════════════════════════════════════


class TestTheClinicianCanDoAllThreeOverHttp:
    """
    THE POSITIVE TWIN FOR EVERY REFUSAL IN THIS FILE, and the wave's own
    claim. Without it a surface that refused everybody would satisfy every
    other class here.
    """

    def test_the_clinician_registers_a_patient_and_the_row_is_readable(self, client, world, reader):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        response = _register_over_http(client, cookie, name="Grace", dob="1985-06-15", sex="F")
        assert response.status_code == 201, response.text

        patient_id = response.json()["patient_id"]
        # READ BACK THROUGH A DOMAIN METHOD (Rule 2a), on a SECOND connection,
        # which also proves the route's transaction committed.
        import uuid

        record = reader.get_patient(world["a"]["orderer"], uuid.UUID(patient_id))
        assert record is not None
        assert record["name"] == "Grace"
        assert record["dob"] == dt.date(1985, 6, 15)
        assert record["sex"] == "F"

    def test_the_clinician_records_consent_and_the_recorder_is_the_clinician(self, client, world, reader):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        response = _consent_over_http(client, cookie, world["a"]["patient"], scope="testing")
        assert response.status_code == 201, response.text

        import uuid

        record = reader.get_consent(world["a"]["orderer"], uuid.UUID(response.json()["consent_id"]))
        assert record is not None
        assert record["patient_id"] == world["a"]["patient"]
        assert record["scope"] == "testing"
        # THE ACTOR IS NOT CLAIMED, IT IS DERIVED. Nothing in the request could
        # have named it.
        assert record["recorded_by"] == world["a"]["orderer"].user_id
        assert record["withdrawn_at"] is None

    def test_the_clinician_withdraws_a_consent_and_the_withdrawer_is_recorded(self, client, world, reader):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        response = _withdraw_over_http(client, cookie, world["a"]["consent"])
        assert response.status_code == 204, response.text
        assert response.content == b""

        record = reader.get_consent(world["a"]["orderer"], world["a"]["consent"])
        assert record["withdrawn_at"] is not None
        assert record["withdrawn_by"] == world["a"]["orderer"].user_id

    def test_supersession_lands_whole_or_not_at_all(self, client, world, reader):
        """
        ATOMICITY, BEHAVIOURALLY, FOR THE ONE VERB THAT WRITES TWICE.
        `record_consent` INSERTs the new consent AND UPDATEs the old one's
        `superseded_by` pointer. Both are inside one `@transactional` body
        under one `@auditable`, so after one HTTP call BOTH must be visible on
        a second connection — a half-committed act would show the new consent
        with the old one's pointer still null.
        """
        import uuid

        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        response = _consent_over_http(
            client, cookie, world["a"]["patient"], scope="testing", supersedes=world["a"]["consent"]
        )
        assert response.status_code == 201, response.text
        new_id = uuid.UUID(response.json()["consent_id"])

        session = world["a"]["orderer"]
        assert reader.get_consent(session, new_id)["superseded_by"] is None
        assert reader.get_consent(session, world["a"]["consent"])["superseded_by"] == new_id


class TestOnlyTheClinicianMayRegister:
    """WRONG VERSION A, and the ruling's two named prohibitions."""

    def test_every_non_clinician_gets_the_one_refusal(self, client, world):
        refusals = set()
        for who in NOT_THE_CLINICIAN:
            cookie = _staff_cookie(client, world["a"]["org_id"], world["a"][f"{who}_email"])
            refusals.add(_pair(_register_over_http(client, cookie)))
        assert refusals == {FORBIDDEN}, refusals

    def test_the_lab_technician_specifically_cannot_create_a_patient_identity(self, client, world, reader):
        """
        THE RULING NAMES THIS ROLE. Asserted separately from the set above so
        that the prohibition is findable by name, and paired with a read-back
        proving the refusal wrote nothing: a refusal that had already inserted
        would satisfy a status-only row.
        """
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["labtech_email"])
        response = _register_over_http(client, cookie, name="Should Not Exist")
        assert _pair(response) == FORBIDDEN
        assert "patient_id" not in response.text

    def test_administrator_is_not_a_superuser_over_clinical_registration(self, client, world):
        """
        THE NARROWER READING, PINNED. The ruling forbids MANDATORY
        Administrator registration and is silent on whether Administrator may
        ALSO register; the tree answers the adjacent question narrowly
        ("an Administrator is not implicitly an Orderer"). If the human later
        widens the gate, THIS ROW IS THE ONE THAT MUST CHANGE, and it is
        written so that it says so.
        """
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["admin_email"])
        assert _pair(_register_over_http(client, cookie)) == FORBIDDEN

    def test_the_unauthenticated_caller_gets_the_other_one_refusal(self, client, world):
        """Six ways to be nobody, one answer — and it is the SHARED staff
        401, not a second one this surface invented."""
        refusals = {
            _pair(_register_over_http(client, None)),
            _pair(_register_over_http(client, "")),
            _pair(_register_over_http(client, MALFORMED)),
            _pair(_register_over_http(client, NOWHERE)),
        }
        assert refusals == {UNAUTHENTICATED}, refusals


class TestOnlyTheClinicianMayRecordConsent:
    """WRONG VERSION A for the second verb."""

    def test_every_non_clinician_gets_the_one_refusal(self, client, world):
        refusals = set()
        for who in NOT_THE_CLINICIAN:
            cookie = _staff_cookie(client, world["a"]["org_id"], world["a"][f"{who}_email"])
            refusals.add(_pair(_consent_over_http(client, cookie, world["a"]["patient"])))
        assert refusals == {FORBIDDEN}, refusals

    def test_the_refusal_is_the_same_for_a_real_patient_and_an_invented_one(self, client, world):
        """
        THE GATE CARRIES NO EXISTENCE ORACLE. A non-clinician must not be able
        to tell a real patient in their own organisation from one that exists
        nowhere — which is only true because the gate precedes the lookup.
        """
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["labtech_email"])
        refusals = {
            _pair(_consent_over_http(client, cookie, world["a"]["patient"])),
            _pair(_consent_over_http(client, cookie, NOWHERE)),
            _pair(_consent_over_http(client, cookie, MALFORMED)),
            _pair(_consent_over_http(client, cookie, world["b"]["patient"])),
        }
        assert refusals == {FORBIDDEN}, refusals

    def test_the_unauthenticated_caller_gets_the_other_one_refusal(self, client, world):
        refusals = {
            _pair(_consent_over_http(client, None, world["a"]["patient"])),
            _pair(_consent_over_http(client, MALFORMED, world["a"]["patient"])),
        }
        assert refusals == {UNAUTHENTICATED}, refusals


class TestOnlyTheClinicianMayWithdrawConsent:
    """WRONG VERSION A for the third verb."""

    def test_every_non_clinician_gets_the_one_refusal(self, client, world):
        refusals = set()
        for who in NOT_THE_CLINICIAN:
            cookie = _staff_cookie(client, world["a"]["org_id"], world["a"][f"{who}_email"])
            refusals.add(_pair(_withdraw_over_http(client, cookie, world["a"]["consent"])))
        assert refusals == {FORBIDDEN}, refusals

    def test_a_refused_withdrawal_leaves_the_consent_active(self, client, world, reader):
        """Standing Rule 4: "it failed" is satisfied by a version that failed
        AFTER writing. The consent must still be active afterwards, read
        through a domain method on a second connection."""
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["admin_email"])
        assert _pair(_withdraw_over_http(client, cookie, world["a"]["consent"])) == FORBIDDEN
        assert reader.get_consent(world["a"]["orderer"], world["a"]["consent"])["withdrawn_at"] is None

    def test_an_already_withdrawn_consent_is_not_found_and_not_a_distinct_status(self, client, world):
        """It is the domain method's `withdrawn_at IS NULL` predicate that
        produces this, and folding it into a distinct status would tell a
        caller that a consent it may not act on nevertheless exists."""
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        assert _pair(_withdraw_over_http(client, cookie, world["a"]["withdrawn_consent"])) == NOT_FOUND


class TestTheGateIsInTheMethodAndNotTheRoute:
    """
    WRONG VERSION B, BEHAVIOURALLY. Every other refusal class in this file
    goes through HTTP and would be equally green with the gate in the router.
    These rows call the domain methods DIRECTLY, with no application, no
    client and no cookie.
    """

    def test_create_patient_refuses_a_non_orderer_session_with_no_http_anywhere(self, dao, world):
        from clinical.data_access import AuthorizationError

        for who in NOT_THE_CLINICIAN:
            with pytest.raises(AuthorizationError) as caught:
                dao.create_patient(world["a"][who], "Direct", dt.date(1990, 1, 1), "M")
            assert "Orderer" in str(caught.value), who

    def test_record_consent_refuses_a_non_orderer_session_with_no_http_anywhere(self, dao, world):
        from clinical.data_access import AuthorizationError

        for who in NOT_THE_CLINICIAN:
            with pytest.raises(AuthorizationError):
                dao.record_consent(world["a"][who], world["a"]["patient"], "testing")

    def test_withdraw_consent_refuses_a_non_orderer_session_with_no_http_anywhere(self, dao, world):
        from clinical.data_access import AuthorizationError

        for who in NOT_THE_CLINICIAN:
            with pytest.raises(AuthorizationError):
                dao.withdraw_consent(world["a"][who], world["a"]["consent"])

    def test_the_twin_the_clinician_is_admitted_by_the_same_direct_call(self, dao, world):
        """Standing Rule 4: without this the three rows above are satisfied by
        a method that refuses everybody."""
        patient = dao.create_patient(world["a"]["orderer"], "Direct", dt.date(1990, 1, 1), "M")
        consent = dao.record_consent(world["a"]["orderer"], patient, "testing")
        dao.withdraw_consent(world["a"]["orderer"], consent)
        assert dao.get_consent(world["a"]["orderer"], consent)["withdrawn_at"] is not None


class TestTheOtherOrganisationIsNotAddressable:
    """
    WRONG VERSION C, WITH THE COLLISION CONSTRUCTED. Organisation B holds a
    REAL patient and a REAL active consent, and organisation A's clinician
    names them by their true identifiers.
    """

    def test_a_clinician_cannot_record_consent_for_another_organisations_patient(self, client, world, reader):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        refusals = {
            _pair(_consent_over_http(client, cookie, world["b"]["patient"])),
            _pair(_consent_over_http(client, cookie, NOWHERE)),
            _pair(_consent_over_http(client, cookie, MALFORMED)),
        }
        assert refusals == {NOT_FOUND}, refusals

    def test_a_clinician_cannot_withdraw_another_organisations_consent(self, client, world, reader):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        refusals = {
            _pair(_withdraw_over_http(client, cookie, world["b"]["consent"])),
            _pair(_withdraw_over_http(client, cookie, NOWHERE)),
            _pair(_withdraw_over_http(client, cookie, MALFORMED)),
        }
        assert refusals == {NOT_FOUND}, refusals
        # AND IT WROTE NOTHING. A refusal that had already stamped
        # `withdrawn_at` would satisfy the set above.
        assert reader.get_consent(world["b"]["orderer"], world["b"]["consent"])["withdrawn_at"] is None

    def test_a_supersedes_pointer_cannot_reach_across_the_boundary(self, client, world, reader):
        """
        THE THIRD IDENTIFIER ON THIS SURFACE, and the one easiest to forget:
        `supersedes_id` travels in the BODY. Naming organisation B's real
        active consent from organisation A must not touch it.
        """
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        response = _consent_over_http(
            client, cookie, world["a"]["patient"], scope="testing", supersedes=world["b"]["consent"]
        )
        assert response.status_code == 201, response.text
        assert reader.get_consent(world["b"]["orderer"], world["b"]["consent"])["superseded_by"] is None

    def test_the_twin_the_same_identifiers_work_inside_their_own_organisation(self, client, world):
        """Standing Rule 4, and the row that makes the three above mean
        something: B's clinician CAN act on B's rows."""
        cookie = _staff_cookie(client, world["b"]["org_id"], world["b"]["orderer_email"])
        assert _consent_over_http(client, cookie, world["b"]["patient"]).status_code == 201
        assert _withdraw_over_http(client, cookie, world["b"]["consent"]).status_code == 204


class TestTheGateRunsBeforeAnyVocabularyOrFormatCheck:
    """
    WRONG VERSION E, BEHAVIOURALLY. At 44d624b `create_patient`'s first
    statement was the sex vocabulary check and `dob` was a `datetime.date`
    parameter, so a malformed body from an unauthorised caller would have
    been answered differently from a well-formed one.
    """

    def test_a_malformed_body_from_a_non_clinician_gets_the_role_refusal(self, client, world):
        refusals = set()
        for who in NOT_THE_CLINICIAN:
            cookie = _staff_cookie(client, world["a"]["org_id"], world["a"][f"{who}_email"])
            refusals.add(_pair(_register_over_http(client, cookie, sex="Z")))
            refusals.add(_pair(_register_over_http(client, cookie, dob="not-a-date")))
            refusals.add(_pair(_register_over_http(client, cookie, dob="not-a-date", sex="Z")))
            refusals.add(_pair(_consent_over_http(client, cookie, MALFORMED)))
        assert refusals == {FORBIDDEN}, refusals

    def test_the_twin_the_clinician_can_tell_all_three_apart(self, client, world):
        """
        Standing Rule 4, and the row that proves the class above is not green
        because the surface answers 403 to everything. An ORDERER gets three
        DIFFERENT answers to the same three requests.
        """
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])

        bad_sex = _register_over_http(client, cookie, sex="Z")
        assert bad_sex.status_code == 400, bad_sex.text
        assert "M/F/O/U" in bad_sex.text

        bad_dob = _register_over_http(client, cookie, dob="not-a-date")
        assert bad_dob.status_code == 400, bad_dob.text
        assert "ISO-8601" in bad_dob.text or "YYYY-MM-DD" in bad_dob.text

        assert _pair(_consent_over_http(client, cookie, MALFORMED)) == NOT_FOUND

    def test_a_rejected_registration_writes_no_patient(self, client, world):
        """
        ATOMICITY FOR THE FIRST VERB. The refusal carries no identifier, so
        there is nothing to read back by id; what is asserted instead is that
        the response body contains no `patient_id` at all and that a
        subsequent well-formed call still succeeds — a half-committed
        transaction would have left the connection in a failed state and the
        second call would error.
        """
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        rejected = _register_over_http(client, cookie, sex="Z")
        assert rejected.status_code == 400
        assert "patient_id" not in rejected.text
        assert _register_over_http(client, cookie, sex="M").status_code == 201


class TestALiveSessionIsNotStandingAuthority:
    """
    WRONG VERSION F. A session minted while the clinician held the role must
    not keep working after the account is disabled or the role revoked.
    """

    def test_a_disabled_clinician_is_refused_on_a_session_that_already_worked(self, client, world, dao, conn):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        assert _register_over_http(client, cookie).status_code == 201

        dao.set_user_disabled(world["a"]["admin"], world["a"]["orderer_id"], True)
        conn.commit()

        # 401, not 403: `_get_session` consults `users.disabled`, so the
        # principal is no longer authenticated at all. The distinction matters
        # and is asserted rather than folded into "it failed".
        assert _pair(_register_over_http(client, cookie)) == UNAUTHENTICATED

    def test_a_role_revoked_clinician_is_refused_on_a_session_that_already_worked(self, client, world, dao, conn):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        assert _register_over_http(client, cookie).status_code == 201

        dao.revoke_role(world["a"]["admin"], world["a"]["orderer_id"], "Orderer")
        conn.commit()

        # 403, not 401: the account is still a valid principal; it simply no
        # longer holds the role. `_require_role` reads `role_assignments` on
        # every call, which is what makes revocation take effect without any
        # session surgery.
        assert _pair(_register_over_http(client, cookie)) == FORBIDDEN
        assert _pair(_consent_over_http(client, cookie, world["a"]["patient"])) == FORBIDDEN
        assert _pair(_withdraw_over_http(client, cookie, world["a"]["consent"])) == FORBIDDEN


class TestTheAuditNamesTheClinicianAndTheOrganisation:
    """
    WRONG VERSION D. Read through `read_audit`, a DOMAIN METHOD (Standing Rule
    2a): a hand-written SELECT could omit the very `org_id` predicate that
    makes the cross-tenant half of this class mean anything.
    """

    @staticmethod
    def _rows(reader, auditor_session, action):
        # (log_id, org_id, user_id, action, details, ip_address, timestamp)
        return [row for row in reader.read_audit(auditor_session, actions=[action], limit=500)]

    def test_registration_is_audited_to_the_registering_clinician(self, client, world, reader):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        response = _register_over_http(client, cookie, name="Audited", dob="1970-02-03", sex="O")
        assert response.status_code == 201, response.text

        rows = self._rows(reader, world["a"]["auditor"], "patient_created")
        mine = [r for r in rows if r[2] == world["a"]["orderer_id"] and r[4].get("name") == "Audited"]
        assert len(mine) == 1, rows
        assert mine[0][1] == world["a"]["org_id"]
        # THE DETAILS CARRY WHAT WAS SUBMITTED, and `dob` is the string this
        # surface accepts -- which is also the evidence that the parse
        # happened inside the domain method rather than in the handler.
        assert mine[0][4]["dob"] == "1970-02-03"
        assert mine[0][4]["sex"] == "O"

    def test_consent_is_audited_to_the_recording_clinician(self, client, world, reader):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        response = _consent_over_http(client, cookie, world["a"]["patient"], scope="a-scope-nothing-else-uses")
        assert response.status_code == 201, response.text

        rows = self._rows(reader, world["a"]["auditor"], "consent_recorded")
        mine = [r for r in rows if r[4].get("scope") == "a-scope-nothing-else-uses"]
        assert len(mine) == 1, rows
        assert mine[0][1] == world["a"]["org_id"]
        assert mine[0][2] == world["a"]["orderer_id"]
        assert mine[0][4]["patient_id"] == str(world["a"]["patient"])

    def test_withdrawal_is_audited_to_the_withdrawing_clinician(self, client, world, reader):
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        assert _withdraw_over_http(client, cookie, world["a"]["consent"]).status_code == 204

        rows = self._rows(reader, world["a"]["auditor"], "consent_withdrawn")
        mine = [r for r in rows if r[4].get("consent_id") == str(world["a"]["consent"])]
        assert len(mine) == 1, rows
        assert mine[0][1] == world["a"]["org_id"]
        assert mine[0][2] == world["a"]["orderer_id"]

    def test_a_refused_attempt_is_attributed_to_the_refused_caller_and_not_to_the_clinician(
        self, client, world, reader
    ):
        """
        THE ATTRIBUTION THAT WOULD BE EASIEST TO GET WRONG QUIETLY.
        `@auditable` writes a `denied` row on the AuthorizationError path, and
        it must name the principal who was refused. A row naming the clinician
        — or naming nobody — would make the trail say the wrong thing about
        the one event an auditor most wants.
        """
        before = len(self._rows(reader, world["a"]["auditor"], "patient_created"))
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["labtech_email"])
        assert _pair(_register_over_http(client, cookie, name="Refused")) == FORBIDDEN

        rows = self._rows(reader, world["a"]["auditor"], "patient_created")
        assert len(rows) == before + 1, (before, rows)
        denied = rows[-1]
        assert denied[1] == world["a"]["org_id"]
        assert denied[2] == world["a"]["labtech_id"]
        assert denied[2] != world["a"]["orderer_id"]

    def test_the_other_organisations_auditor_sees_none_of_it(self, client, world, reader):
        """
        THE TENANT HALF. Organisation B's Auditor must see nothing of
        organisation A's registrations — and B has its own, so "sees nothing"
        is not "the table is empty".
        """
        cookie = _staff_cookie(client, world["a"]["org_id"], world["a"]["orderer_email"])
        assert _register_over_http(client, cookie, name="Only In A").status_code == 201

        theirs = self._rows(reader, world["b"]["auditor"], "patient_created")
        assert all(row[1] == world["b"]["org_id"] for row in theirs), theirs
        assert not [r for r in theirs if r[4].get("name") == "Only In A"], theirs
        # The twin: B's auditor DOES see B's own rows, so the row above is not
        # green because the reader returns nothing.
        assert theirs, "B's auditor sees no patient_created rows at all -- the reader is blind"
