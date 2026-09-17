"""
clinical/tests/test_w132_structural_guards.py
──────────────────────────────────────────────
w132 — the guards that keep the shape after the wave is forgotten. Tests
only; no production code depends on this file.

Each row here catches a change that is ONE LINE, looks like an improvement,
and that no behavioural test in this repository would fail on:

  * a second route setting its own cookie, with its own flags;
  * a CORS middleware added "so the portal can call the API";
  * a route mounted that nobody counted (Standing Rule 9 — and see
    `TestTheRouteCensus` for why `app.routes` is not the naive answer it
    looks like on this version of FastAPI);
  * `ConfigurationError` dropped from the login handler's except clause,
    which reopens the MFA status oracle the moment somebody also tidies away
    the broad backstop underneath it.
"""

from __future__ import annotations

import ast
import pathlib

CLINICAL = pathlib.Path(__file__).resolve().parent.parent
TREE = CLINICAL.parent


def _python_files():
    return [path for path in TREE.rglob("*.py") if "__pycache__" not in path.parts and ".git" not in path.parts]


def _calls_named(path, attribute):
    """Actual CALLS of `x.<attribute>(...)`, read from the AST.

    Not a substring search, and this file is the reason the distinction is
    written down: `auth_endpoints.py`'s own docstring contains the words
    `set_cookie` and `_create_system_session`, so a grep-shaped guard reports
    the prose as a call and fails green.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return 0
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == attribute
    )


class TestCookiePolicyLivesInExactlyOneModule:
    """
    Before w132, `set_cookie` occurred ZERO times in this repository. The
    failure this guard catches is the natural next one: a later route setting
    its own cookie, with its own flags, in its own file — so that "the cookie
    policy" becomes two policies and the weaker one is the one nobody reads.
    """

    def test_only_the_auth_module_sets_a_cookie(self):
        setters = {
            path.relative_to(TREE).as_posix(): _calls_named(path, "set_cookie")
            for path in _python_files()
            if _calls_named(path, "set_cookie")
        }
        assert set(setters) == {"clinical/auth_endpoints.py"}, setters

    def test_the_twin_the_matcher_finds_the_calls_that_exist(self):
        """
        Standing Rule 4: without this, the row above is satisfied by a matcher
        that finds nothing anywhere — which is exactly what a grep for the
        wrong symbol does.
        """
        assert _calls_named(CLINICAL / "auth_endpoints.py", "set_cookie") >= 1

    def test_the_cookie_helper_is_the_only_caller_inside_that_module(self):
        """One module is not enough if the module itself has two policies:
        both routes must go through `_set_session_cookie`."""
        tree = ast.parse((CLINICAL / "auth_endpoints.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            direct = [
                call
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "set_cookie"
            ]
            if direct:
                assert node.name == "_set_session_cookie", (
                    f"{node.name} sets a cookie directly instead of going through "
                    "_set_session_cookie -- that is how two cookie policies begin"
                )


class TestThePerimeterIsStillEmpty:
    """
    The honest negative form of w131's X1. The clinical app adds NO
    middleware, and the reason is recorded in `app.py`: a fail-open layer
    above a fail-closed one only creates a configuration in which the outer
    check is off and looks on.

    The specific thing not to copy is `geper/api/main.py`'s CORS, which
    defaults to `allow_origins=["*"]` with `allow_credentials=True`. This
    guard means adding CORS to a service holding patient data is a deliberate,
    reviewed act rather than a silent widening.
    """

    def test_the_clinical_app_adds_no_middleware(self):
        from clinical.app import app

        assert app.user_middleware == [], app.user_middleware

    def test_the_twin_the_check_detects_one_that_is_added(self):
        """
        Standing Rule 4. `user_middleware` could be the wrong attribute on a
        future Starlette and would then be empty forever. A middleware is
        added to a THROWAWAY app and the same check must see it.
        """
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware

        probe = FastAPI()
        assert probe.user_middleware == []
        probe.add_middleware(CORSMiddleware, allow_origins=["*"])
        assert probe.user_middleware != [], (
            "the check cannot see a middleware that was added, so the row above proves nothing"
        )

    def test_no_cors_import_reaches_the_clinical_package(self):
        for path in CLINICAL.rglob("*.py"):
            if "__pycache__" in path.parts or path.parts[-2:-1] == ("tests",):
                continue
            source = path.read_text(encoding="utf-8")
            assert "CORSMiddleware" not in source, path


def served_routes(app):
    """
    EVERY (path, methods) the app actually serves.

    STANDING RULE 9, AND A CORRECTION TO THE OBVIOUS READING OF IT. "Enumerate
    `app.routes`" is right in intent and NOT sufficient as written on this
    version of FastAPI (0.141.1 / starlette 1.6.0): `include_router` leaves an
    `_IncludedRouter` WRAPPER in `app.routes` rather than flattening the
    router's routes into it. Iterating `app.routes` on this app returns FIVE
    objects — three opaque wrappers, `/healthz` and `/readyz` — so a census
    written the obvious way sees neither `/portal/me` nor `/auth/login` and
    reports a surface of two.

    That is the same defect as counting `@router.` decorators, one layer
    along: a census that cannot see what the framework did.
    """
    found = []
    for route in app.routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            found.extend(served_routes_of(inner))
        else:
            found.append((getattr(route, "path", None), tuple(sorted(getattr(route, "methods", None) or []))))
    return sorted(set(found))


def served_routes_of(router):
    found = []
    for route in getattr(router, "routes", []):
        inner = getattr(route, "original_router", None)
        if inner is not None:
            found.extend(served_routes_of(inner))
        else:
            found.append((getattr(route, "path", None), tuple(sorted(getattr(route, "methods", None) or []))))
    return found


class TestTheRouteCensus:
    """
    The row that would have caught the eight invisible documentation routes,
    and that now also catches the two this wave added had nobody declared
    them. Standing Rule 3 in test form: the definite article is a tell, and a
    census needs counting.
    """

    EXPECTED = sorted(
        {
            ("/healthz", ("GET",)),
            ("/readyz", ("GET",)),
            ("/exceptions/orders/{order_id}", ("GET",)),
            ("/exceptions/worklist", ("GET",)),
            ("/exceptions/{exception_id}", ("PATCH",)),
            ("/portal/me", ("GET",)),
            ("/portal/me/tests", ("GET",)),
            ("/auth/login", ("POST",)),
            ("/portal/login", ("POST",)),
        }
    )

    def test_the_served_surface_matches_the_declared_list_exactly(self):
        from clinical.app import app

        assert served_routes(app) == self.EXPECTED

    def test_the_walker_is_not_returning_an_empty_or_wrapper_shaped_answer(self):
        """
        Standing Rule 4, and the specific hazard this file documents: a
        walker that failed to descend into `_IncludedRouter` returns five
        entries, three of them `(None, ())`. Both shapes are refused here.
        """
        from clinical.app import app

        census = served_routes(app)
        assert len(census) == 9, census
        assert all(path and path.startswith("/") for path, _ in census), census
        assert all(methods for _, methods in census), census

    def test_the_documentation_routes_are_not_among_them(self):
        from clinical.app import app

        paths = {path for path, _ in served_routes(app)}
        assert paths.isdisjoint({"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}), paths


class TestTheRefusalStaysUniform:
    def test_the_login_handlers_name_ConfigurationError_in_their_except_clause(self):
        """
        RECORDED BECAUSE THE BEHAVIOURAL TEST CANNOT SEE IT, and this was
        measured rather than assumed: removing `ConfigurationError` from
        `_refuse_uniformly`'s except tuple leaves every MFA row in
        `test_w132_staff_login_route.py` GREEN, because the broad `Exception`
        backstop underneath catches it anyway.

        That is fine today and it is one tidy-up away from not being fine: a
        later reviewer who removes the broad catch — a reasonable thing to
        want — would silently restore the 500-vs-401 oracle on MFA-enrolled
        accounts. So the named clause is pinned here in addition to the
        behaviour.
        """
        tree = ast.parse((CLINICAL / "auth_endpoints.py").read_text(encoding="utf-8"))
        named = set()
        for handler in ast.walk(tree):
            if not isinstance(handler, ast.ExceptHandler) or handler.type is None:
                continue
            types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
            named.update(node.id for node in types if isinstance(node, ast.Name))

        assert "ConfigurationError" in named, named
        assert "AuthenticationError" in named, named

    def test_the_anonymous_refusal_is_one_function_and_the_auth_module_uses_it(self):
        """A second hand-written `HTTPException(401, ...)` in the auth module
        is how two refusals that differ by a byte begin."""
        source = (CLINICAL / "auth_endpoints.py").read_text(encoding="utf-8")
        assert "_anonymous_refusal" in source
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "HTTPException":
                keywords = {kw.arg: kw for kw in node.keywords}
                status_arg = keywords.get("status_code")
                rendered = ast.unparse(status_arg.value) if status_arg else ""
                assert "401" not in rendered and "UNAUTHORIZED" not in rendered, (
                    "the auth module builds its own 401 instead of using _anonymous_refusal"
                )


class TestTheStaffDependencyWasStillNotWidened:
    """
    The w130 guards, extended to the module this wave added. `_get_session`
    must still be a staff-only dependency, and the new module must not have
    handed a `PatientSession` to it.
    """

    def test_get_session_still_validates_a_staff_session_only(self):
        source = (CLINICAL / "endpoints.py").read_text(encoding="utf-8")
        body = source[source.index("def _get_session(") :]
        body = body[: body.index("\n@router.")]
        assert "dao.session_valid(" in body
        assert "patient_session_valid" not in body
        assert "PatientSession" not in body

    def test_the_auth_module_does_not_import_either_session_dependency(self):
        """
        It has no business validating a session: it MINTS credentials, it does
        not accept them. Importing `_get_session` here would be the first step
        towards a login route that takes a session.
        """
        source = (CLINICAL / "auth_endpoints.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.update(alias.name for alias in node.names)
        assert "_get_session" not in imported, imported
        assert "_get_patient_session" not in imported, imported

    def test_the_twin_the_import_walker_sees_the_imports_that_are_there(self):
        tree = ast.parse((CLINICAL / "auth_endpoints.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.update(alias.name for alias in node.names)
        assert {"_get_data_access", "_anonymous_refusal", "_SESSION_COOKIE"} <= imported, imported
