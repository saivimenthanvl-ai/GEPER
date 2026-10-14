"""
clinical/tests/test_w132_docs_surface.py
─────────────────────────────────────────
w132 fix A — THE ANONYMOUS DOCUMENTATION SURFACE.

THE DEFECT: `FastAPI()` mounts `/openapi.json`, `/docs`,
`/docs/oauth2-redirect` and `/redoc` unless told otherwise. Nobody in this
repository declared them, so nobody decided they were public — and a
`@router.` grep cannot see them, which is why three audits counted ten routes
on a service that served eighteen (Standing Rule 9).

WHAT AN ANONYMOUS CALLER GOT FROM ONE REQUEST TO `/openapi.json`: every path,
every method, every response model field by field — `PortalPatientResponse`
is `patient_id`, `name`, `dob`, `sex` — every declared status code, and every
handler docstring.

THE TWIN IS REQUIRED, NOT OPTIONAL. "The docs 404" is satisfied by an app
that failed to start, by a typo in the path, and by a router that never
mounted. So every negative row here is paired with the same request against
an app built with the flag set, which must return 200 AND name a real route.
That pair is the only thing that distinguishes "unmounted on purpose" from
"broken".
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

_CLINICAL_APP_PATH = pathlib.Path(__file__).resolve().parent.parent / "app.py"
_GEPER_API_MAIN_PATH = pathlib.Path(__file__).resolve().parent.parent.parent / "geper" / "api" / "main.py"

# The four routes FastAPI mounts by default and nobody declared.
_DOC_PATHS = ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc")


def _load_app(module_name: str, path: pathlib.Path):
    """
    Build a FRESH application object from the module source.

    Not `importlib.reload(clinical.app)`: that rebinds `sys.modules` under
    every other test in the session. This executes the module under a private
    name, so the flag's effect is observed on a throwaway app and the real one
    is untouched.
    """
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


@pytest.fixture()
def clinical_app_docs_off(monkeypatch):
    monkeypatch.delenv("CLINICAL_ENABLE_DOCS", raising=False)
    return _load_app("_w132_clinical_app_docs_off", _CLINICAL_APP_PATH)


@pytest.fixture()
def clinical_app_docs_on(monkeypatch):
    monkeypatch.setenv("CLINICAL_ENABLE_DOCS", "1")
    return _load_app("_w132_clinical_app_docs_on", _CLINICAL_APP_PATH)


def _client(app):
    from fastapi.testclient import TestClient

    return TestClient(app)


class TestTheClinicalDocumentationIsNotAnonymouslyServed:
    def test_all_four_default_documentation_routes_are_unmounted(self, clinical_app_docs_off):
        client = _client(clinical_app_docs_off)
        statuses = {path: client.get(path).status_code for path in _DOC_PATHS}
        assert set(statuses.values()) == {404}, statuses

    def test_the_route_map_and_the_model_fields_are_not_obtainable(self, clinical_app_docs_off):
        """
        Not "the /docs page is gone" — `/openapi.json` is the one that carries
        the schemas, and it is a different route. Asserted on the BODY: a 404
        page must not contain a path, a model name or a field name.
        """
        client = _client(clinical_app_docs_off)
        body = client.get("/openapi.json").text
        for leak in ("/portal/me", "/exceptions/worklist", "PortalPatientResponse", "dob"):
            assert leak not in body, f"the anonymous openapi response still names {leak!r}"

    def test_the_documentation_routes_are_absent_from_app_routes(self, clinical_app_docs_off):
        """
        Standing Rule 9: enumerate what the app SERVES. A 404 could also come
        from a route that is mounted and refuses; this reads the route table.
        """
        served = {getattr(route, "path", None) for route in clinical_app_docs_off.routes}
        assert served.isdisjoint(set(_DOC_PATHS)), sorted(p for p in served if p in _DOC_PATHS)


class TestTheRequiredTwin:
    """
    Standing Rule 4. Without these rows the class above passes against an app
    that fails to start, and against a `_DOC_PATHS` tuple full of typos.
    """

    def test_the_flag_remounts_all_four(self, clinical_app_docs_on):
        client = _client(clinical_app_docs_on)
        statuses = {path: client.get(path).status_code for path in _DOC_PATHS}
        assert set(statuses.values()) == {200}, statuses

    def test_the_enabled_schema_still_names_the_real_routes_and_models(self, clinical_app_docs_on):
        """
        Proves the paths in `_DOC_PATHS` are the real ones AND that the
        docstrings and response models were kept in the code rather than
        deleted — the ruling said the documentation stays, only the anonymous
        surface goes.
        """
        spec = _client(clinical_app_docs_on).get("/openapi.json").json()
        assert "/portal/me" in spec["paths"]
        assert "/exceptions/worklist" in spec["paths"]
        assert "PortalPatientResponse" in spec["components"]["schemas"]
        assert "dob" in spec["components"]["schemas"]["PortalPatientResponse"]["properties"]


class TestNothingRealWasUnmounted:
    def test_the_health_probe_still_answers(self, clinical_app_docs_off):
        response = _client(clinical_app_docs_off).get("/healthz")
        assert response.status_code == 200, response.text
        assert response.json() == {"status": "alive"}

    def test_the_five_hand_written_authenticated_routes_are_still_mounted(self, clinical_app_docs_off):
        """
        A mounted route that needs a session 401s; an unmounted one 404s. The
        401 is therefore the proof of the mount, and it is what separates
        "the docs were unmounted" from "the routers were".
        """
        client = _client(clinical_app_docs_off)
        observed = {
            "/exceptions/worklist": client.get("/exceptions/worklist").status_code,
            "/exceptions/orders/{id}": client.get(
                "/exceptions/orders/00000000-0000-0000-0000-000000000000"
            ).status_code,
            "PATCH /exceptions/{id}": client.patch(
                "/exceptions/00000000-0000-0000-0000-000000000000",
                json={"resolution_action": "retry_check", "resolution_note": "x"},
            ).status_code,
            "/portal/me": client.get("/portal/me").status_code,
            "/portal/me/tests": client.get("/portal/me/tests").status_code,
        }
        assert set(observed.values()) == {401}, observed


class TestTheGeperApiMadeTheSameDecision:
    """
    The audit asked for a decision on `geper/api`, which had the identical
    default. It gets the identical gate — one house rule, two apps.

    The BEHAVIOURAL half of that decision is pinned in
    `geper/api/tests/test_w132_docs_surface.py`, because `geper/api/main.py`
    imports `component_identity` and `.submission_store` and is only
    importable with that package's rootdir on the path. What is asserted here
    is the SOURCE, so the clinical suite fails if the two apps drift apart.
    """

    def test_the_geper_api_gates_all_three_documentation_urls(self):
        source = _GEPER_API_MAIN_PATH.read_text(encoding="utf-8")
        head = source[source.index("app = FastAPI(") :]
        head = head[: head.index(")\n")]
        for kwarg in ("docs_url=", "redoc_url=", "openapi_url="):
            assert kwarg in head, f"geper/api/main.py's FastAPI() does not pass {kwarg}"
        assert "GEPER_ENABLE_DOCS" in source
