"""
clinical/tests/test_w126m_readiness_reports_schema_state.py
───────────────────────────────────────────────────────────
WRONG H: A DATABASE THIS CODE CANNOT SERVE THAT REPORTS ITSELF READY.

`/readyz` probed `to_regclass('sessions')`, and `sessions` is a baseline table
that no schema change on this floor touches -- so it exists in every variant
of this schema there has ever been. The probe therefore answered 200 for every
wrong pairing of code and database, Docker's HEALTHCHECK passed, an
orchestrator sent traffic, and the first request that named a missing column
was a 500. The probe detected ABSENCE and called it VERSION.

THE ROWS BELOW NEVER ASSERT ON THE STATUS ALONE. A 503 is satisfied by a
database that is merely down, which is a different action for an operator
(wait, versus deploy the migration). STANDING RULE 8: a complete refusal test
asserts both channels, so every row here asserts the status AND the `reason`
the body names -- and asserts the reasons are DISTINCT across the cases, so a
probe that collapsed them all into one word would fail.

AND THE READY CASE IS ASSERTED TOO. Without it every row here passes against a
probe that returns 503 unconditionally, which is the false RED this endpoint's
own Dockerfile comment warns about.

These tests use their own databases (clinical/tests/migration_db.py). They do
not use the package's drop-and-recreate fixtures, and they do not modify
`/readyz` behaviour for anything but migration state.
"""

from __future__ import annotations

import pathlib

import pytest

from clinical import migrate
from clinical.tests.migration_db import connect, scratch_database

SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"


@pytest.fixture()
def client():
    pytest.importorskip("fastapi", reason="fastapi not installed")
    pytest.importorskip("httpx", reason="httpx not installed (starlette TestClient requires it)")
    from fastapi.testclient import TestClient

    from clinical.app import app

    with TestClient(app) as test_client:
        yield test_client


def _probe(client, monkeypatch, dsn):
    monkeypatch.setenv("CLINICAL_DSN", dsn)
    response = client.get("/readyz")
    body = response.json()
    return response.status_code, body.get("reason"), response.text


def _build_from_schema_sql(connection) -> None:
    with connection.cursor() as cur:
        cur.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
    connection.commit()


def _build_pre_mechanism(connection) -> None:
    baseline = {m.version: m for m in migrate.discover()}[migrate.BASELINE_VERSION]
    with connection.cursor() as cur:
        cur.execute(baseline.sql)
    connection.commit()


class TestReadinessConsultsMigrationState:
    def test_a_database_at_the_current_version_is_ready(self, client, monkeypatch):
        """
        THE POSITIVE CONTROL, first, because every other row here is a
        refusal. Built the production way -- clinical/schema.sql, whole -- and
        the ready body is asserted in full, so this wave adding a field to it
        would fail here rather than silently.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_from_schema_sql(connection)
            monkeypatch.setenv("CLINICAL_DSN", dsn)
            response = client.get("/readyz")
            assert response.status_code == 200, response.text
            assert response.json() == {"status": "ready", "database": "ok", "schema": "ok"}

    def test_a_database_that_predates_the_mechanism_is_not_ready(self, client, monkeypatch):
        """
        WRONG H, IN ITS EXACT SHAPE. This database HAS the sentinel table --
        the old probe's only question is answered yes -- and has never been
        migrated. The old probe answered 200 here. It must now answer 503 and
        say which way.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_pre_mechanism(connection)
            # the old probe's question, asked directly, so the row proves the
            # NEW check is what refuses and not the old one
            with connection.cursor() as cur:
                cur.execute("SELECT to_regclass('sessions')")
                assert cur.fetchone()[0] is not None

            status, reason, _ = _probe(client, monkeypatch, dsn)

        assert status == 503
        assert reason == "schema_not_initialised"

    def test_a_database_behind_the_code_is_not_ready(self, client, monkeypatch, tmp_path):
        """
        The other half of a version mismatch: a database that HAS a history
        and is one migration short of the code. Simulated the only honest way
        available -- by deleting the newest history row from a database that
        is otherwise current, which is exactly the state a deploy reaches when
        the code ships before the migration runs.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_from_schema_sql(connection)
            with connection.cursor() as cur:
                cur.execute("DELETE FROM schema_migrations WHERE version = %s", (migrate.BASELINE_VERSION,))
            connection.commit()

            status, reason, text = _probe(client, monkeypatch, dsn)

        assert status == 503
        assert reason == "schema_migrations_pending"
        assert str(migrate.BASELINE_VERSION) in text

    def test_a_database_whose_history_lies_is_not_ready(self, client, monkeypatch):
        """
        WRONG I, THROUGH THE PROBE. The history says migration 2 is applied.
        One of the tables migration 2 exists to create is gone. Nothing in the
        history can tell you that -- the row is a claim, and the claim is
        still there afterwards, which is asserted. The verdict has to come
        from the catalog, and this row is how `/readyz` proves that it does.

        The object dropped is `exception_events` rather than
        `schema_migrations`, because dropping the history table would take the
        claim down with it and leave nothing to catch lying.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_from_schema_sql(connection)
            with connection.cursor() as cur:
                cur.execute("DROP TABLE exception_events CASCADE")
            connection.commit()
            # the lying row is still there, which is the point
            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM schema_migrations WHERE version = 2")
                assert cur.fetchone()[0] == 1

            status, reason, text = _probe(client, monkeypatch, dsn)

        assert status == 503
        assert reason == "schema_drift"
        assert "exception_events" in text

    def test_the_four_refusals_are_told_apart(self, client, monkeypatch):
        """
        RULE 8 SHAPE, AS A SET. Four distinguishable states, four distinct
        reasons, all 503 -- asserted as a set of size four rather than one at
        a time, because a probe that collapsed two of them would pass every
        per-case assertion above and still leave an operator unable to act.

        `schema_missing` (server up, no schema) is included because it is the
        case the endpoint already had, and the point is that the NEW reasons
        did not swallow it.
        """
        reasons = set()

        with scratch_database() as dsn, connect(dsn) as connection:
            status, reason, _ = _probe(client, monkeypatch, dsn)
            assert status == 503
            reasons.add(reason)  # empty database -> schema_missing

        with scratch_database() as dsn, connect(dsn) as connection:
            _build_pre_mechanism(connection)
            status, reason, _ = _probe(client, monkeypatch, dsn)
            assert status == 503
            reasons.add(reason)  # -> schema_not_initialised

        with scratch_database() as dsn, connect(dsn) as connection:
            _build_from_schema_sql(connection)
            with connection.cursor() as cur:
                cur.execute("DELETE FROM schema_migrations WHERE version = 2")
            connection.commit()
            status, reason, _ = _probe(client, monkeypatch, dsn)
            assert status == 503
            reasons.add(reason)  # -> schema_migrations_pending

        with scratch_database() as dsn, connect(dsn) as connection:
            _build_from_schema_sql(connection)
            with connection.cursor() as cur:
                cur.execute("DROP TABLE exception_events CASCADE")
            connection.commit()
            status, reason, _ = _probe(client, monkeypatch, dsn)
            assert status == 503
            reasons.add(reason)  # -> schema_drift

        assert reasons == {
            "schema_missing",
            "schema_not_initialised",
            "schema_migrations_pending",
            "schema_drift",
        }

    def test_the_refusal_never_contains_the_dsn(self, client, monkeypatch):
        """The existing rule, re-checked on the NEW bodies: a DSN carries a
        password and these details are new text on an anonymous route."""
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_pre_mechanism(connection)
            _, _, text = _probe(client, monkeypatch, dsn)
        assert "postgresql://" not in text
        assert "password" not in text.lower()
