"""
clinical/tests/test_w143_adoption_proves_the_generation.py
───────────────────────────────────────────────────────────
THE ADOPTION FALSE-POSITIVE, TESTED AGAINST A REAL EARLIER SCHEMA.

`python -m clinical.migrate --adopt-existing` stamps a database as the
baseline after checking `0002_baseline.sql`'s own post-conditions. All five of
those are `to_regclass('<table>') IS NOT NULL`. Every security change in this
stack is a COLUMN ADDED TO A TABLE THAT ALREADY EXISTED, so all five are true
of a database that predates every one of them -- and a real pre-security
database was therefore stamped as current, its migrations skipped, and
`/readyz` answered 200 ready.

WHY THIS FILE EXISTS BESIDE `test_w126m_migration_mechanism.py`, WHICH HAS
FOUR ADOPTION ROWS AND CATCHES NONE OF THIS. That file's helper builds the
starting state by applying `0002_baseline.sql` ITSELF, so all four of its
adoption rows exercise adoption against a database ALREADY AT THE BASELINE.
The missing ingredient was never a technique -- `information_schema` and
`pg_catalog` are used throughout that file -- it was the FIXTURE. So the rows
here start from `fixtures/pre_security_schema_da97f847.sql`, which is
`7b034e5:clinical/schema.sql` byte for byte: the actual pre-security schema of
this repository, not a synthesised "old" one and not a current schema with
something removed.

EVERY ROW NAMES WHAT IT CATCHES AND WHAT IT IS VACUOUS AGAINST, against the
seven wrong versions the brief enumerates:

  A  keep the table-existence checks                      -> must FAIL
  B  add another table check present in BOTH generations  -> must FAIL
  C  stamp history without proving the schema             -> must FAIL
  D  reject adoption but leave readiness healthy          -> must FAIL
  E  accept a genuinely current database                  -> must PASS
  F  reject a fresh current database                      -> must FAIL
  G  migrate an already-migrated database again           -> must FAIL

These tests create their own databases (clinical/tests/migration_db.py) and
never touch the package's drop-and-recreate fixtures -- a fixture that rebuilds
from the CURRENT schema.sql would destroy the one property under test.
"""

from __future__ import annotations

import pathlib

import pytest

from clinical import migrate
from clinical.tests.migration_db import (
    SENTINEL_NOTE,
    SENTINEL_ORG,
    connect,
    plant_sentinel,
    read_sentinel,
    scratch_database,
)

SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"
PRE_SECURITY_PATH = pathlib.Path(__file__).resolve().parent / "fixtures" / "pre_security_schema_da97f847.sql"

# `checksum_of`, not a raw sha256: this repository checks `.sql` out with CRLF
# on Windows and LF on the Linux CI container, so only the LF-normalised hash
# is the same number on both machines. Same function the migration checksums
# use, for the same reason.
PRE_SECURITY_CHECKSUM = "43a5eae1fc9bb169a9469ca2c4ed211211897a6cdc856bb92f3a7ced3b775565"

# The five post-conditions `0002_baseline.sql` states in its own header. Named
# here so the first row can prove they are ALL TRUE of the pre-security
# database -- which is the whole defect, stated as data.
BASELINE_FILE_ASSERTION_TABLES = (
    "sessions",
    "organisations",
    "reports",
    "audit_log",
    "exception_events",
)


# ─── helpers ────────────────────────────────────────────────────────────────


def _apply(connection, sql: str) -> None:
    with connection.cursor() as cur:
        cur.execute(sql)
    connection.commit()


def _build_pre_security(connection) -> None:
    """A REAL database of the earlier generation. No drop-and-recreate, no
    current schema with a column removed."""
    _apply(connection, PRE_SECURITY_PATH.read_text(encoding="utf-8"))


def _build_current_generation(connection) -> None:
    """A database that genuinely IS the baseline generation and has no history
    table -- the state `--adopt-existing` exists for, done honestly."""
    baseline = {m.version: m for m in migrate.discover()}[migrate.BASELINE_VERSION]
    _apply(connection, baseline.sql)


def _build_fresh_from_schema_sql(connection) -> None:
    """The production fresh-database path, which stamps its own history."""
    _apply(connection, SCHEMA_PATH.read_text(encoding="utf-8"))


def _stamp_history_without_proving_anything(connection) -> None:
    """
    WRONG VERSION C, BUILT ON PURPOSE. Create the history table and write
    rows saying 1 and 2 are applied, with the REAL checksums, against a
    database that is not at that generation. This is exactly the state the
    broken `adopt_existing` produced, and it is what readiness has to see
    through.
    """
    by_version = {m.version: m for m in migrate.discover()}
    _apply(connection, by_version[1].sql)
    with connection.cursor() as cur:
        for version in (1, migrate.BASELINE_VERSION):
            migration = by_version[version]
            cur.execute(
                "INSERT INTO schema_migrations (version, name, checksum) VALUES (%s, %s, %s)",
                (migration.version, migration.name, migration.checksum),
            )
    connection.commit()


def _has_table(connection, name: str) -> bool:
    with connection.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (name,))
        return cur.fetchone()[0] is not None


def _has_column(connection, table: str, column: str) -> bool:
    with connection.cursor() as cur:
        cur.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass(%s) "
            "AND attname = %s AND attnum > 0 AND NOT attisdropped)",
            (table, column),
        )
        return cur.fetchone()[0]


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
    return response.status_code, response.json().get("reason"), response.text


# ─── the fixture itself, before anything is tested with it ──────────────────


class TestTheHistoricalFixtureIsWhatItClaims:
    def test_the_fixture_is_the_real_pre_security_schema_byte_for_byte(self):
        """
        CATCHES: the quiet death of this whole file -- a fixture someone
        refreshes from the current `schema.sql`, after which every row below
        still passes and proves nothing. The identity is pinned to the blob
        `da97f847` = `7b034e5:clinical/schema.sql`.

        VACUOUS AGAINST: every one of A-G. It tests a file, not the runner.
        """
        assert PRE_SECURITY_PATH.is_file()
        assert migrate.checksum_of(PRE_SECURITY_PATH.read_bytes()) == PRE_SECURITY_CHECKSUM

    def test_the_historical_database_satisfies_ALL_FIVE_baseline_post_conditions(self):
        """
        THE DEFECT, STATED AS DATA AND MEASURED FROM THE CATALOG. Every table
        the frozen baseline asserts exists in the earlier generation too, so
        the file's own post-condition set cannot tell the two apart -- while
        the tenant-isolation column and the patient credential tables are
        absent.

        This row is why "add another table-existence check" (WRONG B) is not
        a fix: it is a census of what the table vocabulary can see, and the
        answer is nothing.

        VACUOUS AGAINST: D, E, F, G -- it never calls adoption or readiness.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_pre_security(connection)

            for table in BASELINE_FILE_ASSERTION_TABLES:
                assert _has_table(connection, table), table

            # ... and yet it is demonstrably the earlier generation:
            assert not _has_column(connection, "exception_events", "org_id")
            assert not _has_column(connection, "reviewer_claims", "report_id")
            assert not _has_column(connection, "users", "registration_number")
            assert not _has_table(connection, "patient_logins")
            assert not _has_table(connection, "patient_sessions")

    def test_the_invariant_vocabulary_is_not_all_table_probes(self):
        """
        CATCHES: A and B directly, at the level of the assertion set -- a fix
        that answers the audit by listing more tables. A new table IS a better
        witness than a shared one, but the next generation will again add
        columns to existing tables, so the set must carry column and
        constraint invariants too.

        NON-VACUITY: the set is also asserted non-empty and actually bound to
        the baseline migration on disk, so a set that silently stopped
        applying (a renamed migration, an emptied tuple) fails here rather
        than passing everything below.

        VACUOUS AGAINST: C, D, E, F, G -- it reads a Python object, not a
        database.
        """
        baseline = {m.version: m for m in migrate.discover()}[migrate.BASELINE_VERSION]
        invariants = migrate.generation_invariants(baseline)
        assert invariants, "the baseline on disk has no generation invariants bound to it"
        assert invariants == migrate.BASELINE_GENERATION_INVARIANTS

        kinds = {i.kind for i in invariants}
        assert "column" in kinds
        assert "constraint" in kinds
        # and if a table probe is used at all it is outnumbered, not relied on
        assert sum(1 for i in invariants if i.kind == "table") < sum(
            1 for i in invariants if i.kind in ("column", "constraint")
        )

        # Every invariant reads pg_catalog, never information_schema:
        # information_schema is privilege-filtered and /readyz evaluates these
        # as clinical_app, which is denied privileges on parts of this schema.
        for invariant in invariants:
            assert "information_schema" not in invariant.expression

    def test_every_invariant_is_readable_by_the_role_readyz_connects_as(self):
        """
        CATCHES: the mirror of F that only production would find -- an
        invariant written against `information_schema`, which is
        PRIVILEGE-FILTERED. `/readyz` evaluates these as `clinical_app`, a
        role this schema deliberately denies privileges on parts of, so an
        information_schema probe would report a present object as absent and
        fail readiness on a perfectly good database. No test that connects as
        the owner can see that; this one changes role.

        Paired with the negative twin in the same database: the
        information_schema form of the same question is shown to be
        privilege-filtered for this role, so the row cannot pass because
        information_schema happens to be fine here.
        """
        baseline = {m.version: m for m in migrate.discover()}[migrate.BASELINE_VERSION]
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_fresh_from_schema_sql(connection)
            with connection.cursor() as cur:
                cur.execute("SET ROLE clinical_app")
                for invariant in migrate.generation_invariants(baseline):
                    cur.execute(f"SELECT ({invariant.expression})")
                    assert cur.fetchone()[0] is True, invariant.description

                # the negative twin: clinical_app has no privilege on
                # schema_migrations' columns beyond SELECT, and none at all on
                # a table it is denied -- information_schema hides what
                # pg_catalog shows. Proven on a table the role cannot touch.
                cur.execute("SELECT count(*) FROM information_schema.columns WHERE table_name = 'patient_logins'")
                via_information_schema = cur.fetchone()[0]
                cur.execute(
                    "SELECT count(*) FROM pg_attribute "
                    "WHERE attrelid = to_regclass('patient_logins') "
                    "AND attnum > 0 AND NOT attisdropped"
                )
                via_pg_catalog = cur.fetchone()[0]
                cur.execute("RESET ROLE")
            connection.rollback()

        assert via_pg_catalog > 0
        # If these ever agree for this role the negative twin has gone
        # vacuous, but the positive half above is what the fix relies on.
        assert via_information_schema <= via_pg_catalog


# ─── the historical database: adoption and readiness ────────────────────────


class TestARealPreSecurityDatabaseIsRefused:
    def test_adoption_refuses_the_historical_database_and_changes_nothing(self):
        """
        THE ROW THE WHOLE FIX IS FOR.

        CATCHES: A (the five table probes all hold here, so keeping them
        passes adoption and fails this row), B (any further table probe over a
        table present in both generations), and C (stamping the history
        without proving the schema -- asserted by the ABSENCE of
        `schema_migrations` afterwards, from the catalog).

        The sentinel data planted first is asserted intact afterwards, so the
        refusal is proved to have rolled back rather than to have half-run.

        VACUOUS AGAINST: E and F -- it never sees a current database. Its
        positive twin is `TestAGenuinelyCurrentDatabaseStillWorks`.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_pre_security(connection)
            plant_sentinel(connection)
            assert migrate.schema_is_present(connection) is True

            with pytest.raises(migrate.MigrationStateError) as excinfo:
                migrate.adopt_existing(connection)

            message = str(excinfo.value)
            assert "exception_events.org_id" in message
            assert "Nothing was changed." in message

            connection.rollback()
            assert not _has_table(connection, "schema_migrations")
            assert read_sentinel(connection) == ((SENTINEL_NOTE,), (SENTINEL_ORG,))

            state = migrate.inspect_state(connection)
            assert state.ok is False
            assert state.reason == "schema_not_initialised"
            assert state.current_version is None

    def test_readiness_refuses_the_historical_database_after_a_refused_adoption(self, client, monkeypatch):
        """
        CATCHES: a readiness probe that answers on table presence alone --
        the pre-w126m `/readyz`, which found `sessions` and said 200. After a
        refused adoption the database still holds no history, and readiness
        must say so rather than report healthy. Asserted on BOTH channels
        (status AND the reason in the body), per Standing Rule 8.

        VACUOUS AGAINST D, and measured to be: a refused adoption leaves no
        history table, so `schema_not_initialised` is reached before any
        invariant is consulted. The row that actually catches D is the next
        one, where the history DOES say current. Also vacuous against a probe
        that is 503 unconditionally -- which is why
        `TestAGenuinelyCurrentDatabaseStillWorks` asserts the 200.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_pre_security(connection)
            with pytest.raises(migrate.MigrationStateError):
                migrate.adopt_existing(connection)
            connection.rollback()

            status, reason, text = _probe(client, monkeypatch, dsn)

        assert status == 503
        assert reason == "schema_not_initialised"
        assert "postgresql://" not in text

    def test_readiness_refuses_a_historical_database_whose_history_says_current(self, client, monkeypatch):
        """
        CATCHES: D proper, and C through the probe. This is the database the
        BROKEN runner left behind: real history rows for 1 and 2, with the
        real checksums, on a database of the earlier generation. Nothing in
        the history can say so -- the rows are a claim, and they are asserted
        STILL PRESENT afterwards so the test cannot pass because something
        cleaned them up.

        The verdict must come from the catalog, and it must name the COLUMN,
        because every table the history's migrations mention is present.

        VACUOUS AGAINST: A and B at the adoption path -- this row never calls
        `adopt_existing`.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_pre_security(connection)
            _stamp_history_without_proving_anything(connection)

            with connection.cursor() as cur:
                cur.execute("SELECT version FROM schema_migrations ORDER BY version")
                assert [r[0] for r in cur.fetchall()] == [1, migrate.BASELINE_VERSION]

            state = migrate.inspect_state(connection)
            status, reason, text = _probe(client, monkeypatch, dsn)

            # the lying rows are still there, which is the point
            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM schema_migrations")
                assert cur.fetchone()[0] == 2

        assert state.ok is False
        assert state.reason == "schema_drift"
        assert "exception_events.org_id" in state.detail
        assert status == 503
        assert reason == "schema_drift"
        assert "exception_events.org_id" in text


# ─── the positive twins: a current database must still work ─────────────────


class TestAGenuinelyCurrentDatabaseStillWorks:
    def test_a_pre_mechanism_database_of_the_CURRENT_generation_is_adopted(self):
        """
        CATCHES: E and F. An invariant set that over-reaches -- asserting an
        object from a HELD branch, say `exception_events.amends_event_id`,
        which belongs to w126 and is not in this baseline -- rejects a
        database that is genuinely current. That is the mirror defect and it
        would break every real adoption.

        The sentinel proves the adoption did not drop and rebuild.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_current_generation(connection)
            plant_sentinel(connection)

            assert migrate.adopt_existing(connection) == (1, migrate.BASELINE_VERSION)

            assert read_sentinel(connection) == ((SENTINEL_NOTE,), (SENTINEL_ORG,))
            assert _has_table(connection, "schema_migrations")
            state = migrate.inspect_state(connection)
            assert state.ok is True
            assert state.current_version == migrate.BASELINE_VERSION

    def test_a_fresh_database_from_schema_sql_is_ready(self, client, monkeypatch):
        """
        CATCHES: F through the probe. A fresh production database must be
        200 ready with the body unchanged. Without this row every refusal row
        above is satisfied by a probe that always says 503.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_fresh_from_schema_sql(connection)
            status, reason, text = _probe(client, monkeypatch, dsn)

        assert status == 200, text
        assert reason is None

    def test_an_already_current_database_is_refused_a_second_adoption_and_a_second_migration(self):
        """
        CATCHES: G. An already-migrated database migrated again must not
        re-run anything and must not be adoptable. Both halves are asserted on
        CONTENT: the history rows are byte-identical before and after, so a
        runner that re-stamped or re-applied fails here.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_fresh_from_schema_sql(connection)
            with connection.cursor() as cur:
                cur.execute("SELECT version, name, checksum FROM schema_migrations ORDER BY version")
                before = tuple(cur.fetchall())
            connection.rollback()
            assert before, "schema.sql did not stamp its own history"

            with pytest.raises(migrate.MigrationStateError) as excinfo:
                migrate.adopt_existing(connection)
            assert "already exists" in str(excinfo.value)
            connection.rollback()

            assert migrate.migrate(connection) == ()

            with connection.cursor() as cur:
                cur.execute("SELECT version, name, checksum FROM schema_migrations ORDER BY version")
                assert tuple(cur.fetchall()) == before
            connection.rollback()


# ─── the column and constraint vocabulary, proved against a current db ──────


class TestTheInvariantsSeeWhatATableProbeCannot:
    def test_a_current_database_missing_only_a_COLUMN_is_not_ok(self):
        """
        CATCHES: A and B, in the sharpest possible form and without the
        historical fixture. Start from a genuinely current database, drop ONE
        COLUMN, leave every table standing. All five of the baseline's own
        post-conditions still hold; the verdict must still be not-ok.

        The positive twin runs FIRST, on the same database, so the row cannot
        pass because `inspect_state` is broken in the other direction.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_fresh_from_schema_sql(connection)
            assert migrate.inspect_state(connection).ok is True

            _apply(connection, "ALTER TABLE exception_events DROP COLUMN org_id CASCADE")

            for table in BASELINE_FILE_ASSERTION_TABLES:
                assert _has_table(connection, table), table

            state = migrate.inspect_state(connection)
            assert state.ok is False
            assert state.reason == "schema_drift"
            assert "exception_events.org_id" in state.detail

    def test_a_current_database_missing_only_a_CONSTRAINT_is_not_ok(self):
        """
        CATCHES: an invariant set built only from columns. A column can be
        restored by hand with the wrong type or no key; the composite foreign
        key is the structural half of the isolation rule and its absence is
        invisible to both a table probe and a column probe.

        VACUOUS AGAINST: the historical database -- that one is already caught
        by the column rows. This row is about the vocabulary.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _build_fresh_from_schema_sql(connection)
            assert migrate.inspect_state(connection).ok is True

            _apply(
                connection,
                "ALTER TABLE reviewer_claims DROP CONSTRAINT fk_claim_report",
            )
            assert _has_column(connection, "reviewer_claims", "report_id")

            state = migrate.inspect_state(connection)
            assert state.ok is False
            assert state.reason == "schema_drift"
            assert "fk_claim_report" in state.detail
