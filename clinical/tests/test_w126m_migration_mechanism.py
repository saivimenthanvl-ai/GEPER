"""
clinical/tests/test_w126m_migration_mechanism.py
────────────────────────────────────────────────
THE MECHANISM, TESTED AGAINST DATABASES RATHER THAN AGAINST ITSELF.

The hazard this file is written against is a specific one and it has a
precedent on this floor: in w133d a guard that COUNTED instead of JUDGING
passed twenty-one of twenty-one rows, because every row inspected the
machinery and none ran the verdict. The same hazard is here in a new shape --
**a row that reads a migration filename, or counts rows in schema_migrations,
proves nothing about the database.** So almost every row below finishes in
`information_schema` or `pg_catalog`, or in the content of a row that was
written before the operation under test.

Where a row IS about the machinery (filename parsing, the lock key), it says
so and it says what it is vacuous against.

NONE OF THESE TESTS USES THE PACKAGE'S DATABASE FIXTURES. They create their
own database per test and drop it afterwards -- see
`clinical/tests/migration_db.py` for why that is structural and not fastidious.
"""

from __future__ import annotations

import dataclasses
import pathlib

import pytest

from clinical import migrate
from clinical.tests import migration_db
from clinical.tests.migration_db import (
    SENTINEL_NOTE,
    SENTINEL_ORG,
    connect,
    plant_sentinel,
    read_sentinel,
    scratch_database,
)

SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"


# ─── helpers that build the three starting states ───────────────────────────


def _apply_sql(connection, sql: str) -> None:
    with connection.cursor() as cur:
        cur.execute(sql)
    connection.commit()


def _fresh_from_schema_sql(connection) -> None:
    """The PRODUCTION fresh-database path: clinical/schema.sql, whole, in one
    transaction -- the same thing `clinical.bootstrap.apply_schema` does."""
    _apply_sql(connection, SCHEMA_PATH.read_text(encoding="utf-8"))


def _pre_mechanism(connection) -> None:
    """
    A database at the BASELINE GENERATION with no history table.

    THE DOCSTRING HERE USED TO SAY "this is what every deployed clinical
    database is", AND THAT SENTENCE WAS FALSE -- Standing Rule 3, and it cost
    a real defect. A deployed database may be an EARLIER generation than the
    baseline, and this helper cannot produce one: it applies the baseline
    itself, so every adoption row that uses it exercises adoption against a
    database already at the baseline. That is why all four rows below were
    green while `adopt_existing` stamped a real pre-security database as
    current.

    The earlier generation is exercised by
    `test_w143_adoption_proves_the_generation.py`, which starts from a
    committed byte copy of `7b034e5:clinical/schema.sql`. Do not add an
    adoption row here that means to test an older database; it cannot.
    """
    baseline = {m.version: m for m in migrate.discover()}[migrate.BASELINE_VERSION]
    _apply_sql(connection, baseline.sql)


def _the_set_adoption_covers() -> tuple:
    """
    THE MIGRATIONS `adopt_existing` ACTUALLY ACCOUNTS FOR -- 1 and the
    baseline, and nothing above them.

    Adoption applies 1 for real and stamps the baseline; its own docstring
    says the rest is somebody else's job -- "Everything above the baseline
    runs normally, by `migrate`" (clinical/migrate.py, `adopt_existing`). So
    "this database is adopted" and "this database is at the newest migration
    on disk" are the same state ONLY while the baseline is the newest file.
    An adoption row that asserts the second is asserting the SIZE OF
    `clinical/migrations`, not the behaviour of adoption, and it changes its
    meaning the day a migration is added -- which is precisely what happened.

    Pinning here is not a relaxation: the verdict asserted against this set is
    the full four-question one, generation invariants included. What is
    excluded is only the question adoption never claimed to answer.
    """
    return tuple(m for m in migrate.discover() if m.version <= migrate.BASELINE_VERSION)


def _write_migrations(directory: pathlib.Path, files: dict) -> pathlib.Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        (directory / name).write_text(body, encoding="utf-8")
    return directory


def _catalog_has_table(connection, name: str) -> bool:
    with connection.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = %s",
            (name,),
        )
        return cur.fetchone() is not None


def _history(connection) -> tuple:
    with connection.cursor() as cur:
        cur.execute("SELECT version, name, checksum FROM schema_migrations ORDER BY version")
        return tuple(cur.fetchall())


# ─── the migration set on disk ──────────────────────────────────────────────


class TestTheMigrationSetIsAnOrderedIdentity:
    """These four rows are about the FILES, and they are the only rows here
    that are. Each says what it cannot see."""

    def test_discover_orders_by_the_integer_in_the_name(self, tmp_path):
        """
        CATCHES: a runner that sorts version strings, which puts 0010 before
        0009 the day the set passes nine.

        VACUOUS AGAINST: everything else, and -- stated plainly -- weak even
        here, because four-digit zero padding makes lexical and numeric order
        agree for every version below 10000. The row that actually proves
        ordering is `test_migrations_run_in_order_against_a_real_database`
        below, which makes a later migration DEPEND on an earlier one.
        """
        directory = _write_migrations(
            tmp_path / "m",
            {
                "0010_ten.sql": "SELECT 1;",
                "0002_two.sql": "SELECT 1;",
                "0003_three.sql": "SELECT 1;",
            },
        )
        assert [m.version for m in migrate.discover(directory)] == [2, 3, 10]

    def test_a_file_that_is_not_a_migration_is_refused_not_ignored(self, tmp_path):
        """
        CATCHES: a runner that skips what it does not recognise. `002_x.sql`,
        `0003-x.sql` and an editor's `0003_x.sql.bak` all become migrations
        that never run and never say so -- the silent kind of missing step.

        VACUOUS AGAINST: every runtime failure. It never opens a database.
        """
        directory = _write_migrations(tmp_path / "m", {"0001_ok.sql": "SELECT 1;", "002_typo.sql": "SELECT 1;"})
        with pytest.raises(migrate.MigrationSetError) as excinfo:
            migrate.discover(directory)
        assert "002_typo.sql" in str(excinfo.value)

    def test_two_files_claiming_one_version_are_refused(self, tmp_path):
        """CATCHES: a merge that lands two branches' migration 3. There is no
        correct order for them, so guessing is the wrong answer.
        VACUOUS AGAINST: everything at runtime."""
        directory = _write_migrations(tmp_path / "m", {"0003_a.sql": "SELECT 1;", "0003_b.sql": "SELECT 1;"})
        with pytest.raises(migrate.MigrationSetError) as excinfo:
            migrate.discover(directory)
        assert "version 3" in str(excinfo.value)

    def test_the_checksum_ignores_line_endings(self, tmp_path):
        """
        CATCHES: a checksum over raw bytes. This repository sets
        core.autocrlf=true and pins eol=lf for *.sh only, so the same committed
        .sql blob is CRLF on a Windows checkout and LF in the Linux CI
        container. A raw-byte checksum would match the stamp in schema.sql on
        exactly one of the two machines -- green locally, red in CI, for a
        reason nothing in the failure names.
        """
        crlf = (tmp_path / "crlf.sql").resolve()
        lf = (tmp_path / "lf.sql").resolve()
        crlf.write_bytes(b"CREATE TABLE t (a INT);\r\nSELECT 1;\r\n")
        lf.write_bytes(b"CREATE TABLE t (a INT);\nSELECT 1;\n")
        assert migrate.checksum_of(crlf.read_bytes()) == migrate.checksum_of(lf.read_bytes())

    def test_the_advisory_lock_key_is_pinned(self):
        """
        CATCHES: a rename of the string the key is derived from. The key is
        the only thing serialising two runners; if it moves, both proceed and
        nothing anywhere reports it.

        VACUOUS AGAINST: a runner that never takes the lock at all -- that is
        test_w126m_migration_concurrency.py.
        """
        assert migrate.ADVISORY_LOCK_KEY == -3602695354166949741

    def test_the_sentinel_table_matches_the_service(self):
        """The one string clinical/migrate.py restates from clinical/app.py
        rather than importing (importing back would be a cycle). If the two
        ever disagree, `migrate` would refuse to adopt a database `/readyz`
        calls bootstrapped, or worse, adopt one it does not."""
        from clinical import app

        assert migrate.SENTINEL_TABLE == app._SENTINEL_TABLE


# ─── a fresh database ───────────────────────────────────────────────────────


class TestAFreshDatabase:
    def test_schema_sql_still_creates_a_complete_database(self):
        """
        CATCHES: this wave breaking the one path that already worked. The
        assertion is on the CATALOG -- `schema_migrations` is there AND so are
        the tables that were there before it.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _fresh_from_schema_sql(connection)
            for table in ("organisations", "sessions", "reports", "exception_events", "schema_migrations"):
                assert _catalog_has_table(connection, table), table

    def test_a_fresh_database_is_already_at_the_latest_version(self):
        """
        CATCHES: fresh-database option A done half way -- schema.sql creating
        the current state without stamping the history. Such a database
        reports every migration pending for ever, and the next deploy runs the
        baseline against a database that already has it.

        VACUOUS AGAINST: a wrong catalog. It reads the verdict, not the tables.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _fresh_from_schema_sql(connection)
            state = migrate.inspect_state(connection)
            assert state.ok is True
            assert state.pending == ()
            assert state.current_version == max(m.version for m in migrate.discover())

    def test_schema_sql_stamps_exactly_the_migration_set(self):
        """
        CATCHES: the two halves of option A drifting -- a migration added to
        `clinical/migrations/` without its stamp in `schema.sql`, or a stamp
        whose checksum no longer matches the file it names (i.e. an applied
        migration edited after the fact).

        THIS IS READ OUT OF A DATABASE, not out of schema.sql: the rows come
        back from a real `SELECT` against a database that file created.
        """
        on_disk = tuple((m.version, m.name, m.checksum) for m in migrate.discover())
        with scratch_database() as dsn, connect(dsn) as connection:
            _fresh_from_schema_sql(connection)
            assert _history(connection) == on_disk

    def test_the_application_role_may_read_the_history_and_may_never_write_it(self):
        """
        CATCHES: a schema_migrations table the service can INSERT into. A
        service that can write its own history can declare itself migrated
        without migrating, which is the exact failure the history exists to
        make impossible.

        Asserted as a SET of the four privileges, not one at a time: a
        per-privilege assertion passes against a grant nobody listed.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _fresh_from_schema_sql(connection)
            with connection.cursor() as cur:
                cur.execute(
                    "SELECT p, has_table_privilege('clinical_app', 'schema_migrations', p) "
                    "FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS p"
                )
                got = dict(cur.fetchall())
        assert got == {"SELECT": True, "INSERT": False, "UPDATE": False, "DELETE": False}


# ─── an empty database, migrated ────────────────────────────────────────────


class TestMigratingFromEmpty:
    def test_migrate_applies_every_migration_and_records_what_it_applied(self):
        """
        CATCHES: a runner that records without running, or runs without
        recording. Both halves are asserted: the CATALOG has the tables, and
        the history names the versions with the checksums of the files on disk.
        """
        expected = tuple((m.version, m.name, m.checksum) for m in migrate.discover())
        with scratch_database() as dsn, connect(dsn) as connection:
            applied = migrate.migrate(connection)
            assert applied == tuple(m.version for m in migrate.discover())
            assert _history(connection) == expected
            for table in ("organisations", "sessions", "reports", "schema_migrations"):
                assert _catalog_has_table(connection, table), table

    def test_migrations_run_in_order_against_a_real_database(self, tmp_path):
        """
        THE NON-VACUOUS ORDERING ROW. 0002 creates a table; 0003 adds a column
        to it. Applied in the wrong order, 0003 raises UndefinedTable and the
        run fails -- so the assertion is that BOTH the table and the column
        exist afterwards, which only an in-order run produces.

        CATCHES: WRONG G (unordered application).
        """
        directory = _write_migrations(
            tmp_path / "m",
            {
                "0001_history.sql": (migrate.MIGRATIONS_DIR / "0001_schema_migrations.sql").read_text(encoding="utf-8"),
                "0002_create.sql": "CREATE TABLE w126m_order (a INT);",
                "0003_alter.sql": "ALTER TABLE w126m_order ADD COLUMN b INT;",
            },
        )
        migrations = migrate.discover(directory)
        with scratch_database() as dsn, connect(dsn) as connection:
            migrate.migrate(connection, migrations)
            with connection.cursor() as cur:
                cur.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = 'w126m_order' "
                    "ORDER BY column_name"
                )
                assert [r[0] for r in cur.fetchall()] == ["a", "b"]

    def test_a_second_run_applies_nothing_and_leaves_the_data_written_between_them(self):
        """
        CATCHES: WRONG C -- silent re-application. A runner with no history, or
        one that replays every step every deploy.

        RULE 4 SHAPE. The absence assertion (`applied == ()`) is paired with a
        positive one that the broken state fails: a row written BETWEEN the two
        runs is still there afterwards, by its exact name. A re-applied
        baseline would have aborted at 42P07; a re-applied "IF NOT EXISTS"
        baseline would have left the row but is caught by the history
        comparison, which must be identical down to the checksum.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            migrate.migrate(connection)
            before = _history(connection)
            plant_sentinel(connection)

            applied = migrate.migrate(connection)

            assert applied == ()
            assert _history(connection) == before
            notes, orgs = read_sentinel(connection)
            assert notes == (SENTINEL_NOTE,)
            assert orgs == (SENTINEL_ORG,)


# ─── an EXISTING database ───────────────────────────────────────────────────


class TestUpgradingADatabaseThatAlreadyExists:
    """The tests the whole audit said could not be written, because every
    fixture in the package destroys the database first."""

    def test_an_existing_database_gains_the_new_object_and_keeps_its_data(self):
        """
        THE CENTRE OF THE UPGRADE STORY, and both halves are load-bearing.

        THE MARKER HALF (WRONG F -- "do what the tests do: DROP SCHEMA and
        re-apply"): an organisation row and a table of its own are written
        BEFORE the upgrade and asserted afterwards BY CONTENT. A
        dropped-and-recreated database cannot have them. This is what makes
        the test structurally incapable of passing because a fixture rebuilt
        the schema.

        THE NEW-OBJECT HALF: `schema_migrations` did not exist before and does
        afterwards, with both versions recorded. Without this half the test
        passes against a runner that does nothing at all.

        THE VERDICT HALF, RE-AUTHORED IN w146. This row used to end
        `assert migrate.inspect_state(connection).ok is True`, which was a
        claim about `adopt_existing` only by coincidence: the baseline was the
        newest file on disk, so "adopted" and "fully current" named one state.
        They are two states and the mechanism always said so. The row now
        asserts them separately -- adoption's contract against the set
        adoption covers, THEN readiness after the rest of the set has run.

        CATCHES, as re-authored: an `adopt_existing` that records the versions
        without proving the generation (the pinned verdict still evaluates
        `BASELINE_GENERATION_INVARIANTS`), and an `adopt_existing` that leaves
        a database the subsequent `migrate` cannot complete.

        VACUOUS AGAINST: the generation question on an EARLIER-generation
        database -- this helper cannot build one, as `_pre_mechanism` says at
        length. That is `test_w143_adoption_proves_the_generation.py`. It is
        also vacuous against a reordering of `inspect_state`'s questions --
        that is `test_w146_generation_survives_a_third_migration.py`.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _pre_mechanism(connection)
            plant_sentinel(connection)
            assert not _catalog_has_table(connection, "schema_migrations")

            migrate.adopt_existing(connection)

            notes, orgs = read_sentinel(connection)
            assert notes == (SENTINEL_NOTE,)
            assert orgs == (SENTINEL_ORG,)
            assert _catalog_has_table(connection, "schema_migrations")
            assert [row[0] for row in _history(connection)] == [1, 2]

            # ADOPTION'S OWN CONTRACT, against the set adoption covers. Pinned
            # rather than relaxed: `ok` here still means all four questions,
            # the catalog one included.
            adopted = migrate.inspect_state(connection, _the_set_adoption_covers())
            assert adopted.ok is True, adopted.detail
            assert adopted.pending == ()
            assert adopted.current_version == migrate.BASELINE_VERSION

            # AND THEN THE REST OF THE SET -- the other half of the contract,
            # asserted as its own step with its own verdict. Two claims, two
            # ways for this row to go red. Today `migrate` applies nothing
            # here because the baseline IS the newest file; the assertion is
            # written so that stays true when it no longer is.
            migrate.migrate(connection)
            full = migrate.inspect_state(connection)
            assert full.ok is True, full.detail
            assert full.pending == ()
            assert [row[0] for row in _history(connection)] == [m.version for m in migrate.discover()]

    def test_migrate_refuses_a_pre_mechanism_database_rather_than_guessing(self):
        """
        CATCHES: a runner that stamps an unknown database at a version it
        assumed, and a runner that runs the baseline against a populated
        database. Asserted with the data still intact: the refusal changed
        nothing.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _pre_mechanism(connection)
            plant_sentinel(connection)

            with pytest.raises(migrate.MigrationStateError) as excinfo:
                migrate.migrate(connection)

            assert "adopt-existing" in str(excinfo.value)
            assert not _catalog_has_table(connection, "schema_migrations")
            assert read_sentinel(connection) == ((SENTINEL_NOTE,), (SENTINEL_ORG,))

    def test_adopting_an_empty_database_is_refused(self):
        """CATCHES: stamping a baseline that is not there. Such a database
        would report ready while holding no tables at all."""
        with scratch_database() as dsn, connect(dsn) as connection:
            with pytest.raises(migrate.MigrationStateError) as excinfo:
                migrate.adopt_existing(connection)
            assert "does not hold the clinical schema" in str(excinfo.value)
            assert not _catalog_has_table(connection, "schema_migrations")

    def test_adopting_twice_is_refused(self):
        """CATCHES: a second adoption overwriting a real history. Asserted on
        the history CONTENT, which must be untouched."""
        with scratch_database() as dsn, connect(dsn) as connection:
            _pre_mechanism(connection)
            migrate.adopt_existing(connection)
            before = _history(connection)

            with pytest.raises(migrate.MigrationStateError):
                migrate.adopt_existing(connection)

            assert _history(connection) == before


# ─── failure and drift ──────────────────────────────────────────────────────


class TestFailureIsObservableAndNeverRecordedAsSuccess:
    def test_a_failing_migration_leaves_neither_its_object_nor_its_history_row(self, tmp_path):
        """
        CATCHES: WRONG E -- the history written outside, or before, the DDL's
        transaction. Such a runner leaves the database RECORDED as upgraded
        and actually not, and every later run skips the step for ever.

        BOTH CHANNELS, which is the shape STANDING RULE 8 asks for: the
        history says the version is NOT applied, and the CATALOG says the
        object is NOT there. A row asserting only one of the two passes
        against half the defect.
        """
        history_sql = (migrate.MIGRATIONS_DIR / "0001_schema_migrations.sql").read_text(encoding="utf-8")
        directory = _write_migrations(
            tmp_path / "m",
            {
                "0001_history.sql": history_sql,
                # The table is created and THEN the step fails, so a runner
                # without a transaction leaves the table behind.
                "0002_half.sql": (
                    "CREATE TABLE w126m_half (a INT);\n"
                    "ALTER TABLE w126m_half ADD CONSTRAINT impossible CHECK (no_such_column > 0);\n"
                ),
            },
        )
        migrations = migrate.discover(directory)
        with scratch_database() as dsn, connect(dsn) as connection:
            with pytest.raises(Exception):  # noqa: B017 -- psycopg raises the server's error
                migrate.migrate(connection, migrations)
            connection.rollback()

            assert [row[0] for row in _history(connection)] == [1]
            assert not _catalog_has_table(connection, "w126m_half")

    def test_the_positive_twin_a_succeeding_migration_leaves_both(self, tmp_path):
        """The twin the row above needs. Same shape, a statement that works:
        the object IS in the catalog and the history row IS there. Without
        this, the row above passes against a runner that applies nothing."""
        history_sql = (migrate.MIGRATIONS_DIR / "0001_schema_migrations.sql").read_text(encoding="utf-8")
        directory = _write_migrations(
            tmp_path / "m",
            {
                "0001_history.sql": history_sql,
                "0002_whole.sql": (
                    "CREATE TABLE w126m_half (a INT);\nALTER TABLE w126m_half ADD CONSTRAINT possible CHECK (a > 0);\n"
                ),
            },
        )
        migrations = migrate.discover(directory)
        with scratch_database() as dsn, connect(dsn) as connection:
            migrate.migrate(connection, migrations)
            assert [row[0] for row in _history(connection)] == [1, 2]
            assert _catalog_has_table(connection, "w126m_half")

    def test_a_migration_whose_first_object_already_exists_is_not_recorded_as_applied(self, tmp_path):
        """
        WRONG B -- "make it idempotent: CREATE TABLE IF NOT EXISTS everywhere",
        or its runner-side twin, a runner that swallows duplicate-object errors
        and calls the step done. Its own author says why it is wrong, three
        lines below the pattern in this repository's one real in-place upgrade
        (geper/api/submission_store.py): "CREATE TABLE IF NOT EXISTS does not
        add a column to a store file created before it existed."

        THE CONSTRUCTION: migration 2 creates TWO tables. The first already
        exists, so the statement raises 42P07 -- and the SECOND table, which is
        what the migration was actually for, never gets created. A runner that
        treats "already there" as "done" records version 2 and the second table
        is missing for ever, silently.

        BOTH CHANNELS, and the catalog one is the load-bearing half:
          * the history must NOT contain version 2;
          * `w126m_b_wanted` must NOT be in the catalog;
          * and the verdict must not be ok -- under the wrong runner the
            history says applied and the MIGRATION-ASSERT below says otherwise,
            so this is WRONG I's shape arriving through WRONG B's door.
        """
        history_sql = (migrate.MIGRATIONS_DIR / "0001_schema_migrations.sql").read_text(encoding="utf-8")
        directory = _write_migrations(
            tmp_path / "m",
            {
                "0001_history.sql": history_sql,
                "0002_two_tables.sql": (
                    "-- MIGRATION-ASSERT: to_regclass('w126m_b_wanted') IS NOT NULL\n"
                    "CREATE TABLE w126m_b_existing (a INT);\n"
                    "CREATE TABLE w126m_b_wanted (a INT);\n"
                ),
            },
        )
        migrations = migrate.discover(directory)
        with scratch_database() as dsn, connect(dsn) as connection:
            # the table is already there -- the state every real "re-run it,
            # it's idempotent" attempt meets
            _apply_sql(connection, "CREATE TABLE w126m_b_existing (a INT)")

            with pytest.raises(Exception):  # noqa: B017 -- psycopg raises DuplicateTable
                migrate.migrate(connection, migrations)
            connection.rollback()

            assert [row[0] for row in _history(connection)] == [1]
            assert not _catalog_has_table(connection, "w126m_b_wanted")
            assert migrate.inspect_state(connection, migrations).ok is False

    def test_the_history_row_and_the_ddl_are_one_transaction(self, tmp_path):
        """
        WRONG E, AND IT NEEDS ITS OWN ROW because the obvious failing-migration
        test does not catch it. When the migration's own SQL fails, a runner
        that commits the DDL and THEN records still loses the DDL -- psycopg
        sends the whole file as one statement, so the failure rolls it back
        either way, and the two implementations are indistinguishable.

        WHAT DISTINGUISHES THEM is a migration whose DDL SUCCEEDS and whose
        HISTORY ROW CANNOT BE WRITTEN. `version` is the PRIMARY KEY, so
        re-applying an already-recorded version is exactly that case:
          * one transaction  -> the duplicate key takes the statement down with
            it, and the row this migration would have inserted is NOT there;
          * two transactions -> the statement is already committed when the
            duplicate key arrives, and the row IS there, for ever, with nothing
            in the history to say it happened.

        `_apply` is called directly because `_apply` IS the transaction
        boundary -- it is the unit under test, not an implementation detail
        being poked at. The assertion is on the CONTENT of the table, never on
        a count: a count of one is satisfied by either outcome if the first row
        went missing.
        """
        history_sql = (migrate.MIGRATIONS_DIR / "0001_schema_migrations.sql").read_text(encoding="utf-8")
        directory = _write_migrations(
            tmp_path / "m",
            {
                "0001_history.sql": history_sql,
                "0002_seed.sql": ("CREATE TABLE w126m_e (note TEXT);\nINSERT INTO w126m_e (note) VALUES ('first');\n"),
            },
        )
        migrations = migrate.discover(directory)
        with scratch_database() as dsn, connect(dsn) as connection:
            migrate.migrate(connection, migrations)
            with connection.cursor() as cur:
                cur.execute("SELECT note FROM w126m_e ORDER BY note")
                assert [r[0] for r in cur.fetchall()] == ["first"]

            replay = dataclasses.replace(migrations[1], sql="INSERT INTO w126m_e (note) VALUES ('second');")
            with pytest.raises(Exception):  # noqa: B017 -- UniqueViolation on version
                migrate._apply(connection, replay)
            connection.rollback()

            with connection.cursor() as cur:
                cur.execute("SELECT note FROM w126m_e ORDER BY note")
                assert [r[0] for r in cur.fetchall()] == ["first"]
            assert [row[0] for row in _history(connection)] == [1, 2]

    def test_a_history_that_says_applied_while_the_catalog_disagrees_is_not_ok(self, tmp_path):
        """
        WRONG I, AND IT IS TESTED FORWARDS. The history says version 2 is
        applied. The object version 2 exists to create is gone. The verdict
        must come from `pg_catalog`, not from the row.

        The row's own state is asserted too -- it is still there, saying
        "applied" -- so the test cannot pass because the history was cleaned
        up instead.
        """
        history_sql = (migrate.MIGRATIONS_DIR / "0001_schema_migrations.sql").read_text(encoding="utf-8")
        directory = _write_migrations(
            tmp_path / "m",
            {
                "0001_history.sql": history_sql,
                "0002_probe.sql": (
                    "-- MIGRATION-ASSERT: to_regclass('w126m_drift_probe') IS NOT NULL\n"
                    "CREATE TABLE w126m_drift_probe (a INT);\n"
                ),
            },
        )
        migrations = migrate.discover(directory)
        with scratch_database() as dsn, connect(dsn) as connection:
            migrate.migrate(connection, migrations)
            # THE POSITIVE TWIN, first: on a database that really is at
            # version 2, the same call says ok.
            assert migrate.inspect_state(connection, migrations).ok is True

            _apply_sql(connection, "DROP TABLE w126m_drift_probe")

            state = migrate.inspect_state(connection, migrations)
            assert state.ok is False
            assert state.reason == "schema_drift"
            assert "w126m_drift_probe" in state.detail
            # and the lying row is still there, which is the point
            assert [row[0] for row in _history(connection)] == [1, 2]

    def test_editing_an_applied_migration_is_refused(self, tmp_path):
        """
        CATCHES: a migration file edited after it ran. The history still says
        applied, the database still holds the OLD shape, and the new bytes
        never run anywhere -- invisible without the checksum.
        """
        history_sql = (migrate.MIGRATIONS_DIR / "0001_schema_migrations.sql").read_text(encoding="utf-8")
        directory = _write_migrations(
            tmp_path / "m",
            {"0001_history.sql": history_sql, "0002_thing.sql": "CREATE TABLE w126m_thing (a INT);\n"},
        )
        with scratch_database() as dsn, connect(dsn) as connection:
            migrate.migrate(connection, migrate.discover(directory))

            (directory / "0002_thing.sql").write_text("CREATE TABLE w126m_thing (a INT, b INT);\n", encoding="utf-8")
            edited = migrate.discover(directory)

            with pytest.raises(migrate.MigrationChecksumMismatch):
                migrate.migrate(connection, edited)
            connection.rollback()

            state = migrate.inspect_state(connection, edited)
            assert state.reason == "schema_migration_checksum_mismatch"

    def test_an_uninitialised_database_is_not_ok_and_says_which_way_it_is_not(self):
        """The third verdict. CATCHES: a state check that only distinguishes
        ok from not-ok, leaving an operator unable to tell "never migrated"
        from "behind" -- different actions."""
        with scratch_database() as dsn, connect(dsn) as connection:
            state = migrate.inspect_state(connection)
            assert state.ok is False
            assert state.reason == "schema_not_initialised"
            assert state.current_version is None


class TestTheCommandLineExitCodeIsAVerdict:
    """
    The CLI is what a deploy pipeline runs, so its EXIT CODE is the verdict
    anything automated will act on. A pipeline reads the number, never the
    text, and a step that exits 0 on a database this code cannot serve is the
    falsely-ready report moved out of /readyz and into the deploy.

    `main()` is called directly rather than through a subprocess: it is the
    entry point `python -m clinical.migrate` runs, and a subprocess would add
    an interpreter start to every row for no extra coverage.
    """

    def test_migrate_exits_non_zero_when_the_database_is_still_not_right(self, monkeypatch, capsys):
        """
        CATCHES: an exit code that reports only "did I raise". Here there is
        nothing pending -- `--migrate` has no work to do and does not fail --
        and the database is nonetheless wrong: the history claims migration 2
        and `exception_events` is gone. "Nothing was pending" is not
        "everything is right".

        The stdout is asserted too, not just the code: the operator must be
        told WHICH way it is wrong.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _fresh_from_schema_sql(connection)
            _apply_sql(connection, "DROP TABLE exception_events CASCADE")

            monkeypatch.setenv("CLINICAL_BOOTSTRAP_DSN", dsn)
            code = migrate.main(["--migrate"])
            out = capsys.readouterr().out

        assert code == 3
        assert "schema_drift" in out
        assert "exception_events" in out

    def test_the_positive_twin_a_correct_database_exits_zero(self, monkeypatch, capsys):
        """Without this the row above passes against a CLI that always exits
        3, which would make every deploy fail and teach everyone to ignore the
        code."""
        with scratch_database() as dsn, connect(dsn) as connection:
            _fresh_from_schema_sql(connection)

            monkeypatch.setenv("CLINICAL_BOOTSTRAP_DSN", dsn)
            code = migrate.main(["--migrate"])
            out = capsys.readouterr().out

        assert code == 0
        assert "verdict       : OK" in out
        assert "(nothing pending)" in out

    def test_status_is_a_query_and_exits_zero_even_on_a_bad_database(self, monkeypatch, capsys):
        """
        The deliberate exception, asserted so it is a decision rather than an
        oversight: an operator asking what a database is at has not failed by
        getting an answer, and a non-zero `--status` is unusable in a shell.
        The VERDICT still has to be in the output.
        """
        with scratch_database() as dsn:
            monkeypatch.setenv("CLINICAL_BOOTSTRAP_DSN", dsn)
            code = migrate.main(["--status"])
            out = capsys.readouterr().out

        assert code == 0
        assert "schema_not_initialised" in out

    def test_a_missing_administrative_dsn_is_refused_and_named(self, monkeypatch, capsys):
        """CATCHES: a CLI that falls back to CLINICAL_DSN, which is the
        application role -- the one the entire GRANT/REVOKE block exists to
        deny these privileges to."""
        monkeypatch.delenv("CLINICAL_BOOTSTRAP_DSN", raising=False)
        code = migrate.main(["--status"])
        err = capsys.readouterr().err
        assert code == 1
        assert "CLINICAL_BOOTSTRAP_DSN" in err
        assert "not CLINICAL_DSN" in err


def test_the_migration_tests_never_call_the_drop_and_recreate_fixture():
    """
    STRUCTURAL, and it is about this file rather than about the mechanism.

    The trap is that these tests are one import away from being handed a
    freshly rebuilt database, at which point every assertion above passes for
    the wrong reason. This fails if the words ever appear in the migration
    test files.
    """
    here = pathlib.Path(__file__).resolve().parent
    files = sorted(here.glob("test_w126m_*.py")) + sorted(here.glob("test_w143_*.py")) + [here / "migration_db.py"]
    # Non-vacuity: a glob that matched nothing would make this pass by
    # checking no files at all, which is the exact shape of the failure it
    # exists to catch.
    assert len(files) >= 2, [f.name for f in files]

    for path in files:
        name = path.name
        text = path.read_text(encoding="utf-8")
        # Each token is BUILT from halves rather than written out, because
        # this file is one of the files it reads and a literal copy anywhere
        # in it -- including in this comment -- would make the check fail on
        # its own source.
        for forbidden in ("reset_" + "schema(", "from clinical.tests." + "db_" + "guard", 'execute("DROP ' + "SCHEMA"):
            assert forbidden not in text, f"{name}: {forbidden}"

    # And the sentinel is a sentinel: nothing in schema.sql creates it, so a
    # database rebuilt from schema.sql cannot have it by any route.
    assert migration_db.SENTINEL_TABLE not in SCHEMA_PATH.read_text(encoding="utf-8")
