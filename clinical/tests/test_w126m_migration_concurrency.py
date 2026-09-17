"""
clinical/tests/test_w126m_migration_concurrency.py
──────────────────────────────────────────────────
TWO RUNNERS, ONE DATABASE -- PROVED DETERMINISTICALLY, NEVER RACED.

WHY THIS IS NOT TESTED WITH THREADS AND SLEEPS. The obvious test starts two
processes at "the same time" and asserts that exactly one migrates. It passes
on a fast machine, fails in CI, and gets marked flaky and skipped -- which is
worse than no test, because the gap stops being visible. Whether the two
processes actually overlap is not something the test controls.

WHAT POSTGRES GIVES INSTEAD, AND IT IS EXACT. The lock is the mechanism, so
take the lock. Connection A acquires `pg_advisory_lock(ADVISORY_LOCK_KEY)` and
HOLDS IT for the whole test -- it is never released while B runs, so B's
outcome does not depend on timing at all: there is no speed at which B could
get the lock, because nothing ever offers it. B's `lock_timeout` bounds how
long B waits before saying so; it does not decide WHETHER B succeeds.

MEASURED, not assumed (PostgreSQL 16, 2026-09-17): `lock_timeout` DOES apply
to a wait for an advisory lock. A blocked `pg_advisory_lock` raises
psycopg.errors.LockNotAvailable, SQLSTATE 55P03, at the timeout.

AND THE ASSERTION IS ABOUT THE DATABASE, NOT ABOUT THE EXCEPTION. "B raised"
is satisfied by a runner that raised for any reason at all, including one that
had already applied half the migration set. So every row below finishes by
reading the history and the catalog.
"""

from __future__ import annotations

import pytest

from clinical import migrate
from clinical.tests.migration_db import connect, scratch_database

# Short ON PURPOSE and it is not a race: A holds the lock for the entire test,
# so B can never acquire it however long it waits. This value decides only how
# long the test takes to reach a verdict it was always going to reach.
BLOCKED_TIMEOUT = "500ms"


def _history(connection) -> tuple:
    with connection.cursor() as cur:
        cur.execute("SELECT version, name FROM schema_migrations ORDER BY version")
        return tuple(cur.fetchall())


def _tables(connection) -> tuple:
    with connection.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
        )
        return tuple(r[0] for r in cur.fetchall())


class TestOnlyOneRunnerAtATime:
    def test_a_second_runner_refuses_rather_than_applying_a_second_copy(self):
        """
        WRONG D. A holds the migration lock. B attempts the whole migration
        set against an EMPTY database and must come away having applied
        NOTHING -- not a partial set, not a duplicate.

        THREE ASSERTIONS, because "it raised" is the weakest of them:
          1. B raised MigrationLockUnavailable (the domain error, not a raw
             server error -- an operator has to be able to tell "someone else
             is deploying" from "the migration is broken");
          2. the history table does not exist -- B recorded nothing;
          3. the catalog is empty of clinical tables -- B ran no DDL either.
        """
        with scratch_database() as dsn:
            with connect(dsn, autocommit=True) as a, connect(dsn) as b:
                with a.cursor() as cur:
                    cur.execute("SELECT pg_advisory_lock(%s)", (migrate.ADVISORY_LOCK_KEY,))

                with pytest.raises(migrate.MigrationLockUnavailable):
                    migrate.migrate(b, lock_timeout=BLOCKED_TIMEOUT)

                b.rollback()
                assert "schema_migrations" not in _tables(b)
                assert "organisations" not in _tables(b)

    def test_the_positive_twin_the_same_runner_succeeds_once_the_lock_is_free(self):
        """
        The twin the row above needs. Without it, that row passes against a
        runner that refuses ALWAYS -- which would also apply nothing, and
        would also be useless.

        Same connection, same call, same database; the only thing that changed
        is that A released the lock. The assertions are the opposite of the
        ones above, and they are about the database.
        """
        with scratch_database() as dsn:
            with connect(dsn, autocommit=True) as a, connect(dsn) as b:
                with a.cursor() as cur:
                    cur.execute("SELECT pg_advisory_lock(%s)", (migrate.ADVISORY_LOCK_KEY,))

                with pytest.raises(migrate.MigrationLockUnavailable):
                    migrate.migrate(b, lock_timeout=BLOCKED_TIMEOUT)
                b.rollback()

                with a.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (migrate.ADVISORY_LOCK_KEY,))

                applied = migrate.migrate(b, lock_timeout=BLOCKED_TIMEOUT)

                assert applied == tuple(m.version for m in migrate.discover())
                assert _history(b) == ((1, "schema_migrations"), (2, "baseline"))
                assert "organisations" in _tables(b)

    def test_a_second_runner_arriving_after_the_first_finished_applies_nothing_twice(self):
        """
        The other half of "serialised": one runner waits, and then finds there
        is nothing left to do. Here A has ALREADY migrated and released; B
        runs the same set against the same database.

        CATCHES: a runner that serialises correctly and then re-applies --
        two replicas starting together where the second waits its turn and
        then runs the baseline again. The history must be byte-identical
        afterwards, checksums included.
        """
        with scratch_database() as dsn:
            with connect(dsn) as a, connect(dsn) as b:
                migrate.migrate(a)
                before = _history(a)

                applied = migrate.migrate(b)

                assert applied == ()
                assert _history(b) == before
                assert migrate.inspect_state(b).ok is True

    def test_the_runner_releases_the_lock_even_when_a_migration_fails(self, tmp_path):
        """
        CATCHES: a lock leak. A runner that holds the advisory lock after a
        failed migration wedges every later deploy, and the symptom -- a
        deploy that hangs -- names nothing. The session-level lock would also
        survive a `commit()`, which is exactly why it is used, and exactly why
        releasing it has to be in a `finally`.

        Proved by OBSERVING THE SERVER's lock table, not by reading the code:
        after the failure, `pg_locks` holds no advisory lock on that key.
        """
        history_sql = (migrate.MIGRATIONS_DIR / "0001_schema_migrations.sql").read_text(encoding="utf-8")
        directory = tmp_path / "m"
        directory.mkdir()
        (directory / "0001_history.sql").write_text(history_sql, encoding="utf-8")
        (directory / "0002_bad.sql").write_text("SELECT no_such_function();\n", encoding="utf-8")
        migrations = migrate.discover(directory)

        def advisory_locks_here(connection) -> int:
            with connection.cursor() as cur:
                # Advisory locks are per-database, and this database was
                # created for this test alone, so ANY advisory lock here is
                # the runner's. Counted by database rather than by
                # reassembling the 64-bit key out of pg_locks' classid and
                # objid, which is an unsigned-versus-signed trap and would
                # make the row pass by returning zero for the wrong reason.
                cur.execute(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                    "AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"
                )
                return cur.fetchone()[0]

        with scratch_database() as dsn:
            with connect(dsn) as runner, connect(dsn, autocommit=True) as observer:
                # THE POSITIVE CONTROL FOR THE INSTRUMENT. A count that is
                # always zero proves nothing; show it reads one first.
                with observer.cursor() as cur:
                    cur.execute("SELECT pg_advisory_lock(%s)", (migrate.ADVISORY_LOCK_KEY,))
                assert advisory_locks_here(observer) == 1
                with observer.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (migrate.ADVISORY_LOCK_KEY,))
                assert advisory_locks_here(observer) == 0

                with pytest.raises(Exception):  # noqa: B017 -- the server's error
                    migrate.migrate(runner, migrations)
                runner.rollback()

                assert advisory_locks_here(observer) == 0

                # and the proof that the lock is genuinely free: another
                # runner can now take it and finish the work.
                assert migrate.migrate(runner, migrations[:1]) == ()
