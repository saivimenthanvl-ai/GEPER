"""
clinical/tests/test_w146_generation_survives_a_third_migration.py
──────────────────────────────────────────────────────────────────
THE GENERATION VERDICT, PROVED IN A WORLD WHERE IT IS NOT THE FIRST REFUSAL.

WHAT THIS FILE IS FOR, AND WHY IT IS A FILE AND NOT THREE MORE ROWS.

`test_w143_adoption_proves_the_generation.py` proves that readiness reads the
CATALOG rather than the history table. Every row of it was written while
`clinical/migrations/` held exactly two files, and in that world one predicate
stood for three different claims at once:

    fully adopted  ==  at the newest migration  ==  of the current generation

`inspect_state` asks four questions in a fixed order and returns the FIRST
refusal it finds (clinical/migrate.py, `inspect_state`): history table, then
pending migrations, then checksums, then -- last, and only last -- the catalog
assertions that carry `BASELINE_GENERATION_INVARIANTS`. That order is correct.
You cannot evaluate a migration's post-conditions before it has run, and the
runner says so in its own words: "in the order in which each makes the next
meaningful". NOTHING HERE ASKS FOR IT TO CHANGE.

But it means the generation verdict is the LAST one reachable, and a proof
that asserts a refusal BY ITS REASON is coupled to that order. Add a third
migration and every database that has not applied it answers
`schema_migrations_pending` -- including a pre-security database whose history
is a forgery, whose real fault is that it has no `exception_events.org_id`,
and which the w143 rows exist to catch. The rows go RED, loudly. The danger is
not the red; it is the cheapest repair, which is to accept the new reason.
That repair is green and it is hollow: the nine generation invariants could be
DELETED and nothing would notice.

So this file proves the properties that the two-migration world let the other
two files take for granted:

  (i)   GENERATION IS DISTINGUISHABLE FROM VERSION. One database, two
        migration sets, two different verdicts -- and the generation half of
        the verdict does not move.
  (ii)  GENERATION/DRIFT IS EVALUATED INDEPENDENTLY OF HOW MANY MIGRATIONS
        EXIST. The same wrong-generation database is refused for
        `schema_drift`, naming the same column, under a two-migration set and
        under a three-migration set.
  (iii) THE GENERATION VERDICT CANNOT BE HIDDEN BEHIND THE CHEAPER REFUSAL.
        Stated as precedence, asserted rather than assumed, in both
        directions: not behind -> the generation verdict is what comes back;
        behind -> the cheap one does, and that is exactly why no generation
        row may be written against a database that is behind.
  (iv)  EVERY REFUSAL REASON HAS A MEANINGFUL TWIN. In particular
        `schema_migrations_pending` gets the twin it never had: a database
        that is behind AND of the right generation, whose invariants are
        shown to HOLD -- measured, on that database, from the catalog. Without
        it, "pending" is satisfied by a machine whose generation check is
        broken, unreached, or absent.

HOW A THREE-MIGRATION WORLD IS OBTAINED WITHOUT ADDING A THIRD MIGRATION.
Every row below builds a throwaway set in `tmp_path` -- the idiom
`test_w126m_migration_mechanism.py` already uses in six places -- from the
REAL `0001_schema_migrations.sql`, the REAL `0002_baseline.sql` bytes, and one
trivial third file. NO FILE IS ADDED UNDER `clinical/migrations/`, and
`clinical/migrate.py`, `clinical/app.py` and `clinical/schema.sql` are not
touched by this wave at all.

THE THROWAWAY BASELINE IS NAMED `baseline` ON PURPOSE. `_GENERATION_INVARIANTS`
is keyed by `(version, name)` and not by version alone, so a throwaway
`0002_anything.sql` carries NO invariants and every row here would pass
against a runner with no generation machinery whatsoever. The first row below
is that non-vacuity check and it must be read as a precondition for the rest
of the file.

WHAT THIS FILE CANNOT SEE. `/readyz` calls `migrate.discover()` itself and
cannot be handed a pinned set, so the probe rows stay in
`test_w143_adoption_proves_the_generation.py`, in the real two-migration
world. That file's forged-history helper now stamps the WHOLE discovered set,
which is what keeps the probe reaching the catalog whatever the size of
`clinical/migrations/`.

These tests create their own databases (clinical/tests/migration_db.py) and
never touch the package's drop-and-recreate fixtures.
"""

from __future__ import annotations

import pathlib

import pytest

from clinical import migrate
from clinical.tests.migration_db import connect, scratch_database

PRE_SECURITY_PATH = pathlib.Path(__file__).resolve().parent / "fixtures" / "pre_security_schema_da97f847.sql"

# The third migration's only job is to EXIST and to be applicable to a
# baseline-generation database. It carries a post-condition of its own so that
# a set built from it is a real migration set, checked the same way as any
# other, rather than a file the runner tolerates.
THIRD_MIGRATION_SQL = (
    "-- MIGRATION-ASSERT: to_regclass('w146_third_migration') IS NOT NULL\n"
    "CREATE TABLE w146_third_migration (note TEXT PRIMARY KEY);\n"
)

# A REALISTIC third migration, and it is realistic in the one way that
# matters: it touches the tenant-isolation column. Every security change in
# this stack is a column added to a table that already existed, and every
# migration after one of them is written against the result -- so a third
# migration that does NOT depend on the current generation is the unusual
# case, not this. Used by the row that shows why "just run the rest of the
# set" is not a repair for a database of the wrong generation.
DEPENDENT_MIGRATION_SQL = (
    "-- MIGRATION-ASSERT: to_regclass('w146_dependent_idx') IS NOT NULL\n"
    "CREATE INDEX w146_dependent_idx ON exception_events (org_id);\n"
)

# The column whose absence separates the baseline generation from every
# earlier one. Named here so the rows assert on the CONTENT of the refusal and
# not merely on its label -- a `schema_drift` that named some other object
# would be a different finding wearing the same word.
THE_SECURITY_COLUMN = "exception_events.org_id"


# ─── helpers ────────────────────────────────────────────────────────────────


def _apply(connection, sql: str) -> None:
    with connection.cursor() as cur:
        cur.execute(sql)
    connection.commit()


def _real(name: str) -> str:
    return (migrate.MIGRATIONS_DIR / name).read_text(encoding="utf-8")


@pytest.fixture()
def three(tmp_path):
    """
    A THREE-MIGRATION WORLD, built from the real first two.

    `0002` keeps the name `baseline` so that `(2, "baseline")` still resolves
    in `_GENERATION_INVARIANTS`: this set must carry the REAL generation
    invariants or every row in this file is decoration.
    """
    directory = tmp_path / "three"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "0001_schema_migrations.sql").write_text(_real("0001_schema_migrations.sql"), encoding="utf-8")
    (directory / "0002_baseline.sql").write_text(_real("0002_baseline.sql"), encoding="utf-8")
    (directory / "0003_w146_third.sql").write_text(THIRD_MIGRATION_SQL, encoding="utf-8")
    return migrate.discover(directory)


@pytest.fixture()
def dependent_three(tmp_path):
    """The same three-migration world, except that the third migration needs
    the current generation to exist in order to run at all."""
    directory = tmp_path / "dependent"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "0001_schema_migrations.sql").write_text(_real("0001_schema_migrations.sql"), encoding="utf-8")
    (directory / "0002_baseline.sql").write_text(_real("0002_baseline.sql"), encoding="utf-8")
    (directory / "0003_w146_dependent.sql").write_text(DEPENDENT_MIGRATION_SQL, encoding="utf-8")
    return migrate.discover(directory)


@pytest.fixture()
def two(three):
    """The same world one migration earlier -- the same objects, so a verdict
    that differs between `two` and `three` differs because of the SET and not
    because of the files."""
    return three[:2]


def _stamp_the_whole_set(connection, migrations) -> None:
    """
    A FORGED HISTORY THAT CLAIMS TO BE CURRENT. Real checksums, real names,
    every version in the set -- written against a database that is not at that
    generation. This is the state the broken `adopt_existing` produced, and it
    is a claim rather than evidence.
    """
    _apply(connection, {m.version: m for m in migrations}[1].sql)
    with connection.cursor() as cur:
        for migration in migrations:
            cur.execute(
                "INSERT INTO schema_migrations (version, name, checksum) VALUES (%s, %s, %s)",
                (migration.version, migration.name, migration.checksum),
            )
    connection.commit()


def _invariants_hold(connection, migrations) -> bool:
    """
    Evaluate `BASELINE_GENERATION_INVARIANTS` against this database DIRECTLY,
    without going through `inspect_state`.

    That is the point of it: `inspect_state` may return before it reaches
    them, and a row that wants to say "the generation machinery is fine, it
    simply was not consulted" cannot use the function that did not consult
    them to prove it.
    """
    baseline = {m.version: m for m in migrations}[migrate.BASELINE_VERSION]
    invariants = migrate.generation_invariants(baseline)
    assert invariants, "the baseline in this set carries no generation invariants"
    with connection.cursor() as cur:
        for invariant in invariants:
            cur.execute(f"SELECT ({invariant.expression})")
            if cur.fetchone()[0] is not True:
                connection.rollback()
                return False
    connection.rollback()
    return True


def _verdict(state) -> tuple:
    """
    The verdict as a comparable value, on BOTH channels a caller can branch
    on: the boolean, the reason string, what is pending, and whether the
    detail names the security column.

    Standing Rule 8 in the shape this mechanism takes. `ok`/`reason` alone
    cannot separate the two `schema_drift` states below -- a database missing
    a column and a database of the earlier generation -- and `reason` alone
    cannot separate a refusal that named the right object from one that named
    something else entirely.
    """
    return (
        state.ok,
        state.reason,
        state.pending,
        THE_SECURITY_COLUMN in (state.detail or ""),
    )


# ─── builders for the six states ────────────────────────────────────────────


def _state_current_generation(connection, migrations):
    """1. A correct, current-generation database with the whole set applied."""
    migrate.migrate(connection, migrations)


def _state_pre_security_generation(connection, migrations):
    """2. A real database of the EARLIER generation, untouched: no history at
    all. The fixture is `7b034e5:clinical/schema.sql` byte for byte."""
    _apply(connection, PRE_SECURITY_PATH.read_text(encoding="utf-8"))


def _state_pending_migration(connection, migrations):
    """3. Current generation, honestly built, one migration short."""
    migrate.migrate(connection, migrations[:-1])


def _state_schema_drift(connection, migrations):
    """4. Current generation, whole set applied, then ONE COLUMN removed.
    Every table still standing, so every table probe still passes."""
    migrate.migrate(connection, migrations)
    _apply(connection, "ALTER TABLE exception_events DROP COLUMN org_id CASCADE")


def _state_forged_history(connection, migrations):
    """5. The earlier generation with a history that says it is current."""
    _apply(connection, PRE_SECURITY_PATH.read_text(encoding="utf-8"))
    _stamp_the_whole_set(connection, migrations)


def _state_already_current(connection, migrations):
    """6. A database that is current and is migrated AGAIN."""
    migrate.migrate(connection, migrations)
    assert migrate.migrate(connection, migrations) == ()


THE_SIX_STATES = (
    ("correct current generation", _state_current_generation, (True, None, (), False)),
    ("pre-security generation", _state_pre_security_generation, (False, "schema_not_initialised", (1, 2, 3), False)),
    ("pending migration", _state_pending_migration, (False, "schema_migrations_pending", (3,), False)),
    ("schema drift", _state_schema_drift, (False, "schema_drift", (), True)),
    ("forged migration history", _state_forged_history, (False, "schema_drift", (), True)),
    ("already-current database", _state_already_current, (True, None, (), False)),
)


# ─── the non-vacuity precondition for everything below ──────────────────────


class TestTheThrowawaySetIsARealThreeMigrationWorld:
    def test_the_throwaway_baseline_still_carries_the_real_generation_invariants(self, three):
        """
        CATCHES: the quiet death of this entire file. `_GENERATION_INVARIANTS`
        is keyed by `(version, name)`, so a throwaway `0002_probe.sql` carries
        NOTHING and every drift row below would be satisfied by a runner whose
        generation machinery had been deleted. The set here must be the real
        one, bound to the real baseline bytes.

        VACUOUS AGAINST: all six states. It reads Python objects and a
        directory, never a database. That is the trade: it is the only row
        here that can fail before a container is even needed.
        """
        assert [m.version for m in three] == [1, 2, 3]
        baseline = {m.version: m for m in three}[migrate.BASELINE_VERSION]
        assert baseline.name == "baseline"
        assert migrate.generation_invariants(baseline) == migrate.BASELINE_GENERATION_INVARIANTS
        assert migrate.BASELINE_GENERATION_INVARIANTS, "the runner has no generation invariants at all"

        # the third file is a real migration with a real post-condition, not a
        # file the runner merely tolerates
        assert three[2].assertions

        # and it is genuinely a LATER migration than the baseline, which is
        # the only property that makes this a three-migration world
        assert three[2].version > migrate.BASELINE_VERSION


# ─── the demonstration the decision asked for ───────────────────────────────


class TestSixStatesRemainDiscriminated:
    def test_six_states_produce_the_verdicts_that_tell_them_apart(self, three):
        """
        THE DEMONSTRATION. Six databases, one verdict function, and the
        question is whether the verdicts still separate them once a third
        migration exists.

        CATCHES: WRONG-FIRST C -- "assert only that readiness is not ok,
        without naming the reason". Four of these six are not-ok; a row that
        asserted only that could not tell a pre-security database from a
        database that is simply behind, which is the whole substitution this
        wave exists to prevent.

        CATCHES: WRONG-FIRST B -- "relax the drift row to accept either
        reason". States 3 and 5 would then be indistinguishable, and the
        assertion below that their verdicts DIFFER is what says so.

        RULE 8. The verdict is compared on both channels together -- the
        boolean AND the reason AND what is pending AND whether the detail
        names the security column -- because states 4 and 5 share a reason and
        differ only in the rest, and states 1 and 6 share everything and must.

        RULE 4. This is not a count. Each state is asserted against its own
        expected verdict BY VALUE first; the cardinality assertions afterwards
        are a second reading of the same data, not the proof.

        VACUOUS AGAINST: `/readyz`. Every verdict here comes from the library
        call with a pinned set. The probe is proved in
        `test_w143_adoption_proves_the_generation.py`.
        """
        verdicts = {}
        for label, build, expected in THE_SIX_STATES:
            with scratch_database() as dsn, connect(dsn) as connection:
                build(connection, three)
                state = migrate.inspect_state(connection, three)
            verdicts[label] = _verdict(state)
            assert verdicts[label] == expected, f"{label}: {state.reason} / {state.detail}"

        # the two that share a reason are still told apart, and it is the
        # DETAIL and the pending set that do it
        assert verdicts["schema drift"][1] == verdicts["forged migration history"][1] == "schema_drift"

        # the two that must be indistinguishable are, and by construction:
        # "already current" is "current" migrated a second time
        assert verdicts["correct current generation"] == verdicts["already-current database"]

        # ... and the pre-security, pending and drift states are three
        # different answers, not one answer three times. This is the assertion
        # that a relaxed row fails.
        distinct = {
            verdicts["pre-security generation"],
            verdicts["pending migration"],
            verdicts["forged migration history"],
        }
        assert len(distinct) == 3, verdicts


# ─── (i) generation, separated from version ─────────────────────────────────


class TestGenerationIsDistinguishableFromMigrationVersion:
    def test_one_database_two_sets_two_version_verdicts_and_one_generation(self, two, three):
        """
        (i). ONE DATABASE, inspected against two migration sets. It is of the
        current generation either way -- that is a fact about its catalog and
        nothing about a directory listing can change it. Its VERSION verdict
        does change: complete against the two-set, behind against the
        three-set.

        CATCHES: a runner (or a proof) that answers the generation question
        out of the history table. Under the three-set this database is refused
        and the refusal is `schema_migrations_pending`, NOT `schema_drift` --
        so a reader can tell that what is wrong with it is its version and not
        its generation.

        THE POSITIVE TWIN IS IN THE SAME DATABASE, and it is the half that
        matters: the generation invariants are evaluated DIRECTLY against the
        catalog and shown to HOLD. Without it, "refused for pending" is
        equally true of a database with no `org_id` at all -- which is the
        exact confusion this wave exists to end.

        VACUOUS AGAINST: an earlier-generation database. That is the next
        class.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            migrate.migrate(connection, two)

            complete = migrate.inspect_state(connection, two)
            behind = migrate.inspect_state(connection, three)

            # the generation, read from the catalog, not from either verdict
            assert _invariants_hold(connection, three) is True

        assert complete.ok is True, complete.detail
        assert complete.pending == ()

        assert behind.ok is False
        assert behind.reason == "schema_migrations_pending"
        assert behind.pending == (3,)
        assert THE_SECURITY_COLUMN not in (behind.detail or "")
        # the same database, so the version verdict moved and nothing else did
        assert behind.current_version == complete.current_version == migrate.BASELINE_VERSION


# ─── (ii) drift, independent of how many migrations exist ───────────────────


class TestTheDriftVerdictDoesNotDependOnHowManyMigrationsExist:
    def test_the_same_wrong_generation_database_is_refused_for_drift_under_both_sets(self, two, three):
        """
        (ii). One earlier-generation database with a history forged to say
        CURRENT, inspected against a two-migration set and a three-migration
        set. Both must answer `schema_drift` and both must name
        `exception_events.org_id`.

        This is the property the w143 proof silently relied on and never
        stated. It is stated here as an equality between two verdicts, so a
        future set of any size cannot change the answer without failing this
        row.

        CATCHES: WRONG-FIRST A -- "add `migrate()` to all three rows". On THIS
        database `migrate()` would run the third migration's DDL against a
        pre-security schema: a different experiment, whose outcome has nothing
        to do with generations. The row instead makes the history complete by
        construction, which is what the forgery was always claiming.

        VACUOUS AGAINST: a database that is behind. By construction it cannot
        be -- the stamp covers the whole set, asserted through `pending`.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _apply(connection, PRE_SECURITY_PATH.read_text(encoding="utf-8"))
            _stamp_the_whole_set(connection, three)

            under_three = migrate.inspect_state(connection, three)
            # the same database, stamped past the end of the smaller set,
            # which is not pending against it either
            under_two = migrate.inspect_state(connection, two)

            # the lying rows are still there, which is the point
            with connection.cursor() as cur:
                cur.execute("SELECT version FROM schema_migrations ORDER BY version")
                stamped = [r[0] for r in cur.fetchall()]

        assert stamped == [1, 2, 3]

        assert under_three.pending == ()
        assert under_two.pending == ()
        assert under_three.reason == "schema_drift"
        assert under_two.reason == "schema_drift"
        assert THE_SECURITY_COLUMN in under_three.detail
        assert THE_SECURITY_COLUMN in under_two.detail
        # the verdict is the same verdict, not merely the same label
        assert _verdict(under_three) == _verdict(under_two)

    def test_running_the_rest_of_the_set_is_NOT_a_repair_for_the_wrong_generation(self, dependent_three):
        """
        WRONG-FIRST A, MADE CONCRETE AND MEASURED RATHER THAN ARGUED.

        The obvious repair for the three broken rows is "insert
        `migrate.migrate(connection)` after the adoption". For the two
        adoption rows it restores the meaning exactly. For the forged-history
        row it does not, and the reason is not style: that row's database is
        an EARLIER GENERATION, and the rest of the set is written against the
        current one. Here the third migration indexes
        `exception_events.org_id` -- the column the whole file is about -- and
        it CANNOT RUN. The repair does not weaken the experiment; it replaces
        it with one that raises.

        CATCHES: wrong version A. A repair that treats all three rows alike
        fails here, and it fails on the one row that carries the security
        property.

        Both halves asserted: the refusal, and that the database is unchanged
        afterwards -- the history still says exactly what the forgery said, so
        the row cannot pass because something half-applied and tidied up.

        VACUOUS AGAINST: a third migration that happens not to touch the
        current generation. That one would apply cleanly and the repair would
        look correct -- which is exactly why this must be settled by the
        experiment the row PERFORMS and not by what the next migration
        happens to contain.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _apply(connection, PRE_SECURITY_PATH.read_text(encoding="utf-8"))
            _stamp_the_whole_set(connection, dependent_three[:2])

            with pytest.raises(Exception) as excinfo:  # noqa: B017 -- psycopg raises UndefinedColumn
                migrate.migrate(connection, dependent_three)
            connection.rollback()

            assert "org_id" in str(excinfo.value)

            with connection.cursor() as cur:
                cur.execute("SELECT version FROM schema_migrations ORDER BY version")
                stamped = [r[0] for r in cur.fetchall()]
                cur.execute("SELECT to_regclass('w146_dependent_idx')")
                index_created = cur.fetchone()[0]
            connection.rollback()

            # ... whereas the repair this file uses reaches the verdict the
            # row was written to get, on the same database
            state = migrate.inspect_state(connection, dependent_three[:2])

        assert stamped == [1, 2]
        assert index_created is None
        assert state.reason == "schema_drift"
        assert THE_SECURITY_COLUMN in state.detail


# ─── (iii) precedence, asserted in both directions ──────────────────────────


class TestThePrecedenceTheProofDependsOn:
    def test_a_database_that_is_not_behind_gets_the_generation_verdict(self, three):
        """
        (iii), the direction the proof RELIES ON, stated so that a reordering
        of `inspect_state`'s questions turns something red.

        A wrong-generation database whose history is complete gets
        `schema_drift`. If the pending question were ever moved after the
        catalog question, or the catalog question removed, this row fails.

        Its twin is the next one, which shows the same database answering the
        OTHER reason when it is behind -- so neither row can be read as a
        claim that ordering does not matter. It does, and that is why every
        generation row in this repository must be written against a database
        that is not behind.

        CATCHES: wrong version B -- "relax the row to accept either reason" --
        measured: under a runner with `BASELINE_GENERATION_INVARIANTS`
        emptied, the B form of this row is GREEN and this one is red.

        VACUOUS AGAINST: the checksum verdict and `schema_not_initialised`;
        this database has a complete, checksum-correct history by
        construction.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _apply(connection, PRE_SECURITY_PATH.read_text(encoding="utf-8"))
            _stamp_the_whole_set(connection, three)
            state = migrate.inspect_state(connection, three)

        assert state.pending == ()
        assert state.ok is False
        assert state.reason == "schema_drift"
        assert THE_SECURITY_COLUMN in state.detail

    def test_a_database_that_is_behind_gets_the_cheaper_verdict_instead(self, three):
        """
        (iii), the direction that makes the other one meaningful -- AND THE
        HAZARD, WRITTEN DOWN AS A TEST RATHER THAN AS A COMMENT.

        The SAME earlier-generation database, stamped only as far as the
        baseline, is refused for `schema_migrations_pending` and the catalog
        is never read: the detail does NOT name the security column, even
        though the column is genuinely missing.

        THIS ROW IS THE PROOF THAT THE VACUITY IS REAL. It is not an argument
        that the runner is wrong -- the ordering is correct, and you cannot
        evaluate migration 3's post-conditions before migration 3 has run. It
        is the demonstration that a generation row written against a
        partially-stamped database would be certifying the cheap refusal, and
        would stay green with every generation invariant deleted.

        RULE 4: the absence assertion (`org_id` is NOT named) is paired with
        the positive one in the row above, on a database built the same way
        and differing only in how far the forgery reaches.

        CATCHES: wrong version C -- "assert only that readiness is not ok,
        without naming the reason". This database and the one above are BOTH
        not-ok; a row that asserted only that could not tell them apart, and
        the whole of this file's subject lies in the difference.

        VACUOUS AGAINST: the runner. Nothing here is a defect in
        `inspect_state` -- the ordering it asserts is the correct one. It is a
        statement about what a TEST may conclude from a refusal.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            _apply(connection, PRE_SECURITY_PATH.read_text(encoding="utf-8"))
            _stamp_the_whole_set(connection, three[:2])
            state = migrate.inspect_state(connection, three)

            # and the database really is of the wrong generation -- measured
            # from the catalog, not inferred from the verdict that did not
            # look
            generation_is_wrong = _invariants_hold(connection, three) is False

        assert generation_is_wrong
        assert state.ok is False
        assert state.reason == "schema_migrations_pending"
        assert state.pending == (3,)
        assert THE_SECURITY_COLUMN not in (state.detail or "")


# ─── (iv) the twin `schema_migrations_pending` never had ────────────────────


class TestEveryRefusalHasAMeaningfulTwin:
    def test_pending_on_a_RIGHT_generation_database_is_the_twin_of_drift(self, three):
        """
        (iv), and it is Rule 4 applied to a `reason` string.

        `schema_migrations_pending` had no positive twin anywhere in this
        repository: nothing asserted that a database refused for being behind
        is otherwise SOUND. Without that, "pending" is equally the answer for
        a database whose generation machinery is broken, unreached, or gone --
        and the natural repair of the w143 rows would have been exactly that
        confusion, made permanent and green.

        So: current generation, honestly built, one migration short. Refused
        for `pending`. And the nine generation invariants are evaluated
        against its catalog DIRECTLY and every one of them holds.

        CATCHES: WRONG-FIRST D -- "a twin case that asserts the ABSENCE of a
        refusal with no positive counterpart". A row that asserted only
        "pending does not mention org_id" is satisfied by a runner with no
        invariants at all. The direct catalog evaluation is the counterpart
        that such a runner fails.

        VACUOUS AGAINST: the checksum verdict, which has its own row in
        `test_w126m_migration_mechanism.py`.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            migrate.migrate(connection, three[:2])
            state = migrate.inspect_state(connection, three)
            sound = _invariants_hold(connection, three)

        assert sound is True
        assert state.ok is False
        assert state.reason == "schema_migrations_pending"
        assert state.pending == (3,)
        assert state.current_version == migrate.BASELINE_VERSION
        assert THE_SECURITY_COLUMN not in (state.detail or "")

    def test_the_third_migration_completes_that_same_database_and_it_becomes_ok(self, three):
        """
        The positive end of the same story, and the reason the row above is a
        refusal about VERSION rather than about anything else: apply the
        missing migration and the identical database is ok.

        CATCHES: a `pending` verdict that is really a permanent refusal in
        disguise, and a third migration that cannot actually be applied to a
        baseline-generation database -- which is the assumption every future
        `0003` will rest on.

        CATCHES: wrong version D in its second form -- a twin that asserts
        only an absence. "Pending does not name org_id" is satisfied by a
        machine that never looks; "apply the migration and the same database
        becomes ok" is not.

        VACUOUS AGAINST: everything about generations. The database here is of
        the right generation throughout, which is what makes it the twin
        rather than the subject.
        """
        with scratch_database() as dsn, connect(dsn) as connection:
            migrate.migrate(connection, three[:2])
            assert migrate.inspect_state(connection, three).ok is False

            assert migrate.migrate(connection, three) == (3,)

            state = migrate.inspect_state(connection, three)
            with connection.cursor() as cur:
                cur.execute("SELECT to_regclass('w146_third_migration')")
                created = cur.fetchone()[0]
            connection.rollback()

        assert created is not None
        assert state.ok is True, state.detail
        assert state.pending == ()
        assert state.current_version == 3
