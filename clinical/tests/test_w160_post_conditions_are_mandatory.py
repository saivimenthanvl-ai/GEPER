"""
clinical/tests/test_w160_post_conditions_are_mandatory.py
─────────────────────────────────────────────────────────
w160 — THE HUMAN'S RULING, AS BEHAVIOUR: "EVERY migration MUST declare at least
ONE checkable post-condition. A migration declaring zero post-conditions is NOT
allowed. The migration/readiness mechanism must be able to verify that."

WHERE THE REFUSAL LIVES, AND WHY IT IS NOT THE OTHER TWO CANDIDATES. The
question was asked explicitly and answered from the code rather than assumed.

  * `inspect_state()` — CHOSEN, and it carries the ruling's verifiability
    half. `clinical/schema.sql` STAMPS the migration history itself, in its own
    transaction, so a FRESH database reaches the current version without
    `migrate()` ever being called. `inspect_state` is the ONE chokepoint both
    the fresh path and the upgrade path cross; it is what `/readyz` calls on
    every probe and what the CLI prints for every verdict. A refusal here
    therefore also sees the database nobody is migrating today — one stamped by
    a build of the runner that predates the ruling — which is the case with
    nothing pending, and so the case `migrate()` can never reach.

  * `discover()` — REJECTED, and it costs two specific things. (1) It breaks
    `--status`, which `clinical/migrate.py::main` deliberately exempts from a
    non-zero exit because it is a QUERY: `discover()` raising would escape as a
    `MigrationError`, `main` would return 2, and an operator asking what a
    database is at would get an error instead of an answer. (2) `/readyz` wraps
    `inspect_state` in its own `try` and reports only the exception TYPE
    (clinical/app.py), never its text — so the 503 would read
    `schema_state_unreadable` / `MigrationSetError` and would not name the
    migration. Both costs are asserted below, not argued.

  * `migrate()` — CHOSEN AS WELL, but it could not be the only place. It
    refuses before the advisory lock so nothing is applied, which is what "is
    NOT allowed" should mean for a deployment. It cannot see a fresh database
    (see above) and it cannot see a database that is already stamped, because
    such a database has nothing pending and `migrate()` is never run against
    it.

BOTH CHANNELS SATISFY THE RULE, and that is load-bearing rather than generous.
`0001_schema_migrations` holds a `MIGRATION-ASSERT` header line and NO
`_GENERATION_INVARIANTS` entry; `0002_baseline`'s strongest post-conditions can
only live in the map, because its bytes are frozen by the `schema.sql` stamp
and adding a comment would change its checksum. A rule keyed on map membership
alone rejects `0001`; one keyed on the file alone under-reads `0002`. Asserted
below against the real directory, not asserted from this paragraph.

WRONG-FIRST, AND WHICH ROW CATCHES WHICH. Each row also states what it is
VACUOUS against, because a guard nobody has seen fail is decoration.

  A  the guard accepts a migration declaring nothing
     → TestAMigrationThatDeclaresNothingIsRefused (all three rows)
  B  the refusal keyed on `_GENERATION_INVARIANTS` membership alone, which
     must reject 0001
     → TestBothChannelsSatisfyTheRule::test_0001_declares_only_in_its_header_and_is_not_rejected
  C  refusal at discover(), breaking --status
     → TestStatusIsStillAQuery (both rows)
  D  a post-condition syntactically present but unverifiable — declared and
     never evaluated
     → TestADeclarationThatCannotBeEvaluatedIsNotADeclaration, and
       structurally by
       TestTheDeclarationAndTheEvaluationReadOneCollection
  E  the readiness probe still reporting healthy for a zero-post-condition
     migration
     → TestReadinessRefusesAnUnverifiableMigration

NO FILE IS CREATED UNDER `clinical/migrations/`. Every negative case is a
synthetic set in `tmp_path`, built by COPYING the real directory's bytes and
adding one file, so the day a real 0005 lands these build a six-migration
world. The suite discovers throwaway sets that also number files 0002, which is
why `_GENERATION_INVARIANTS` is keyed by `(version, name)`; nothing here
monkeypatches that map except the one row whose subject IS the map.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from clinical import migrate
from clinical.tests.migration_db import connect, scratch_database

# The prohibited shape: a plausible migration that declares nothing. An empty
# file would be caught by other rows for other reasons.
SILENT_SQL = "CREATE TABLE w160_silent (note TEXT PRIMARY KEY);\n"

# The legitimate twin, ONE LINE different.
DECLARED_SQL = "-- MIGRATION-ASSERT: to_regclass('w160_silent') IS NOT NULL\n" + SILENT_SQL

# Declared, and the declaration cannot be evaluated: `w160_no_such_function`
# does not exist, so the expression raises rather than returning false. This is
# wrong-first D — a post-condition that is syntactically present and measures
# nothing.
UNRUNNABLE_SQL = "-- MIGRATION-ASSERT: w160_no_such_function('w160_silent')\n" + SILENT_SQL

# Declared, evaluable, and FALSE: the object it names is never created. The
# control that separates "cannot be checked" from "checked and wrong" -- two
# different findings that must not collapse into one another.
FALSE_SQL = "-- MIGRATION-ASSERT: to_regclass('w160_never_created') IS NOT NULL\n" + SILENT_SQL

SILENT_NAME = "w160_extra"


def _synthetic_set(root: pathlib.Path, body: str) -> pathlib.Path:
    """
    The REAL migration set plus one extra file, in `tmp_path`.

    Copied by BYTES and discovered rather than named, so this helper does not
    hard-code today's set. NO FILE IS CREATED UNDER `clinical/migrations/`.
    """
    directory = root / "migrations"
    directory.mkdir(parents=True)
    for path in sorted(migrate.MIGRATIONS_DIR.iterdir()):
        if path.is_file():
            (directory / path.name).write_bytes(path.read_bytes())
    highest = max(m.version for m in migrate.discover())
    (directory / f"{highest + 1:04d}_{SILENT_NAME}.sql").write_text(body, encoding="utf-8")
    return directory


def _extra(migrations):
    return max(migrations, key=lambda m: m.version)


def _restamp_as(connection, migration) -> None:
    """
    Rewrite this migration's history row so it records `migration`'s OWN
    checksum and name.

    WHY ANY ROW THAT VERIFIES AGAINST A DIFFERENT FILE NEEDS THIS. The only way
    to reach "a database already stamped at an undeclared migration" is to
    build it with the DECLARED twin and then verify against the SILENT one --
    `migrate` refuses to build it directly. But those are two different files,
    so their checksums differ, and `schema_migration_checksum_mismatch` would
    catch the silent set too. A row that did not correct for that would be
    green for the wrong reason: it would prove the checksum check works, which
    was never in doubt, and would say nothing about the declaration rule.
    MEASURED: with the declaration refusal sabotaged, those rows reported
    `schema_migration_checksum_mismatch` rather than passing -- the confound
    was real and visible.

    Restamping makes the history exactly what an OLDER BUILD OF THIS RUNNER
    would have written for the silent file, which is the situation being
    tested, and leaves question 0 as the only question that can fail.
    """
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {migrate.HISTORY_TABLE} SET name = %s, checksum = %s WHERE version = %s",
            (migration.name, migration.checksum, migration.version),
        )
    connection.commit()


# ═══════════════════════════════════════════════════════════════════════════
# THE REAL DIRECTORY IS UNTOUCHED — asserted first, because every row below
# would be a different test if it were not
# ═══════════════════════════════════════════════════════════════════════════


class TestTheRealMigrationSetIsUntouchedAndAlreadyCompliant:
    """
    STRUCTURAL, and these rows take NO database fixture — Rule 10. A claim
    about the FILES must not be able to skip; a row that took `world` or
    `client` here would skip without `CLINICAL_TEST_DSN` and a skip and a pass
    are the same green dot.
    """

    def test_every_migration_on_disk_satisfies_the_ruling(self):
        """
        THE RULING, ASSERTED AGAINST THE REPOSITORY. Measured, not quoted: the
        brief said the four files carry 1/5/5/3 header lines; they carry
        1/5/4/2. The conclusion is unchanged — every one declares at least one
        — and the count is not asserted anywhere, deliberately, because a count
        in a test is the decay this floor keeps paying for.

        CATCHES: a migration added without a declaration, on the day it is
        added rather than on the day someone deploys it.

        VACUOUS AGAINST: declaration STRENGTH. `SELECT true` satisfies it.
        """
        discovered = migrate.discover()
        assert discovered, "discover() found nothing -- the assertion below would be vacuous"
        assert migrate.undeclared(discovered) == ()

    def test_the_synthetic_sets_create_no_file_under_the_real_directory(self, tmp_path):
        before = sorted(p.name for p in migrate.MIGRATIONS_DIR.iterdir())
        _synthetic_set(tmp_path, SILENT_SQL)
        assert sorted(p.name for p in migrate.MIGRATIONS_DIR.iterdir()) == before

    def test_the_synthetic_set_really_is_the_real_set_plus_one(self, tmp_path):
        """NON-VACUITY of the helper every negative row depends on. A helper
        that silently built a one-file world would make each refusal below
        pass while proving nothing about a realistic set."""
        discovered = migrate.discover(_synthetic_set(tmp_path, SILENT_SQL))
        real = migrate.discover()
        assert [m.version for m in discovered] == [m.version for m in real] + [max(m.version for m in real) + 1]
        assert [m.checksum for m in discovered][:-1] == [m.checksum for m in real]


# ═══════════════════════════════════════════════════════════════════════════
# WRONG-FIRST B — both channels satisfy the rule, and 0001 is not rejected
# ═══════════════════════════════════════════════════════════════════════════


class TestBothChannelsSatisfyTheRule:
    """Structural. No database fixture — Rule 10."""

    def test_0001_declares_only_in_its_header_and_is_not_rejected(self):
        """
        WRONG-FIRST B, and `0001_schema_migrations` is the witness the whole
        design turns on. It carries a `MIGRATION-ASSERT` line and NO
        `_GENERATION_INVARIANTS` entry. A refusal keyed on map membership alone
        would reject it — a legitimate, frozen, already-deployed migration —
        and the first symptom would be every existing database reported not
        ready.

        Both halves are asserted, so the row cannot pass because 0001 quietly
        gained a map entry.

        VACUOUS AGAINST: the map-only channel, which is the row below.
        """
        first = next(m for m in migrate.discover() if m.version == 1)
        assert first.assertions, "0001 lost its header declaration"
        assert migrate.generation_invariants(first) == (), (
            "0001 gained a _GENERATION_INVARIANTS entry -- this row no longer witnesses "
            "the header-only channel; find another migration that does, do not delete it"
        )
        assert migrate.undeclared([first]) == ()
        assert len(migrate.post_conditions(first)) == len(first.assertions)

    def test_the_baseline_declares_in_both_and_the_map_half_is_read(self):
        """
        THE OTHER CHANNEL. `0002_baseline`'s generation invariants live in the
        module because its bytes are frozen by the `schema.sql` stamp. A rule
        that read only the file would under-read it.

        VACUOUS AGAINST: a migration declaring ONLY in the map, which is the
        row below.
        """
        baseline = next(m for m in migrate.discover() if m.version == migrate.BASELINE_VERSION)
        assert baseline.assertions
        assert migrate.generation_invariants(baseline)
        assert len(migrate.post_conditions(baseline)) == len(baseline.assertions) + len(
            migrate.generation_invariants(baseline)
        )

    def test_a_migration_declaring_only_in_the_map_satisfies_the_rule(self, tmp_path, monkeypatch):
        """
        THE MAP-ONLY CHANNEL, which no migration on disk exercises today. A
        rule that read only the FILE would reject this, and it is exactly how
        `0002_baseline` would have to declare if it had no header lines.

        Keyed by `(version, name)` — asserted by patching that key and no
        other.
        """
        discovered = migrate.discover(_synthetic_set(tmp_path, SILENT_SQL))
        extra = _extra(discovered)
        assert migrate.undeclared(discovered) == (f"{extra.version:04d}_{extra.name}",)

        patched = dict(migrate._GENERATION_INVARIANTS)
        patched[(extra.version, extra.name)] = (migrate._table_invariant("w160_silent"),)
        monkeypatch.setattr(migrate, "_GENERATION_INVARIANTS", patched)

        assert migrate.undeclared(discovered) == ()
        assert len(migrate.post_conditions(extra)) == 1


# ═══════════════════════════════════════════════════════════════════════════
# WRONG-FIRST D — the declaration and the evaluation are ONE collection
# ═══════════════════════════════════════════════════════════════════════════


class TestTheDeclarationAndTheEvaluationReadOneCollection:
    """
    WRONG-FIRST D, CAUGHT STRUCTURALLY RATHER THAN BY EXAMPLE. "Declared but
    never evaluated" is possible whenever the thing that COUNTS declarations
    and the thing that EVALUATES them are two separate readers: the counter
    sees one, the evaluator iterates a different list, the migration passes the
    refusal and readiness measures nothing. Read from the AST, because three
    guards on this floor have fired on prose — a docstring mentioning
    `generation_invariants` is not a call to it.

    VACUOUS AGAINST: an evaluator that iterates the right collection and
    mis-evaluates it. That is the behavioural row in the class below.
    """

    def _function(self, name: str) -> ast.FunctionDef:
        source = pathlib.Path(migrate.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=migrate.__file__)
        found = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
        assert len(found) == 1, f"expected exactly one def {name}, found {len(found)}"
        return found[0]

    def _calls(self, node: ast.AST) -> set:
        return {
            child.func.id
            for child in ast.walk(node)
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
        }

    def test_the_evaluator_iterates_post_conditions(self):
        assert "post_conditions" in self._calls(self._function("_failed_assertions"))

    def test_the_refusal_counts_post_conditions(self):
        assert "post_conditions" in self._calls(self._function("undeclared"))

    def test_neither_reads_a_channel_directly_behind_the_other_s_back(self):
        """
        THE ACTUAL PROHIBITION. If either one reached past `post_conditions`
        into a single channel, the two could disagree about what "declared"
        means. `post_conditions` itself is the one place allowed to.
        """
        for name in ("_failed_assertions", "undeclared"):
            assert "generation_invariants" not in self._calls(self._function(name)), name
        assert "generation_invariants" in self._calls(self._function("post_conditions"))

    def test_the_ast_reader_is_not_vacuous(self):
        """
        Rule 4. Every row above is shaped "the name is / is not in a set", and
        that shape is satisfied by a reader that returns nothing at all.
        """
        assert self._calls(self._function("_failed_assertions")), "the AST reader found no calls"
        with pytest.raises(AssertionError):
            self._function("w160_no_such_function_in_migrate_py")


# ═══════════════════════════════════════════════════════════════════════════
# WRONG-FIRST A — a migration declaring nothing is refused
# ═══════════════════════════════════════════════════════════════════════════


class TestAMigrationThatDeclaresNothingIsRefused:
    """THE MISSING POST-CONDITION CASE the human's list names."""

    def test_migrate_refuses_and_applies_nothing(self, tmp_path):
        """
        WRONG-FIRST A, at the deployment. The refusal is asserted by TYPE and
        by CONTENT — "it raised" is satisfied by a runner that raises for any
        reason at all — and then against the DATABASE, because a refusal that
        arrived after half the set was applied would also raise.

        VACUOUS AGAINST: a database somebody else already stamped; `migrate`
        never sees one. That is `TestReadinessRefusesAnUnverifiableMigration`.
        """
        five = migrate.discover(_synthetic_set(tmp_path, SILENT_SQL))
        extra = _extra(five)

        with scratch_database("w160_refuse") as dsn, connect(dsn) as connection:
            with pytest.raises(migrate.MigrationNotVerifiable) as excinfo:
                migrate.migrate(connection, five)
            connection.rollback()

            assert not migrate.history_table_exists(connection)
            assert not migrate.schema_is_present(connection)

        assert f"{extra.version:04d}_{extra.name}" in str(excinfo.value)
        assert "Nothing was applied." in str(excinfo.value)

    def test_the_positive_twin_one_header_line_and_the_same_set_applies(self, tmp_path):
        """
        THE LEGITIMATE TWIN, ONE LINE DIFFERENT. Without it the row above
        passes against a runner that refuses every set — which would also
        apply nothing, and would also be useless.

        This is the VALID MIGRATION WITH A REAL POST-CONDITION case, and the
        post-condition is real rather than `SELECT true`: the row below drops
        its object and the verdict changes.
        """
        five = migrate.discover(_synthetic_set(tmp_path, DECLARED_SQL))

        with scratch_database("w160_allow") as dsn, connect(dsn) as connection:
            applied = migrate.migrate(connection, five)
            state = migrate.inspect_state(connection, five)
            connection.rollback()

        assert applied == tuple(m.version for m in five)
        assert state.ok is True, state.detail
        assert state.pending == ()

    def test_adopt_existing_refuses_an_unverifiable_set(self, tmp_path):
        """
        ADOPTION IS THE PATH WHERE POST-CONDITIONS ARE THE ONLY EVIDENCE: it
        STAMPS the baseline rather than running it, so an undeclared migration
        in the set means a version recorded on nothing at all.

        Asserted against the database as well as the exception: adoption
        applies migration 1 for real, so a refusal that arrived too late would
        leave a history table behind.
        """
        five = migrate.discover(_synthetic_set(tmp_path, SILENT_SQL))
        baseline_sql = next(m for m in five if m.version == migrate.BASELINE_VERSION).sql

        with scratch_database("w160_adopt") as dsn, connect(dsn) as connection:
            with connection.cursor() as cur:
                cur.execute(baseline_sql)
            connection.commit()
            assert migrate.schema_is_present(connection)

            with pytest.raises(migrate.MigrationNotVerifiable):
                migrate.adopt_existing(connection, five)
            connection.rollback()

            assert not migrate.history_table_exists(connection)


# ═══════════════════════════════════════════════════════════════════════════
# WRONG-FIRST D — a declaration that cannot be evaluated is not a declaration
# ═══════════════════════════════════════════════════════════════════════════


class TestADeclarationThatCannotBeEvaluatedIsNotADeclaration:
    """
    THE INVALID POST-CONDITION CASE the human's list names, and it is the
    behavioural half of wrong-first D: a header line that PARSES, counts as a
    declaration, satisfies the refusal above, and measures nothing because it
    cannot run.
    """

    def test_an_unevaluable_post_condition_is_reported_not_verifiable(self, tmp_path):
        """
        CATCHES: the runner letting the server's error escape. Before this
        wave a malformed expression raised out of `inspect_state`, and
        `/readyz` — which reports the exception TYPE and never its text —
        answered `schema_state_unreadable` naming a class, with nothing to say
        which migration or which expression.

        VACUOUS AGAINST: an expression that runs and returns the wrong answer,
        which is `schema_drift` and is the row after next.
        """
        five = migrate.discover(_synthetic_set(tmp_path, UNRUNNABLE_SQL))
        extra = _extra(five)
        assert migrate.undeclared(five) == (), "the unrunnable header must still COUNT as a declaration"

        with scratch_database("w160_unrunnable") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, five)
            state = migrate.inspect_state(connection, five)
            connection.rollback()

        assert state.ok is False
        assert state.reason == "schema_migration_not_verifiable"
        assert str(extra.version) in (state.detail or "")
        assert "w160_no_such_function" in (state.detail or "")

    def test_the_bad_expression_does_not_poison_the_caller_s_transaction(self, tmp_path):
        """
        THE SAVEPOINT, PROVED RATHER THAN ASSERTED FROM THE SOURCE. A failed
        statement aborts a Postgres transaction, so without the savepoint the
        connection would be unusable afterwards and every later read would
        raise InFailedSqlTransaction — the damage landing far from its cause.
        The proof is that the SAME connection answers a real query afterwards.
        """
        five = migrate.discover(_synthetic_set(tmp_path, UNRUNNABLE_SQL))

        with scratch_database("w160_savepoint") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, five)
            migrate.inspect_state(connection, five)

            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM schema_migrations")
                assert cur.fetchone()[0] == len(five)
            connection.rollback()

    def test_a_post_condition_that_runs_and_is_false_is_schema_drift_not_unverifiable(self, tmp_path):
        """
        THE DISCRIMINATOR, and it is why the two findings are not collapsed.
        "This database is wrong" and "this repository's post-condition is
        wrong" send an operator to different places. A single reason for both
        would make the verdict useless for the only thing a verdict is for.
        """
        five = migrate.discover(_synthetic_set(tmp_path, FALSE_SQL))

        with scratch_database("w160_false") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, five)
            state = migrate.inspect_state(connection, five)
            connection.rollback()

        assert state.ok is False
        assert state.reason == "schema_drift"
        assert "w160_never_created" in (state.detail or "")


# ═══════════════════════════════════════════════════════════════════════════
# WRONG-FIRST C — the refusal is not in discover(), and --status still answers
# ═══════════════════════════════════════════════════════════════════════════


class TestStatusIsStillAQuery:
    """
    WRONG-FIRST C. `clinical/migrate.py::main` exempts `--status` from a
    non-zero exit on purpose: it is a QUERY, and an operator asking what a
    database is at has not failed by getting an answer. A refusal raised from
    `discover()` would escape as a `MigrationError`, `main` would return 2, and
    the exemption would be gone — silently, because the verdict text would
    still look plausible.
    """

    def test_discover_still_returns_an_undeclared_migration(self, tmp_path):
        """
        THE PLACEMENT, ASSERTED DIRECTLY. `discover()` reads the FILES; it must
        keep reporting what is on disk. If this row ever goes red because
        `discover` learned to refuse, `--status` is broken and the row below
        will say so too.
        """
        five = migrate.discover(_synthetic_set(tmp_path, SILENT_SQL))
        assert len(five) == len(migrate.discover()) + 1
        assert migrate.undeclared(five) != ()

    def test_status_exits_zero_and_names_the_verdict(self, tmp_path, monkeypatch, capsys):
        """
        THE EXEMPTION, END TO END, through the entry point a deploy runs.
        Asserted on the OUTPUT as well as the code: a `--status` that exited 0
        while printing nothing useful would satisfy half of this.

        Uses the REAL migration set, because `main()` discovers for itself —
        which is the honest test of the CLI, and it shows the exemption is
        intact for the ordinary case.

        VACUOUS AGAINST: `--migrate`, which must NOT exit zero. Next row.
        """
        with scratch_database("w160_status") as dsn:
            monkeypatch.setenv("CLINICAL_BOOTSTRAP_DSN", dsn)
            code = migrate.main(["--status"])
            out = capsys.readouterr().out

        assert code == 0
        assert "schema_not_initialised" in out

    def test_status_still_exits_zero_on_an_UNVERIFIABLE_set_and_names_it(self, tmp_path, monkeypatch, capsys):
        """
        THE ROW THAT ACTUALLY CATCHES WRONG-FIRST C, and it is here because the
        row above does NOT. Measured: with the refusal moved into `discover()`,
        `--status` over the REAL set still exits 0 (every real migration
        declares, so `discover` never raises) — so the ordinary-case row stays
        green while the exemption is broken for exactly the input that
        provokes it. Only a `--status` over an UNVERIFIABLE set can see it.

        `discover()` raising would escape `inspect_state`, reach `main`'s
        `except MigrationError`, and return 2. As a VERDICT it returns 0 and
        prints the reason, which is what an operator diagnosing the problem
        needs.

        VACUOUS AGAINST: the refusal's content on the migrate path — that is
        the row below.
        """
        directory = _synthetic_set(tmp_path, SILENT_SQL)
        monkeypatch.setattr(migrate, "MIGRATIONS_DIR", directory)

        with scratch_database("w160_status_bad") as dsn:
            monkeypatch.setenv("CLINICAL_BOOTSTRAP_DSN", dsn)
            code = migrate.main(["--status"])
            out = capsys.readouterr().out

        assert code == 0, "--status is a QUERY and must stay usable in a shell pipeline"
        assert "schema_migration_not_verifiable" in out
        assert SILENT_NAME in out

    def test_migrate_exits_non_zero_on_an_unverifiable_set(self, tmp_path, monkeypatch, capsys):
        """
        THE POSITIVE TWIN for the row above: the deploy path DOES fail. Pointed
        at a synthetic directory through `MIGRATIONS_DIR`, because `main()`
        takes no directory argument and the alternative would be creating a
        file under `clinical/migrations/`, which this wave does not do.

        Exit 2 rather than 3: the CLI already distinguishes "the runner
        refused" (a `MigrationError`, 2) from "it ran and the database is still
        not right" (3), and an unverifiable migration set is the former --
        nothing was applied.
        """
        directory = _synthetic_set(tmp_path, SILENT_SQL)
        monkeypatch.setattr(migrate, "MIGRATIONS_DIR", directory)

        with scratch_database("w160_cli") as dsn:
            monkeypatch.setenv("CLINICAL_BOOTSTRAP_DSN", dsn)
            code = migrate.main(["--migrate"])
            err = capsys.readouterr().err

        assert code == 2
        assert "declare no catalog post-condition" in err
        assert f"{SILENT_NAME}" in err


# ═══════════════════════════════════════════════════════════════════════════
# WRONG-FIRST E — readiness
# ═══════════════════════════════════════════════════════════════════════════


class TestReadinessRefusesAnUnverifiableMigration:
    """
    WRONG-FIRST E, AND IT IS THE CASE `migrate()` STRUCTURALLY CANNOT SEE: a
    database that is ALREADY STAMPED at the undeclared version. It has nothing
    pending, so nobody runs `migrate` against it; only `inspect_state` ever
    looks at it again. This is not a contrivance — it is a database stamped by
    a build of this runner that predates the ruling, running under one that
    carries it.

    Reached by building with the DECLARED twin and verifying against the SILENT
    one, since `migrate` now refuses to create the state directly. The two sets
    differ in ONE header line, asserted, so the row is not comparing two
    unrelated worlds.
    """

    def test_a_stamped_database_at_a_silent_migration_is_not_ready(self, tmp_path):
        silent = migrate.discover(_synthetic_set(tmp_path / "silent", SILENT_SQL))
        declared = migrate.discover(_synthetic_set(tmp_path / "declared", DECLARED_SQL))

        assert [m.version for m in silent] == [m.version for m in declared]
        assert [m.name for m in silent] == [m.name for m in declared]
        assert migrate.undeclared(silent) != () and migrate.undeclared(declared) == ()

        with scratch_database("w160_ready") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, declared)
            healthy = migrate.inspect_state(connection, declared)

            # The history now says exactly what an older build of this runner
            # would have written for the SILENT file, so the checksum check
            # cannot fire and question 0 is the only one left.
            _restamp_as(connection, _extra(silent))
            verdict = migrate.inspect_state(connection, silent)
            connection.rollback()

        assert healthy.ok is True, healthy.detail
        assert verdict.ok is False, "readiness still reports healthy for a zero-post-condition migration"
        assert verdict.reason == "schema_migration_not_verifiable"
        assert f"{SILENT_NAME}" in (verdict.detail or "")

    def test_the_readyz_probe_itself_answers_503_and_names_the_reason(self, tmp_path, monkeypatch):
        """
        THE PRODUCTION PROBE, not the function behind it. `/readyz` wraps
        `inspect_state` in its own `try` and reports only the exception TYPE on
        a raise — so a refusal implemented as an EXCEPTION would have produced
        `schema_state_unreadable` here and named no migration. A refusal
        implemented as a VERDICT produces the reason and the detail. That
        difference is the whole argument for `inspect_state` over `discover`,
        and this row is where it is measured.
        """
        from fastapi.testclient import TestClient

        from clinical import app as clinical_app

        directory = _synthetic_set(tmp_path, SILENT_SQL)
        declared = migrate.discover(_synthetic_set(tmp_path / "declared", DECLARED_SQL))

        with scratch_database("w160_readyz") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, declared)
            _restamp_as(connection, _extra(migrate.discover(directory)))
            connection.commit()

            monkeypatch.setattr(migrate, "MIGRATIONS_DIR", directory)
            monkeypatch.setenv("CLINICAL_DSN", dsn)

            with TestClient(clinical_app.app) as client:
                response = client.get("/readyz")

        assert response.status_code == 503
        body = response.json()
        assert body["reason"] == "schema_migration_not_verifiable", body
        assert SILENT_NAME in body["detail"], body

    def test_the_positive_twin_the_same_probe_answers_200_when_every_migration_declares(self, tmp_path):
        """
        Rule 4. Without this the row above passes against a `/readyz` that
        answers 503 for every database, which would be a different outage.
        """
        from fastapi.testclient import TestClient

        from clinical import app as clinical_app

        with scratch_database("w160_readyz_ok") as dsn, connect(dsn) as connection:
            migrate.migrate(connection)
            connection.commit()

            with TestClient(clinical_app.app) as client:
                import os

                old = os.environ.get("CLINICAL_DSN")
                os.environ["CLINICAL_DSN"] = dsn
                try:
                    response = client.get("/readyz")
                finally:
                    if old is None:
                        os.environ.pop("CLINICAL_DSN", None)
                    else:
                        os.environ["CLINICAL_DSN"] = old

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "ready"


# ═══════════════════════════════════════════════════════════════════════════
# THE REMAINING CASES ON THE HUMAN'S LIST: fresh, historical, current,
# failure, concurrency
# ═══════════════════════════════════════════════════════════════════════════


class TestTheRulingHoldsAcrossEveryDatabaseShape:
    def test_a_fresh_database_from_schema_sql_is_still_ready(self, tmp_path):
        """
        FRESH DATABASE. `clinical/schema.sql` builds the current state and
        STAMPS the history in the same transaction — `migrate()` is never
        called on this path at all, which is the reason the refusal had to live
        in `inspect_state`. The ruling must not have broken it.
        """
        schema = (pathlib.Path(migrate.__file__).parent / "schema.sql").read_text(encoding="utf-8")
        with scratch_database("w160_fresh") as dsn, connect(dsn) as connection:
            with connection.cursor() as cur:
                cur.execute(schema)
            connection.commit()

            state = migrate.inspect_state(connection)
            connection.rollback()

        assert state.ok is True, state.detail
        assert state.pending == ()
        assert state.current_version == max(m.version for m in migrate.discover())

    def test_a_fresh_database_is_refused_when_the_code_ships_an_undeclared_migration(self, tmp_path):
        """
        THE SAME FRESH DATABASE, AND THIS IS THE ROW THAT PROVES THE PLACEMENT
        CHOICE PAID FOR SOMETHING. The database is perfect; the CODE is not.
        `migrate()` would never have been called here, so a refusal placed
        there alone would have reported this deployment ready.
        """
        schema = (pathlib.Path(migrate.__file__).parent / "schema.sql").read_text(encoding="utf-8")
        five = migrate.discover(_synthetic_set(tmp_path, SILENT_SQL))

        with scratch_database("w160_fresh_bad") as dsn, connect(dsn) as connection:
            with connection.cursor() as cur:
                cur.execute(schema)
            connection.commit()

            state = migrate.inspect_state(connection, five)
            connection.rollback()

        assert state.ok is False
        assert state.reason == "schema_migration_not_verifiable"

    def test_an_upgraded_historical_database_is_still_ready(self):
        """
        UPGRADED HISTORICAL DATABASE. Built the OTHER way — the baseline
        applied on its own and then migrated forward by the runner — and the
        data written in between must survive, which is what makes this an
        upgrade rather than a rebuild.
        """
        real = migrate.discover()
        first_two = tuple(m for m in real if m.version <= migrate.BASELINE_VERSION)

        with scratch_database("w160_historical") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, first_two)
            with connection.cursor() as cur:
                cur.execute(
                    "INSERT INTO organisations (name, created_at) VALUES (%s, now())",
                    ("w160 Historical Organisation",),
                )
            connection.commit()

            applied = migrate.migrate(connection, real)
            state = migrate.inspect_state(connection, real)

            with connection.cursor() as cur:
                cur.execute("SELECT name FROM organisations ORDER BY name")
                names = [r[0] for r in cur.fetchall()]
            connection.rollback()

        assert applied == tuple(m.version for m in real if m.version > migrate.BASELINE_VERSION)
        assert state.ok is True, state.detail
        assert names == ["w160 Historical Organisation"], names

    def test_a_current_database_is_ready_and_re_running_applies_nothing(self):
        """CURRENT DATABASE. Rule 4 shape: the absence assertion
        (`applied == ()`) is paired with the positive one that the verdict is
        ok and the frontier is derived, never a literal."""
        with scratch_database("w160_current") as dsn, connect(dsn) as connection:
            migrate.migrate(connection)
            again = migrate.migrate(connection)
            state = migrate.inspect_state(connection)
            connection.rollback()

        assert again == ()
        assert state.ok is True, state.detail
        assert state.current_version == max(m.version for m in migrate.discover())

    def test_a_migration_that_fails_still_fails_for_its_own_reason(self, tmp_path):
        """
        MIGRATION FAILURE, and the row exists because the new refusal could
        HOLLOW THIS OUT rather than break it. `migrate` now refuses an
        undeclared set before taking the lock, so a failing fixture that
        declared nothing would raise the refusal instead of running — and a
        `pytest.raises(Exception)` would swallow the difference, leaving a
        green row that proved nothing about failure at all. Measured, not
        feared: that is exactly what happened to two existing rows in this
        suite when the refusal landed, and both were repaired by giving their
        fixtures a declaration.

        So: the failing migration DECLARES, and the exception is asserted to be
        the server's rather than this module's.
        """
        history_sql = (migrate.MIGRATIONS_DIR / "0001_schema_migrations.sql").read_text(encoding="utf-8")
        directory = tmp_path / "m"
        directory.mkdir()
        (directory / "0001_history.sql").write_text(history_sql, encoding="utf-8")
        (directory / "0002_boom.sql").write_text(
            "-- MIGRATION-ASSERT: to_regclass('w160_boom') IS NOT NULL\n"
            "CREATE TABLE w160_boom (a INT);\n"
            "ALTER TABLE w160_boom ADD CONSTRAINT impossible CHECK (no_such_column > 0);\n",
            encoding="utf-8",
        )
        migrations = migrate.discover(directory)
        assert migrate.undeclared(migrations) == ()

        with scratch_database("w160_fail") as dsn, connect(dsn) as connection:
            with pytest.raises(Exception) as excinfo:  # noqa: B017 -- the server's error
                migrate.migrate(connection, migrations)
            connection.rollback()

            # NOT this module's refusal -- if it were, nothing ran and the row
            # would be measuring the wrong failure.
            assert not isinstance(excinfo.value, migrate.MigrationError), excinfo.value

            # migration 1 DID run and committed; migration 2 left nothing.
            with connection.cursor() as cur:
                cur.execute("SELECT version FROM schema_migrations ORDER BY version")
                assert [r[0] for r in cur.fetchall()] == [1]
            with connection.cursor() as cur:
                cur.execute("SELECT to_regclass('w160_boom')")
                assert cur.fetchone()[0] is None
            connection.rollback()

    def test_concurrency_the_second_runner_still_refuses_and_applies_nothing(self):
        """
        CONCURRENCY. Deterministic, never raced: A holds the advisory lock for
        the whole test, so there is no speed at which B could acquire it.

        THE POINT HERE IS THE ORDER OF THE TWO REFUSALS. The declaration check
        happens BEFORE the lock is taken, so it could have masked the lock
        refusal for every set — a runner that refused everything early would
        pass "B applied nothing" while never testing the lock at all. The set
        is fully declared, so the only reason B can fail is the lock, and the
        exception TYPE is asserted.
        """
        with scratch_database("w160_conc") as dsn:
            with connect(dsn, autocommit=True) as a, connect(dsn) as b:
                with a.cursor() as cur:
                    cur.execute("SELECT pg_advisory_lock(%s)", (migrate.ADVISORY_LOCK_KEY,))

                with pytest.raises(migrate.MigrationLockUnavailable):
                    migrate.migrate(b, lock_timeout="500ms")
                b.rollback()

                assert not migrate.history_table_exists(b)

                with a.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (migrate.ADVISORY_LOCK_KEY,))

                applied = migrate.migrate(b, lock_timeout="500ms")
                assert applied == tuple(m.version for m in migrate.discover())
                assert migrate.inspect_state(b).ok is True

    def test_concurrency_an_undeclared_set_never_reaches_the_lock(self, tmp_path):
        """
        THE OTHER ORDER, ASSERTED. An undeclared set must be refused BEFORE the
        advisory lock, not after — a runner that took the lock and then refused
        would be fine here but would serialise deploys behind a check that was
        always going to fail, and (before the `_release` fix this suite already
        carries) could leak the lock on the way out.

        Proved by OBSERVING THE SERVER's lock table while B is refused, not by
        reading the code. The instrument gets a positive control first: a count
        that is always zero proves nothing.
        """
        five = migrate.discover(_synthetic_set(tmp_path, SILENT_SQL))

        def advisory_locks_here(connection) -> int:
            with connection.cursor() as cur:
                cur.execute(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                    "AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"
                )
                return cur.fetchone()[0]

        with scratch_database("w160_conc2") as dsn:
            with connect(dsn) as runner, connect(dsn, autocommit=True) as observer:
                with observer.cursor() as cur:
                    cur.execute("SELECT pg_advisory_lock(%s)", (migrate.ADVISORY_LOCK_KEY,))
                assert advisory_locks_here(observer) == 1
                with observer.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (migrate.ADVISORY_LOCK_KEY,))
                assert advisory_locks_here(observer) == 0

                with pytest.raises(migrate.MigrationNotVerifiable):
                    migrate.migrate(runner, five)
                runner.rollback()

                assert advisory_locks_here(observer) == 0


# ═══════════════════════════════════════════════════════════════════════════
# THE GUARD SHAPE THIS FLOOR TRUSTS — the refusal proves its own subject can
# fail, in band
# ═══════════════════════════════════════════════════════════════════════════


class TestTheRefusalAssertionCanItselfFail:
    """
    THE SHAPE: widen the grant, observe SUCCESS, restore, observe the REFUSAL —
    all in one row, against one database, so neither half can rot without the
    other noticing.

    The "grant" being widened here is the DECLARATION: the same migration, the
    same DDL, the same database, with and without one header line. A refusal
    test that only ever sees the refusal is green against a runner that refuses
    everything; a permission test that only ever sees success is green against
    one that permits everything. This row sees both transitions and asserts the
    verdict flips in both directions.
    """

    def test_the_verdict_flips_both_ways_on_one_header_line(self, tmp_path):
        declared = migrate.discover(_synthetic_set(tmp_path / "wide", DECLARED_SQL))
        silent = migrate.discover(_synthetic_set(tmp_path / "narrow", SILENT_SQL))

        # The ONLY difference is the header line -- asserted, not assumed.
        wide, narrow = _extra(declared), _extra(silent)
        assert wide.version == narrow.version and wide.name == narrow.name
        assert narrow.sql in wide.sql
        assert len(wide.sql) > len(narrow.sql)

        with scratch_database("w160_flip") as dsn, connect(dsn) as connection:
            # 1. WIDENED -- observe SUCCESS.
            applied = migrate.migrate(connection, declared)
            widened = migrate.inspect_state(connection, declared)

            # 2. RESTORED -- the same database, verified against the narrow
            #    set, with the history restamped so the CHECKSUM check cannot
            #    be what fires. Observe the REFUSAL.
            _restamp_as(connection, narrow)
            restored = migrate.inspect_state(connection, silent)

            # 3. WIDENED AGAIN -- restamped back, and it is ok again, so the
            #    refusal above is not a state the database got stuck in.
            _restamp_as(connection, wide)
            again = migrate.inspect_state(connection, declared)
            connection.rollback()

        assert applied == tuple(m.version for m in declared)
        assert widened.ok is True, widened.detail
        assert restored.ok is False
        assert restored.reason == "schema_migration_not_verifiable"
        assert again.ok is True, again.detail

    def test_and_the_declared_post_condition_is_genuinely_evaluated(self, tmp_path):
        """
        THE OTHER HALF OF "CAN ITSELF FAIL". The row above proves the refusal
        responds to the DECLARATION. This one proves the declaration is not
        decoration: drop the object it names and the same `ok=True` becomes
        `schema_drift` naming it. Without this, a declaration that is never
        evaluated would pass every row in this file.

        This is the measurement the original defect was stated as, kept
        forwards: before the fix the SILENT twin stayed ok=True through exactly
        this vandalism.
        """
        declared = migrate.discover(_synthetic_set(tmp_path, DECLARED_SQL))

        with scratch_database("w160_evaluated") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, declared)
            assert migrate.inspect_state(connection, declared).ok is True

            with connection.cursor() as cur:
                cur.execute("DROP TABLE w160_silent")
            connection.commit()

            state = migrate.inspect_state(connection, declared)
            connection.rollback()

        assert state.ok is False
        assert state.reason == "schema_drift"
        assert "w160_silent" in (state.detail or "")
