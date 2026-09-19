"""
clinical/tests/test_w151_migration_declaration_guards.py
────────────────────────────────────────────────────────
w151 — TWO DIFFERENT PROBLEMS, SEPARATED, AND ONE OF THEM IS NOT SOLVED HERE.

THE FIRST PROBLEM IS A TEST-SUITE SHAPE PROBLEM: literals where a derivation
belongs. `test_w147_…` re-introduced `state.current_version == 3` after w146
removed nine instances of that shape; `test_w149_…:342` re-introduced it again
as `state.current_version == AMENDMENT_VERSION`. Every one of them asserts
"four is the HIGHEST migration", which is a claim about the SIZE of
`clinical/migrations/` written as a constant — true today, false the morning a
fifth file lands, and false in a way that reads as a broken migration rather
than as a stale test. A source-scanning guard is the right answer to this,
because the defect IS a property of the source text. `TestNoTestPinsTheFrontier`
below is that guard.

THE SECOND PROBLEM IS A PRODUCTION INTEGRITY PROBLEM AND A SOURCE SCAN IS A
WEAKER ANSWER TO IT. `clinical/migrate.py::_GENERATION_INVARIANTS` is a
hand-written `{(version, name): …}` map, so for a migration that is not in it,
*absence of a declaration is indistinguishable from a declaration that nothing
is required* — and `inspect_state` reported such a database `ok`. A fifth
migration that declares nothing therefore left `/readyz` answering 200 on a
database no one had checked. `TestEveryMigrationDeclaresAPostCondition` fails
in CI when that happens. **It does not make a deployment refuse**, and the
difference was the whole point of keeping it: CI catches a migration somebody
wrote, a deployment catches a database somebody has.

THE STOP THIS FILE RECORDED IS ANSWERED — DECISION w151-D1, RULED 2026-09-19.
w151 declined to make the runner refuse, because doing so contradicted three
places where the tree documented the declaration as OPTIONAL, and recorded the
question instead of guessing. The human then ruled: "EVERY migration MUST
declare at least ONE checkable post-condition. A migration declaring zero
post-conditions is NOT allowed." w160 implemented it, and corrected all of
those places rather than leaving them to decay:

  * `clinical/migrate.py` (the `_ASSERT` block) — said "A migration MAY state";
    now states the requirement and why either channel satisfies it.
  * `clinical/migrate.py` (the generation-invariants block) — said "a future
    migration that WANTS generation invariants"; now separates the choice of
    CHANNEL, which is free, from declaring at all, which is not.
  * `clinical/tests/test_w149_migration_0004_amendment.py` — said "Nothing
    forces a migration to declare a generation invariant."
  * `clinical/tests/test_w147_migration_0003_retraction.py` — quoted w146's
    "nothing forces a new migration to declare one". w160 found this fourth
    one; the brief named three.

WHAT REMAINS TRUE, AND IT IS THE REASON THE GUARD BELOW READS BOTH CHANNELS:
migration `0001_schema_migrations` has no `_GENERATION_INVARIANTS` entry and is
entirely correct, while `0002_baseline`'s strongest post-conditions can only
live in the map because its bytes are frozen. A rule keyed on map-membership
ALONE would reject `0001`; one keyed on the file alone would under-read
`0002`. `clinical/migrate.py::post_conditions` is now the single production
function that reads both, and `_failed_assertions` evaluates exactly what it
returns — so a migration cannot be declared to the refusal and invisible to the
evaluator.

WHAT EACH GUARD IS VACUOUS AGAINST — stated, because a guard nobody has seen
fail is decoration:

  * `TestEveryMigrationDeclaresAPostCondition` is vacuous against a migration
    that declares a post-condition which is TRIVIALLY TRUE (`SELECT true`), and
    against everything `/readyz` does at run time. It reads declarations, not
    their strength, and it is a test rather than a refusal.
  * `TestNoTestPinsTheFrontier` is vacuous against a literal frontier written
    inside a function that ALSO builds a synthetic migration set — the
    exemption that keeps the legitimate `tmp_path` rows passing is granted per
    function, not per assertion. It is also vacuous against literals that are
    not comparisons (`assert state.current_version in (3, 4)` is not a
    `Compare` against a literal int and is not flagged), and against anything
    outside `clinical/tests`.
  * The synthetic-`0005` rows are vacuous against the real
    `clinical/migrations/` directory: they build their set in `tmp_path` and no
    file is created under `clinical/migrations/` by this wave.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from clinical import migrate
from clinical.tests.migration_db import connect, scratch_database

# THE ANCHOR IS THE SHARED ONE, not a fourth path resolution. `_anchor()` names
# landmark files and raises if the tree it is reading is not this repository —
# w132 measured a real vacuous pass from a path-reading guard that found
# nothing and reported green.
from clinical.tests.test_w132_structural_guards import _anchor

# Landmarks for the TEST corpus, the same way w132 uses landmarks for the tree:
# existence assertions, not a census. A count here would be the exact defect
# this file exists to forbid.
_TEST_CORPUS_LANDMARKS = (
    "test_w126m_migration_mechanism.py",
    "test_w143_adoption_proves_the_generation.py",
    "test_w146_generation_survives_a_third_migration.py",
    "test_w147_migration_0003_retraction.py",
    "test_w149_migration_0004_amendment.py",
)

# A migration whose header declares NOTHING. This is the prohibited shape, and
# it is deliberately a plausible migration rather than an empty file: an empty
# file would be caught by half a dozen other rows for other reasons.
SILENT_FIFTH_SQL = "CREATE TABLE w151_silent_fifth (note TEXT PRIMARY KEY);\n"

# The same migration with the ONE line that makes it declared. The legitimate
# twin, and the reason the guard reads the file's own header and not only the
# module's map.
DECLARED_FIFTH_SQL = "-- MIGRATION-ASSERT: to_regclass('w151_silent_fifth') IS NOT NULL\n" + SILENT_FIFTH_SQL

SILENT_FIFTH_NAME = "silent_fifth"
SILENT_FIFTH_FILE = "0005_silent_fifth.sql"


# ═══════════════════════════════════════════════════════════════════════════
# THE DECLARATION PREDICATE — BOTH CHANNELS, and that is the point
# ═══════════════════════════════════════════════════════════════════════════


def declared_post_conditions(migration: migrate.Migration) -> tuple:
    """
    Every catalog post-condition this migration declares, from BOTH channels.

    A migration may declare in its own header (`-- MIGRATION-ASSERT:`) or in
    `clinical/migrate.py::_GENERATION_INVARIANTS`, and the two are read by the
    same `_failed_assertions` loop at run time. A guard that read only the map
    would fail on `0001_schema_migrations`, which has no map entry and is
    correct; a guard that read only the file would fail on any migration whose
    post-conditions are held in the module because its bytes are frozen. So
    this reads what the RUNNER reads, which is both.
    """
    return tuple(migration.assertions) + tuple(
        invariant.description for invariant in migrate.generation_invariants(migration)
    )


def undeclared(migrations) -> list:
    """Which of these migrations declare no catalog post-condition at all."""
    return [f"{m.version:04d}_{m.name}" for m in migrations if not declared_post_conditions(m)]


# ═══════════════════════════════════════════════════════════════════════════
# GUARD 1 — the production-integrity guard, in the form this tree supports
# ═══════════════════════════════════════════════════════════════════════════


class TestEveryMigrationDeclaresAPostCondition:
    """
    STRUCTURAL: the subject is `migrate.discover()`, which reads the directory.
    Nothing here names a file, a version or a count, so the day
    `0005_whatever.sql` is added this guard is already about it.
    """

    def test_the_guard_reads_the_directory_the_runner_reads(self):
        """
        THE ANCHOR. A guard that discovered migrations from somewhere else
        would pass while the runner read a directory nobody checked.
        """
        root = _anchor()
        assert migrate.MIGRATIONS_DIR.resolve() == (root / "clinical" / "migrations").resolve(), (
            f"the runner reads {migrate.MIGRATIONS_DIR}, this guard is anchored at {root}"
        )
        assert migrate.MIGRATIONS_DIR.is_dir()

    def test_the_discovered_set_is_not_empty(self):
        """
        NON-VACUITY, and it is an existence check rather than a count: `all()`
        over an empty tuple is True, so an empty discovery would make the row
        below pass by checking nothing.
        """
        discovered = migrate.discover()
        assert discovered, "discover() found no migrations -- the guard below would pass vacuously"
        names = {f"{m.version:04d}_{m.name}.sql" for m in discovered}
        assert "0002_baseline.sql" in names, sorted(names)

    def test_every_migration_on_disk_declares_at_least_one_catalog_post_condition(self):
        """
        THE HUMAN'S ISSUE, as far as a test can carry it.

        CATCHES: a fifth (or fiftieth) migration added with no
        `MIGRATION-ASSERT` line and no `_GENERATION_INVARIANTS` entry — the
        case where `inspect_state` has nothing to evaluate for that version and
        reports the database ready on the strength of a history row alone.

        VACUOUS AGAINST: a declaration that is trivially true, and against a
        deployment, which never runs this. See the class below for the half
        this cannot reach.
        """
        missing = undeclared(migrate.discover())
        assert not missing, (
            f"migration(s) {missing} declare no catalog post-condition in EITHER channel: no "
            "`-- MIGRATION-ASSERT:` line in the file and no entry in "
            "clinical/migrate.py::_GENERATION_INVARIANTS. `inspect_state` therefore has nothing "
            "to evaluate for them, so a database whose history row says they are applied is "
            "reported ready without anything having been measured. Declare a post-condition -- "
            "do not delete this assertion."
        )

    def test_the_predicate_reads_the_module_map_and_not_only_the_file(self):
        """
        NON-VACUITY of the predicate itself: it must see BOTH channels.
        `0002_baseline` is the witness -- its generation invariants live in the
        module, not in its (frozen) bytes.
        """
        baseline = next(m for m in migrate.discover() if m.version == migrate.BASELINE_VERSION)
        declared = declared_post_conditions(baseline)
        assert migrate.generation_invariants(baseline), "the baseline lost its generation invariants"
        assert len(declared) > len(baseline.assertions), (
            "the predicate is not reading _GENERATION_INVARIANTS; it would then pass on a "
            "migration whose only declarations are in the module"
        )


# ═══════════════════════════════════════════════════════════════════════════
# THE SYNTHETIC FIFTH MIGRATION — the case that makes guard 1 fail
# ═══════════════════════════════════════════════════════════════════════════


def _synthetic_set(tmp_path: pathlib.Path, fifth_sql: str) -> pathlib.Path:
    """
    The REAL migration set plus one fifth file, in `tmp_path`.

    Copied by BYTES from `migrate.MIGRATIONS_DIR` and copied by DISCOVERY
    rather than by name, so this helper does not itself hard-code the current
    set -- the day a real `0005` lands this builds a six-migration world.
    NO FILE IS CREATED UNDER `clinical/migrations/`.
    """
    # parents=True so a caller can build TWO sets under one tmp_path by
    # passing tmp_path / "silent" and tmp_path / "declared".
    directory = tmp_path / "migrations"
    directory.mkdir(parents=True)
    for path in sorted(migrate.MIGRATIONS_DIR.iterdir()):
        if path.is_file():
            (directory / path.name).write_bytes(path.read_bytes())
    highest = max(m.version for m in migrate.discover())
    (directory / f"{highest + 1:04d}_{SILENT_FIFTH_NAME}.sql").write_text(fifth_sql, encoding="utf-8")
    return directory


class TestTheSyntheticFifthMigration:
    """
    THE NEGATIVE CONTROL. `0003`'s derivation script proved its own refusal
    path against a pair that must be rejected; these rows do the same for the
    declaration guard. Without them the guard above has never been observed to
    fail and is decoration.
    """

    def test_a_fifth_migration_that_declares_nothing_is_caught(self, tmp_path):
        """THE PROHIBITED SHAPE, and the guard fails on it."""
        directory = _synthetic_set(tmp_path, SILENT_FIFTH_SQL)
        discovered = migrate.discover(directory)

        assert len(discovered) == len(migrate.discover()) + 1
        missing = undeclared(discovered)
        assert missing == [f"{max(m.version for m in discovered):04d}_{SILENT_FIFTH_NAME}"], missing

    def test_the_same_fifth_migration_with_one_header_line_is_not_caught(self, tmp_path):
        """
        THE LEGITIMATE TWIN, and it is one line different from the row above.
        A guard that failed here would be banning migrations rather than
        banning silence.
        """
        directory = _synthetic_set(tmp_path, DECLARED_FIFTH_SQL)
        assert undeclared(migrate.discover(directory)) == []

    def test_a_fifth_migration_declared_only_in_the_module_map_is_not_caught(self, tmp_path, monkeypatch):
        """
        THE OTHER LEGITIMATE TWIN: post-conditions held in
        `_GENERATION_INVARIANTS` and none in the file -- which is exactly how
        `0002_baseline`'s own generation invariants are held, because its bytes
        are frozen by the `schema.sql` stamp.
        """
        directory = _synthetic_set(tmp_path, SILENT_FIFTH_SQL)
        discovered = migrate.discover(directory)
        fifth = max(discovered, key=lambda m: m.version)

        patched = dict(migrate._GENERATION_INVARIANTS)
        patched[(fifth.version, fifth.name)] = (migrate._table_invariant("w151_silent_fifth"),)
        monkeypatch.setattr(migrate, "_GENERATION_INVARIANTS", patched)

        assert undeclared(discovered) == []

    def test_the_real_directory_is_untouched_by_the_synthetic_rows(self, tmp_path):
        """Rule: no file under `clinical/migrations/` is created by this wave."""
        before = sorted(p.name for p in migrate.MIGRATIONS_DIR.iterdir())
        _synthetic_set(tmp_path, SILENT_FIFTH_SQL)
        assert sorted(p.name for p in migrate.MIGRATIONS_DIR.iterdir()) == before
        assert not (migrate.MIGRATIONS_DIR / SILENT_FIFTH_FILE).exists()


class TestTheRunnerStillAnswersOkAndThatIsTheOpenDECISION:
    """
    RE-AUTHORED BY w160, WHICH IS THE WAVE THAT OWNS THE CHANGE — the class
    above asked for exactly that and the class name is kept so the history is
    followable from the commit that recorded the gap to the one that closed it.

    DECISION w151-D1 IS ANSWERED. The human ruled on 2026-09-19: "EVERY
    migration MUST declare at least ONE checkable post-condition. A migration
    declaring zero post-conditions is NOT allowed." So `inspect_state` now
    returns `schema_migration_not_verifiable` and `migrate` refuses outright,
    and the rows below are INVERTED rather than deleted — deleting them would
    remove the only live evidence that the gap was ever there, and would leave
    nothing that fails if the refusal is ever backed out.

    WHAT THE GAP WAS, as measured by w151 and reproduced by w160 before the
    fix: a fifth migration declaring nothing was applied to a scratch database,
    its table was dropped, and `inspect_state` still answered `ok=True` at
    `current_version=5`, `pending=()`. The same vandalism against a fifth
    migration carrying ONE header line was caught as `schema_drift` naming the
    object. The first two rows below are the two halves of that measurement,
    each now asserting the refusal instead of the silence.
    """

    def test_a_database_at_the_silent_fifth_migration_can_no_longer_be_created(self, tmp_path):
        """
        INVERTED. This row used to assert `state.ok is True` on a database at a
        silent fifth migration. `migrate` now refuses the set before the
        advisory lock, so the database cannot reach that state at all.

        CATCHES: wrong-first A — a guard that accepts a migration declaring
        nothing. Both channels of the refusal are asserted, the exception type
        and the named migration, because "it raised" is satisfied by a runner
        that raises for any reason at all.

        VACUOUS AGAINST: a database somebody else already stamped — nothing
        here re-reads an existing history. That is the row two below.
        """
        directory = _synthetic_set(tmp_path, SILENT_FIFTH_SQL)
        five = migrate.discover(directory)
        fifth = max(m.version for m in five)

        assert undeclared(five), "the fifth migration is not the silent one -- this row proves nothing"

        with scratch_database("w151_silent") as dsn, connect(dsn) as connection:
            with pytest.raises(migrate.MigrationNotVerifiable) as excinfo:
                migrate.migrate(connection, five)
            connection.rollback()

            # NOTHING WAS APPLIED -- the refusal is before the lock, not after
            # a partial run. Asserted against the database, not the exception.
            assert not migrate.history_table_exists(connection)
            assert not migrate.schema_is_present(connection)

            # ...and the verdict names the same thing, so /readyz says it too.
            state = migrate.inspect_state(connection, five)
            connection.rollback()

        assert f"{fifth:04d}_{SILENT_FIFTH_NAME}" in str(excinfo.value)
        assert "Nothing was applied." in str(excinfo.value)
        assert state.ok is False
        assert state.reason == "schema_migration_not_verifiable"
        assert f"{fifth:04d}_{SILENT_FIFTH_NAME}" in (state.detail or "")

    def test_the_positive_twin_a_declared_fifth_migration_is_also_healthy(self, tmp_path):
        """
        Rule 4. Without this, the row above passes against a runner that
        reports every database ok for some unrelated reason, and the
        "readiness cannot tell the difference" claim would be untested in the
        direction that matters.
        """
        directory = _synthetic_set(tmp_path, DECLARED_FIFTH_SQL)
        five = migrate.discover(directory)

        with scratch_database("w151_declared") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, five)
            state = migrate.inspect_state(connection, five)
            connection.rollback()

        assert undeclared(five) == []
        assert state.ok is True, state.detail

    def test_and_the_declared_fifth_migration_is_actually_evaluated(self, tmp_path):
        """
        THE ROW THAT MAKES THE ONE ABOVE MEAN SOMETHING, and it is the
        difference the STOP is about: a DECLARED fifth migration whose object
        is missing is caught by readiness; a SILENT one cannot be, because
        there is nothing to evaluate.
        """
        directory = _synthetic_set(tmp_path, DECLARED_FIFTH_SQL)
        five = migrate.discover(directory)

        with scratch_database("w151_drift") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, five)
            with connection.cursor() as cur:
                cur.execute("DROP TABLE w151_silent_fifth")
            connection.commit()
            declared_state = migrate.inspect_state(connection, five)
            connection.rollback()

        assert declared_state.ok is False
        assert declared_state.reason == "schema_drift"
        assert "w151_silent_fifth" in (declared_state.detail or "")

    def test_the_silent_fifth_migration_is_caught_even_on_a_database_already_stamped(self, tmp_path):
        """
        INVERTED, AND IT IS THE HALF THAT MATTERS MOST. This row used to say:
        drop the silent fifth migration's table and readiness still answers
        `ok=True` at the fifth version. "Nothing in this file can fix that;
        only the runner can" — the runner now does.

        THE DATABASE IS BUILT WITH THE DECLARED TWIN AND THEN VERIFIED AGAINST
        THE SILENT ONE, which is the only way to reach the state at all now
        that `migrate` refuses the silent set. It is also the REAL scenario
        rather than a contrivance: a database stamped by a build of this
        runner that predates the ruling, sitting under a build that carries it.
        Such a database exists in the world and `migrate` can never see it,
        because it has nothing pending — `inspect_state` is the only thing that
        can, which is exactly why the refusal lives there.

        CATCHES: wrong-first E — a readiness probe that still reports healthy
        for a zero-post-condition migration; and, with the row above, wrong-
        first C, since a refusal placed in `discover()` would have made this
        state unreachable for the wrong reason (it would also have broken
        `--status`, which is asserted separately in the w160 file).

        VACUOUS AGAINST: the strength of a declaration. A fifth migration
        declaring `SELECT true` satisfies the refusal and measures nothing;
        that limit is stated in this file's header and is not closed here.
        """
        silent = migrate.discover(_synthetic_set(tmp_path / "silent", SILENT_FIFTH_SQL))
        declared = migrate.discover(_synthetic_set(tmp_path / "declared", DECLARED_FIFTH_SQL))

        # The two sets differ in ONE header line and in nothing else: same
        # versions, same names, same DDL. Without this the row could be
        # comparing two unrelated worlds.
        assert [m.version for m in silent] == [m.version for m in declared]
        assert [m.name for m in silent] == [m.name for m in declared]
        assert undeclared(silent) and undeclared(declared) == []

        with scratch_database("w151_nodrift") as dsn, connect(dsn) as connection:
            migrate.migrate(connection, declared)
            # the database is genuinely at the fifth version and genuinely ok
            healthy = migrate.inspect_state(connection, declared)

            # THE HISTORY IS RESTAMPED with the SILENT file's own checksum, so
            # this row measures the declaration rule and not the checksum
            # check. Without it the two files differ, and
            # `schema_migration_checksum_mismatch` would fire first and make
            # the row green for a reason that has nothing to do with the
            # ruling -- measured, by sabotaging the refusal and watching it
            # report exactly that. This is also what an older build of the
            # runner would genuinely have written.
            fifth = max(silent, key=lambda m: m.version)
            with connection.cursor() as cur:
                cur.execute(
                    f"UPDATE {migrate.HISTORY_TABLE} SET name = %s, checksum = %s WHERE version = %s",
                    (fifth.name, fifth.checksum, fifth.version),
                )
            connection.commit()

            state = migrate.inspect_state(connection, silent)
            connection.rollback()

        assert healthy.ok is True, healthy.detail
        assert state.ok is False, "a stamped database at a silent migration is still reported ready"
        assert state.reason == "schema_migration_not_verifiable"
        assert f"{max(m.version for m in silent):04d}_{SILENT_FIFTH_NAME}" in (state.detail or "")


# ═══════════════════════════════════════════════════════════════════════════
# GUARD 2 — the test-suite shape guard: literals where a derivation belongs
# ═══════════════════════════════════════════════════════════════════════════

# The migration FRONTIER attribute. `MigrationState.current_version` is
# `max(applied)` -- a claim about the SIZE of the set, which is what decays.
_FRONTIER_ATTR = "current_version"

# Calls that can be handed an explicit migration set or directory, and the
# index of the argument that does it. A function that hands one of these an
# explicit set is operating on a SYNTHETIC world (`tmp_path`), where a literal
# version is a legitimate statement about a set the test itself built -- the
# brief names this case as legitimate and not to be "fixed".
_EXPLICIT_SET_ARG = {"discover": (0, "directory"), "inspect_state": (1, "migrations"), "migrate": (1, "migrations")}


def _test_corpus(root: pathlib.Path | None = None) -> list:
    """
    EVERY Python file under `clinical/tests`, derived from the directory.

    Not a glob list of `test_w1*_migration_*.py`: a guard that names the files
    it reads protects the files somebody remembered, and the next migration
    test will not be on that list. Anchored, and `__pycache__` excluded because
    a stale `.pyc` is not source.
    """
    root = (_anchor() / "clinical" / "tests") if root is None else pathlib.Path(root)
    assert root.is_dir(), f"{root} is not a directory -- this guard would scan nothing"
    found = sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)
    return found


def _parse(path: pathlib.Path) -> ast.Module:
    """
    A FILE THAT CANNOT BE PARSED IS AN ERROR, NOT A ZERO (w132c, Rule 7). A
    mojibaked or half-written module must not report "no violations".
    """
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _module_int_constants(tree: ast.Module) -> dict:
    """Module-level `NAME = <int>` bindings. `AMENDMENT_VERSION = 4` is one, and
    comparing the frontier to it is the same literal wearing a name."""
    constants = {}
    for node in tree.body:
        targets, value = [], None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, int) or isinstance(value.value, bool):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                constants[target.id] = value.value
    return constants


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return ""


def _hands_an_explicit_set(call: ast.Call) -> bool:
    spec = _EXPLICIT_SET_ARG.get(_call_name(call))
    if spec is None:
        return False
    index, keyword = spec
    return len(call.args) > index or any(kw.arg == keyword for kw in call.keywords)


def _is_literal_int(node: ast.expr, constants: dict) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return True
    return isinstance(node, ast.Name) and node.id in constants


def _is_literal_version_list(node: ast.expr, constants: dict) -> bool:
    return (
        isinstance(node, (ast.List, ast.Tuple))
        and bool(node.elts)
        and all(_is_literal_int(element, constants) for element in node.elts)
    )


def _mentions_discovery(node: ast.expr) -> bool:
    """Does this expression derive from the migration set on disk?"""
    return any(
        isinstance(child, ast.Call) and _call_name(child) in ("discover", "_on_disk_versions")
        for child in ast.walk(node)
    )


def _parents(tree: ast.Module) -> dict:
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    return parent


def _enclosing_scope_is_synthetic(node: ast.AST, parent: dict) -> bool:
    """
    THE EXEMPTION, AND IT IS DERIVED RATHER THAN LISTED.

    A literal version is legitimate when the test built the world it is
    counting: `migrate.inspect_state(connection, three)` over a three-file
    `tmp_path` set may assert `current_version == 3`, because three is a fact
    about the fixture and not about `clinical/migrations/`. The discriminator
    is the CALL: an explicit migration-set or directory argument. A file-name
    allow-list here would be the same decay this guard exists to forbid.
    """
    current = parent.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(isinstance(n, ast.Call) and _hands_an_explicit_set(n) for n in ast.walk(current)):
                return True
        current = parent.get(current)
    return False


def frontier_violations(tree: ast.Module) -> list:
    """
    Every assertion in this module that pins the migration FRONTIER or the
    migration COUNT to a literal.

    READ FROM THE AST, so a comment or a docstring that discusses
    `current_version == 4` is not a violation: comments never reach the tree
    and a docstring is an `Expr`, not a `Compare`. That distinction is the
    reason this is not a grep -- and it is the same reason the `schema.sql`
    stamp block and the frozen checksum declarations, which are legitimate and
    are not Python, are outside this guard's subject entirely.
    """
    constants = _module_int_constants(tree)
    parent = _parents(tree)
    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        sides = [node.left, *node.comparators]
        frontier = any(isinstance(s, ast.Attribute) and s.attr == _FRONTIER_ATTR for s in sides)
        derived = any(_mentions_discovery(s) for s in sides)
        literal = any(_is_literal_int(s, constants) for s in sides)
        literal_list = any(_is_literal_version_list(s, constants) for s in sides)
        if not ((frontier and literal) or (derived and (literal or literal_list))):
            continue
        if _enclosing_scope_is_synthetic(node, parent):
            continue
        violations.append((node.lineno, ast.unparse(node)))
    return violations


class TestTheFrontierGuardIsNotVacuous:
    """
    Rule 4 applied to this guard's own footing. Every row below is shaped "the
    scan found nothing", and that shape is satisfied by a scan that read
    nothing, by a matcher that matches nothing, and by a matcher that matches
    everything (which would be removed by the first person it inconvenienced).
    """

    def test_the_corpus_is_the_whole_directory_and_contains_the_migration_tests(self):
        names = {p.name for p in _test_corpus()}
        missing = [landmark for landmark in _TEST_CORPUS_LANDMARKS if landmark not in names]
        assert not missing, (
            f"the scan did not find {missing} -- it is reading the wrong directory, and every "
            "absence-shaped row below is vacuous. Fix the anchor, do not shorten the landmarks."
        )
        assert len(names) > len(_TEST_CORPUS_LANDMARKS)

    def test_the_corpus_is_derived_and_finds_a_test_file_nobody_listed(self, tmp_path):
        """
        WRONG VERSION A, and the only row that can catch it. A corpus that is
        a hand-written list of today's files satisfies every other row here --
        the list is complete today -- and fails silently on the first file
        written after it. A derivation finds a file nobody named; a list does
        not. Subdirectories included, because a corpus that stopped at the top
        level would be the same defect one directory down.
        """
        (tmp_path / "test_w999_written_next_year.py").write_text("x = 1\n", encoding="utf-8")
        nested = tmp_path / "deeper"
        nested.mkdir()
        (nested / "test_w1000_deeper_still.py").write_text("y = 2\n", encoding="utf-8")
        cached = tmp_path / "__pycache__"
        cached.mkdir()
        (cached / "test_stale.py").write_text("z = 3\n", encoding="utf-8")

        found = {p.name for p in _test_corpus(tmp_path)}
        assert found == {"test_w999_written_next_year.py", "test_w1000_deeper_still.py"}, found

    def test_the_corpus_is_tests_and_not_production(self):
        """
        PRODUCTION IS NOT THE SUBJECT. `clinical/migrate.py` holds
        `BASELINE_VERSION = 2` and must: the runner needs a name for a fixed
        historical generation. This guard forbids pinning the FRONTIER in a
        TEST, and a corpus that swept production would demand the runner stop
        naming its own baseline.
        """
        paths = {p.resolve() for p in _test_corpus()}
        assert (_anchor() / "clinical" / "migrate.py").resolve() not in paths
        assert all("tests" in p.parts for p in paths)

    def test_the_matcher_flags_the_shape_this_wave_removed(self):
        """THE PROHIBITED SHAPE, in both of its spellings."""
        source = (
            "AMENDMENT_VERSION = 4\n"
            "def test_it(connection):\n"
            "    state = migrate.inspect_state(connection)\n"
            "    assert state.current_version == AMENDMENT_VERSION\n"
            "    assert state.current_version == 4\n"
        )
        found = frontier_violations(ast.parse(source))
        assert [line for line, _ in found] == [4, 5], found

    def test_the_matcher_clears_the_derivation_that_belongs_there(self):
        source = (
            "def test_it(connection):\n"
            "    state = migrate.inspect_state(connection)\n"
            "    assert state.current_version == max(m.version for m in migrate.discover())\n"
            "    assert [r[0] for r in history] == _on_disk_versions()\n"
        )
        assert frontier_violations(ast.parse(source)) == []

    def test_the_matcher_clears_a_literal_over_a_synthetic_set(self):
        """
        THE LEGITIMATE CASE THE BRIEF NAMES, and the row that stops this guard
        from being wrong-version C. `three` is a `tmp_path` fixture; three is a
        fact about it.
        """
        source = (
            "def test_it(connection, three):\n"
            "    state = migrate.inspect_state(connection, three)\n"
            "    assert state.current_version == 3\n"
            "    assert [m.version for m in migrate.discover(directory)] == [2, 3, 10]\n"
        )
        assert frontier_violations(ast.parse(source)) == []

    def test_the_matcher_clears_a_fixed_historical_generation(self):
        """
        `adopted.current_version == migrate.BASELINE_VERSION` is NOT the
        prohibited shape: the baseline does not move when a fifth migration
        lands, and a guard that banned it would be banning the runner's own
        vocabulary.
        """
        source = (
            "def test_it(connection):\n"
            "    adopted = migrate.inspect_state(connection)\n"
            "    assert adopted.current_version == migrate.BASELINE_VERSION\n"
        )
        assert frontier_violations(ast.parse(source)) == []

    def test_the_matcher_ignores_comments_and_docstrings(self):
        """
        WRONG VERSION C, in miniature. A grep for `current_version == 4` finds
        the prose that explains why it is forbidden -- including this file's
        own header -- and fails on its own documentation.
        """
        source = (
            '"""A docstring that says state.current_version == 4 and must not count."""\n'
            "def test_it(connection):\n"
            "    # assert state.current_version == 4\n"
            '    """state.current_version == 4"""\n'
            "    return None\n"
        )
        assert frontier_violations(ast.parse(source)) == []

    def test_an_unparseable_file_is_an_error_not_a_zero(self):
        with pytest.raises(SyntaxError):
            ast.parse("def test_it(:\n    pass\n")

    def test_this_file_is_itself_in_the_corpus(self):
        """The guard reads its own file. Its header discusses the prohibited
        shape at length, which is why it is written in prose and not in code."""
        assert pathlib.Path(__file__).resolve() in {p.resolve() for p in _test_corpus()}


class TestNoTestPinsTheFrontier:
    def test_no_test_in_the_suite_asserts_the_migration_frontier_against_a_literal(self):
        """
        THE GUARD. It is about the SHAPE and not about today's files: the
        corpus is the directory, the exemption is derived from the call, and
        nothing here names a version, a count or a file.

        CATCHES: the fourth consecutive wave to write
        `assert state.current_version == <the version this wave added>`. That
        assertion is a claim that the wave's migration is the LAST one, and it
        becomes a red migration test the morning a fifth file lands.

        VACUOUS AGAINST: a literal frontier inside a function that also builds
        a synthetic set, and against any assertion that is not a comparison.
        """
        offences = []
        for path in _test_corpus():
            for line, text in frontier_violations(_parse(path)):
                offences.append(f"{path.name}:{line}: {text}")
        assert not offences, (
            "these assertions pin the migration frontier or the migration count to a literal:\n  "
            + "\n  ".join(offences)
            + "\nDerive it instead -- `max(m.version for m in migrate.discover())` -- or, if the "
            "literal is about a synthetic set your test built, hand the explicit set to "
            "discover()/inspect_state()/migrate() so it is visibly a statement about that set."
        )
