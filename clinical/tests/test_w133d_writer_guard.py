"""
clinical/tests/test_w133d_writer_guard.py
──────────────────────────────────────────
w133d — THE FUTURE-WRITER GUARD. Tests only; no production code imports this.

w133 made revocation point-in-time: `set_user_disabled` and
`set_patient_login_disabled` end the principal's live sessions at the instant
they run, and session validation was deliberately NOT taught to re-read the
principal row on every request. That decision is unchanged here, and this file
adds nothing to the session-validation path.

What it adds is the thing that decision leaves missing: **a constraint on
future code**. At `37a477c` the census is one application-level writer of
`users.disabled` and one of `patient_logins.disabled`, and each already ends
the sessions it invalidates. Nothing structural holds the NEXT one to that.
A bulk offboarding job, an HR-system sync, a seed script or a "disable every
user in this organisation" action would inherit the residue silently, because
under a point-in-time model the write and the invalidation are only ever
together by the author's own care.

This file makes that care mandatory, and it is the only mechanism that makes
the point-in-time ruling enforceable rather than merely documented.


THE INSTRUCTION THAT CANNOT BE FOLLOWED LITERALLY, SAID PLAINLY
───────────────────────────────────────────────────────────────
"Prove that any writer also invalidates sessions IN THE SAME TRANSACTION" is
**not statically decidable in general**. A static reader cannot prove atomicity
for an arbitrary future method: the statement may be built at run time, the
invalidation may live behind an arbitrary call graph, the transaction may be
opened or committed by something this file cannot see.

So this file does not claim that proof. It implements a **conservative,
fail-closed approximation** whose exact boundary is written out below and is
repeated in every failure message. A writer that satisfies the rule is not
thereby proved atomic; a writer that does not satisfy it FAILS, including when
the reason is that the analyser could not understand its shape.


THE RULE, EXACTLY
─────────────────
For every statement in PRODUCTION code (see "Production, structurally") that
writes the `disabled` column of a PRINCIPAL table (see "Principals,
structurally"), the enclosing method must:

  CONDITION 1 — carry the `@transactional` decorator, so that the whole body is
                one transaction and the write and the invalidation cannot be
                separated by a commit boundary; AND

  CONDITION 2 — contain, in its own body OR in a private helper it calls
                within the SAME MODULE (exactly ONE level of resolution — no
                more, and this is a boundary, not an oversight), an UPDATE of
                that principal's session table that SETs `terminated_at` and is
                KEYED ON THE PRINCIPAL'S IDENTIFIER and not on a session id.

FAIL CLOSED. A writer whose shape the analyser cannot resolve — an unknown
helper, a helper in another module, a dynamically built statement, a write that
sits outside any function — does not satisfy CONDITION 2 and therefore FAILS.
It never passes merely because the analyser did not understand it. Every
failure names the file, the line, the method and which condition was not
established.

WHAT THE RULE DOES NOT PROVE, stated so nobody quotes it as more than it is:
  * It does not prove atomicity. It proves the decorator is present and the
    statement is in the same body, which is the decidable shadow of atomicity.
  * It does not prove the two statements bind the same principal id at run
    time; it proves the invalidation's WHERE clause names the principal's key
    column rather than a session id.
  * It exempts a plain `INSERT INTO <principal>` that names `disabled`. A row
    that does not yet exist cannot hold a session, so creation is not a writer
    of an EXISTING principal's disabled state. An `INSERT ... ON CONFLICT ...`
    that touches `disabled` is NOT exempt — that is an update in disguise and
    is analysed as one.
  * It says nothing about writes from outside this repository (a DBA console, a
    restore). That exposure is unchanged by this file and by w133.


THE CANNOT-FAIL HAZARD, WHICH IS SEVERE HERE
────────────────────────────────────────────
This guard is ABSENCE-SHAPED BY CONSTRUCTION: "no writer lacks invalidation" is
satisfied by finding NO WRITERS AT ALL. Every way the scan can come up empty is
a silent green — a wrong root, a renamed package, a moved module, a
writer-detection pattern that stops matching after a harmless rename.

So the guard ASSERTS WHAT IT FOUND before it concludes anything:

  * the root is anchored by w132's `_anchor()` — the SAME helper, not a fifth
    path resolution — which raises on a redirected root instead of finding
    nothing and passing;
  * the principal map is derived from `clinical/schema.sql` and asserted to
    contain the two principals and their session tables;
  * the writer census is asserted to CONTAIN the two known writers at
    `37a477c`, `set_user_disabled` (`clinical/data_access.py`, `UPDATE users
    SET disabled`) and `set_patient_login_disabled` (`UPDATE patient_logins SET
    disabled`);
  * and the test-exclusion row asserts the excluded test writers EXIST under the
    root, so that "they were excluded" is not satisfied by their absence.

IT DOES NOT ASSERT THAT THERE ARE EXACTLY TWO WRITERS, and that distinction is
the design. A count protects today's census, not tomorrow's property: it fails
on a THIRD writer that is perfectly correct, and it is silent about whether any
of the writers it counted invalidates anything. **The known writers are a FLOOR
for non-vacuity, never a CEILING for correctness.** A third writer that
satisfies the rule PASSES; a third that does not FAILS. Both directions are
proved below against synthetic roots.


THE SCENARIO NUMBERS BELOW. The brief I worked from pins two of the human's
six by number -- SCENARIO 3 (invalidation behind a private helper must be
RECOGNISED) and SCENARIO 6 (a redirected source root must FAIL LOUDLY) -- and
describes the rest without numbering them. Only those two carry a number here.
The other rows say what they catch instead of claiming a number I was not
given.


PRINCIPALS, STRUCTURALLY — not a hard-coded pair
────────────────────────────────────────────────
The set of principal disabled columns is DERIVED FROM THE SCHEMA, so a future
principal table enters the guard's scope without anybody remembering to add it:

  a PRINCIPAL is a table that declares a `disabled` column and is the target of
  a FOREIGN KEY from a SESSION table, where a SESSION table is one declaring
  both `session_id` and `terminated_at`.

At `37a477c` that yields `users` (sessions, keyed `user_id`),
`patient_logins` (patient_sessions, keyed `patient_login_id`) and `patients`
(patient_sessions, keyed `patient_id`, which has no writer at all today).
`organisations` is NOT a principal by this rule — no session table references
it — which is correct for this guard and is stated as a known limitation rather
than hidden.


PRODUCTION, STRUCTURALLY — and comments and docstrings, from the AST
───────────────────────────────────────────────────────────────────
Tests are excluded BY TREE POSITION (a `tests` package directory, a `test_*.py`
or `*_test.py` basename, a `conftest.py`), never by looking for words in the
text. The audit records three test files that write these flags by direct SQL
— `test_w132_login_refusal_parity.py`, `test_w133_revocation.py` and
`test_w133_staff_revocation.py` — and they must not count.

Comments and docstrings are excluded STRUCTURALLY, from the AST, not by a
substring search:
  * a comment is not in the AST at all, so a `--`-style or `#`-style mention can
    never be seen as a statement;
  * a docstring is an `ast.Expr` whose value is a string, and every bare
    string-valued `ast.Expr` is skipped for exactly that reason.
`data_access.py:542`, `:750` and `:2622` mention `set_user_disabled` in
comments and must not count; a synthetic root proves the docstring case, with a
positive twin in the same root proving the exclusion is not swallowing real
writers.


THE ANCHOR, AND THE TENSION IN IT
─────────────────────────────────
The guard must FAIL LOUDLY when the source root is redirected, so the root must
be anchored. The wrong-first rows must run the analysis over SOURCE THEY
CONTROL, so the root must be a parameter. Those pull in opposite directions,
and the resolution is: the analyser is a PURE FUNCTION OVER A ROOT PATH,
defaulting to w132's anchored real root. The wrong-first rows call it with
temporary roots under `tmp_path` — which must themselves satisfy the anchor, so
anchoring is never bypassed, only relocated — and one separate row proves the
DEFAULT resolves to the real application root and that a redirected root raises.

NO SYNTHETIC WRONG WRITER IS EVER WRITTEN INTO THE REAL TREE.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
import re

import pytest

# THE REUSE, and it is the point: w132's anchor, shared, rather than a fifth
# private path resolution that can drift from the other four.
from clinical.tests.test_w132_structural_guards import _anchor, _source

SCHEMA = "clinical/schema.sql"
DATA_ACCESS = "clinical/data_access.py"


# ═══════════════════════════════════════════════════════════════════════════
# THE ANALYSER — a pure function over a root path
# ═══════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class Principal:
    """A table whose `disabled` column gates a principal that holds sessions."""

    table: str
    key_column: str
    session_tables: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Writer:
    """One production statement that writes a principal's `disabled` column."""

    path: str
    line: int
    method: str
    table: str
    statement: str
    transactional: bool
    invalidates_via: str | None  # "body", a helper name, or None
    unresolved: str | None  # why the shape could not be resolved, if that is why

    @property
    def satisfied(self) -> bool:
        return self.transactional and self.invalidates_via is not None

    def failure(self) -> str:
        missing = []
        if not self.transactional:
            missing.append(
                "CONDITION 1 (the enclosing method does not carry @transactional, so the write and "
                "any invalidation are not provably one transaction)"
            )
        if self.invalidates_via is None:
            detail = self.unresolved or (
                "no UPDATE of this principal's session table setting `terminated_at` and keyed on "
                f"`{self.table}`'s principal identifier was found in the method body or in a private "
                "helper it calls in the same module"
            )
            missing.append(f"CONDITION 2 ({detail})")
        return (
            f"{self.path}:{self.line} in `{self.method}` writes `{self.table}.disabled` "
            f"and did not establish {' and '.join(missing)}.\n"
            f"  statement: {self.statement[:160]}\n"
            "  THE RULE: a writer of a principal's disabled state must, in ONE transactional body, "
            "also terminate that principal's live sessions, keyed on the principal and not on a "
            "session id. This is a CONSERVATIVE, FAIL-CLOSED approximation of atomicity -- "
            "atomicity itself is not statically decidable, and a shape the analyser cannot resolve "
            "FAILS rather than passes. If this writer is genuinely correct, make its shape legible "
            "(inline the termination, or put it in a private helper in the same module); do not "
            "relax this guard."
        )


@dataclasses.dataclass(frozen=True)
class Analysis:
    root: pathlib.Path
    principals: dict[str, Principal]
    scanned: tuple[str, ...]
    writers: tuple[Writer, ...]


def _schema_blocks(root: pathlib.Path) -> dict[str, str]:
    """Every `CREATE TABLE` body in the schema, with SQL line comments removed.

    The comment strip is load-bearing: `schema.sql:332` and `:959` contain
    commented-out `REFERENCES` clauses, and a commented FOREIGN KEY must not
    make a table a principal.
    """
    text = (root / SCHEMA).read_text(encoding="utf-8")
    stripped = "\n".join(line.split("--")[0] for line in text.splitlines())
    blocks = {m.group(1): m.group(2) for m in re.finditer(r"CREATE TABLE\s+(\w+)\s*\((.*?)\n\);", stripped, re.S)}
    assert blocks, (
        f"no CREATE TABLE parsed out of {root / SCHEMA} -- the principal map would be empty and every row here vacuous"
    )
    return blocks


def _principals(root: pathlib.Path) -> dict[str, Principal]:
    blocks = _schema_blocks(root)
    disabled = {t for t, b in blocks.items() if re.search(r"^\s*disabled\s+BOOLEAN", b, re.M | re.I)}
    sessions = {
        t
        for t, b in blocks.items()
        if re.search(r"^\s*session_id\b", b, re.M) and re.search(r"^\s*terminated_at\b", b, re.M)
    }
    found: dict[str, dict] = {}
    for session_table in sorted(sessions):
        for fk in re.finditer(
            r"FOREIGN KEY\s*\(([^)]*)\)\s*REFERENCES\s+(\w+)\s*\(([^)]*)\)", blocks[session_table], re.I | re.S
        ):
            target = fk.group(2)
            if target not in disabled:
                continue
            local = [c.strip() for c in fk.group(1).split(",")]
            remote = [c.strip() for c in fk.group(3).split(",")]
            key = next((near for near, far in zip(local, remote) if far != "org_id"), None)
            if key is None:
                continue
            entry = found.setdefault(target, {"key": key, "sessions": set()})
            entry["sessions"].add(session_table)
    return {
        table: Principal(table=table, key_column=entry["key"], session_tables=tuple(sorted(entry["sessions"])))
        for table, entry in found.items()
    }


def _production_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Every production Python file under the root, tests excluded BY TREE POSITION."""
    out = []
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root).parts
        if "__pycache__" in parts or ".git" in parts:
            continue
        if any(part == "tests" for part in parts[:-1]):
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py") or path.name == "conftest.py":
            continue
        out.append(path)
    return out


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    table: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            table[child] = node
    return table


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """Every string constant that is a bare expression statement -- i.e. a docstring
    or a stray literal. Structural, from the AST; never a substring search."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            out.add(id(node.value))
    return out


def _sql_literals(tree: ast.AST) -> list[ast.Constant]:
    skip = _docstring_nodes(tree)
    return [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip]


def _enclosing_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.FunctionDef | None:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parents.get(current)
    return None


def _is_disabled_write(statement: str, table: str) -> bool:
    """An UPDATE of `<table>` touching `disabled`, or an ON CONFLICT upsert that does.

    A plain INSERT is exempt by design and the file docstring says why.
    """
    if not re.search(r"\bdisabled\s*=", statement, re.I):
        return False
    if re.match(rf"\s*UPDATE\s+{re.escape(table)}\s+SET\b", statement, re.I):
        return True
    if re.match(rf"\s*INSERT\s+INTO\s+{re.escape(table)}\b", statement, re.I) and re.search(
        r"\bON\s+CONFLICT\b", statement, re.I
    ):
        return True
    return False


def _is_dynamic_sql(node: ast.AST, table: str) -> bool:
    """A statement assembled at run time whose static part names this principal.

    f-strings, `+` concatenation, `%` formatting and `.format()` all produce a
    string this analyser cannot read. Such a shape is UNRESOLVABLE and therefore
    fails; it must never pass because the reader could not see the SQL.
    """
    if isinstance(node, ast.JoinedStr):
        static = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        static = "".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
    ):
        static = node.func.value.value
    else:
        return False
    return bool(re.search(rf"\bUPDATE\s+{re.escape(table)}\b", static, re.I))


def _invalidates(func: ast.FunctionDef, principal: Principal) -> bool:
    """Does this function body carry a qualifying session-invalidation statement?"""
    for literal in _sql_literals(func):
        statement = literal.value
        if not any(re.match(rf"\s*UPDATE\s+{re.escape(s)}\s+SET\b", statement, re.I) for s in principal.session_tables):
            continue
        if not re.search(r"\bterminated_at\s*=\s*%s", statement, re.I):
            continue
        if not re.search(rf"\b{re.escape(principal.key_column)}\s*=\s*%s", statement, re.I):
            continue
        if re.search(r"\bsession_id\s*=", statement, re.I):
            continue  # that is logout, not revocation: it ends one device
        return True
    return False


def _callee_names(func: ast.FunctionDef) -> list[str]:
    names = []
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                names.append(node.func.attr)
            elif isinstance(node.func, ast.Name):
                names.append(node.func.id)
    return names


def _is_transactional(func: ast.FunctionDef) -> bool:
    for decorator in func.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "transactional":
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr == "transactional":
            return True
    return False


def analyse(root=None) -> Analysis:
    """
    THE ANALYSER. A pure function over a root path; the default is w132's
    anchored real application root, and a redirected root RAISES rather than
    finding nothing and passing.
    """
    root = _anchor(root)
    principals = _principals(root)
    writers: list[Writer] = []
    scanned: list[str] = []

    for path in _production_files(root):
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:  # a file that will not parse is an ERROR, not a zero
            raise AssertionError(
                f"{relative} did not parse ({exc}). A production file this guard cannot read is a "
                "hole in an absence-shaped census, not an acceptable skip."
            ) from exc
        scanned.append(relative)

        parents = _parents(tree)
        functions = {
            node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        candidates: list[tuple[ast.AST, str, str, str | None]] = []
        for literal in _sql_literals(tree):
            for table in principals:
                if _is_disabled_write(literal.value, table):
                    candidates.append((literal, table, literal.value, None))
        for node in ast.walk(tree):
            for table in principals:
                if _is_dynamic_sql(node, table):
                    candidates.append(
                        (
                            node,
                            table,
                            "<dynamically built statement>",
                            "the statement is built at run time (f-string, concatenation, %% or "
                            ".format()), so its SQL cannot be read and the invalidation cannot be "
                            "established -- this shape FAILS CLOSED",
                        )
                    )

        for node, table, statement, unresolved in candidates:
            principal = principals[table]
            enclosing = _enclosing_function(node, parents)
            if enclosing is None:
                writers.append(
                    Writer(
                        path=relative,
                        line=getattr(node, "lineno", 0),
                        method="<module level -- no enclosing method>",
                        table=table,
                        statement=statement,
                        transactional=False,
                        invalidates_via=None,
                        unresolved="the write is not inside any method, so there is no transactional "
                        "body to hold it and the invalidation together -- this shape FAILS CLOSED",
                    )
                )
                continue

            via: str | None = None
            if unresolved is None:
                if _invalidates(enclosing, principal):
                    via = "body"
                else:
                    # EXACTLY ONE LEVEL of same-module resolution. Scenario 3:
                    # `_require_role` already uses this shape and a future writer
                    # legitimately may, so it must be RECOGNISED. Two levels are
                    # NOT resolved; that is a stated boundary, not an oversight.
                    for name in _callee_names(enclosing):
                        helper = functions.get(name)
                        if helper is not None and helper is not enclosing and _invalidates(helper, principal):
                            via = name
                            break

            writers.append(
                Writer(
                    path=relative,
                    line=getattr(node, "lineno", 0),
                    method=enclosing.name,
                    table=table,
                    statement=statement,
                    transactional=_is_transactional(enclosing),
                    invalidates_via=via,
                    unresolved=unresolved,
                )
            )

    return Analysis(root=root, principals=principals, scanned=tuple(scanned), writers=tuple(writers))


# ═══════════════════════════════════════════════════════════════════════════
# SYNTHETIC ROOTS — for the wrong-first rows only. Never the real tree.
# ═══════════════════════════════════════════════════════════════════════════

_LANDMARK_STUBS = (
    "clinical/app.py",
    "clinical/endpoints.py",
    "clinical/portal_endpoints.py",
    "clinical/auth_endpoints.py",
    # w152. This list must track w132's `_LANDMARKS`, because `_anchor()` is
    # the SAME helper (imported above) and a synthetic root that does not
    # satisfy it is refused — which is the anchor doing its job. Adding the
    # administrative module there without adding the stub here made sixteen
    # rows in this file fail with "THE GUARDS ARE NOT ANCHORED", which is the
    # correct failure and is why the anchor is shared rather than copied.
    "clinical/admin_endpoints.py",
    "clinical/data_access.py",
    "geper/api/main.py",
)

_MINIMAL_SCHEMA = """
CREATE TABLE users (
    user_id  UUID PRIMARY KEY,
    org_id   UUID NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE sessions (
    session_id    UUID PRIMARY KEY,
    user_id       UUID NOT NULL,
    org_id        UUID NOT NULL,
    terminated_at TIMESTAMPTZ,
    CONSTRAINT sessions_user_fk
        FOREIGN KEY (user_id, org_id) REFERENCES users (user_id, org_id)
);
"""


def _synthetic_root(tmp_path, modules: dict[str, str], schema: str = _MINIMAL_SCHEMA) -> pathlib.Path:
    """
    A root that SATISFIES w132's anchor and contains only source we wrote here.

    The anchor is not bypassed for the wrong-first rows, only relocated: a
    synthetic root that does not carry the landmarks still raises, which is why
    the redirected-root row below uses a bare `tmp_path`.
    """
    root = tmp_path / "tree"
    for relative in _LANDMARK_STUBS:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("", encoding="utf-8")
    (root / SCHEMA).parent.mkdir(parents=True, exist_ok=True)
    (root / SCHEMA).write_text(schema, encoding="utf-8")
    for relative, source in modules.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    return root


_CORRECT_WRITER = """
class Store:
    @auditable(action="user_disabled")
    @transactional
    def set_user_disabled(self, session, target_user_id, disabled):
        self._execute(
            "UPDATE users SET disabled = %s, updated_at = %s WHERE user_id = %s AND org_id = %s",
            (disabled, now, target_user_id, session.org_id),
        )
        if disabled:
            self._execute(
                "UPDATE sessions SET terminated_at = %s, terminated_by = %s "
                "WHERE user_id = %s AND org_id = %s AND terminated_at IS NULL",
                (now, session.user_id, target_user_id, session.org_id),
            )
"""


# ═══════════════════════════════════════════════════════════════════════════
# THE FOOTING — asserted BEFORE anything is concluded
# ═══════════════════════════════════════════════════════════════════════════


class TestTheAnalyserFoundWhatItIsAbout:
    """
    Rule 4, and it is the whole file's survival. "No writer lacks invalidation"
    is satisfied by finding no writers. These rows are what stop that from
    being a green.
    """

    def test_the_default_root_is_the_real_anchored_application_root(self):
        """
        SCENARIO 6, the half that proves the DEFAULT is right. The wrong-first
        rows below all run against temporary roots; this is the one row that
        proves the guard's own production run does not.
        """
        result = analyse()
        assert result.root == _anchor()
        assert (result.root / DATA_ACCESS).is_file()
        assert _source(DATA_ACCESS).strip(), "the anchored data_access.py is empty -- everything here would be vacuous"
        assert DATA_ACCESS in result.scanned, (
            f"the production walk did not visit {DATA_ACCESS}. It is walking the wrong tree, and "
            "every absence-shaped assertion built on it is vacuous."
        )
        assert len(result.scanned) > 20, f"only {len(result.scanned)} production files scanned -- that is not this tree"

    def test_a_redirected_root_fails_loudly_instead_of_finding_nothing(self, tmp_path):
        """
        SCENARIO 6. A guard that reads source by path reports green when the
        path is wrong. w132 MEASURED that failure on this floor. The anchor is
        reused, not reimplemented, so this is the same defence.
        """
        with pytest.raises(AssertionError) as exc:
            analyse(tmp_path)
        assert "NOT ANCHORED" in str(exc.value)

    def test_the_principal_map_is_derived_from_the_schema_and_found_both_principals(self):
        principals = analyse().principals
        assert "users" in principals and "patient_logins" in principals, (
            f"the schema-derived principal map is {sorted(principals)} -- if either principal is "
            "missing, its writers are invisible to this guard and it passes vacuously"
        )
        assert principals["users"].key_column == "user_id"
        assert principals["users"].session_tables == ("sessions",)
        assert principals["patient_logins"].key_column == "patient_login_id"
        assert principals["patient_logins"].session_tables == ("patient_sessions",)

    def test_the_two_known_writers_are_found_and_they_are_a_floor_not_a_ceiling(self):
        """
        THE NON-VACUITY ASSERTION, and the one row whose exact shape matters
        most in this file.

        It asserts the census CONTAINS the two writers known at `37a477c`. It
        does NOT assert the census has size two, and it never may: a count
        protects today's number, not tomorrow's property. It fails on a correct
        third writer and says nothing about whether any writer it counted
        invalidates anything. The known writers are a FLOOR for non-vacuity,
        never a CEILING for correctness -- `TestAThirdWriterIsJudgedOnItsShape`
        proves both directions of that.
        """
        found = {(w.path, w.method, w.table) for w in analyse().writers}
        for expected in (
            (DATA_ACCESS, "set_user_disabled", "users"),
            (DATA_ACCESS, "set_patient_login_disabled", "patient_logins"),
        ):
            assert expected in found, (
                f"{expected} is NOT in the writer census {sorted(found)}. The two writers this "
                "guard was built around were not found, so 'every writer invalidates sessions' is "
                "true only because nothing was scanned. Fix the detection -- do not relax this row."
            )

    def test_the_test_suites_that_write_these_flags_exist_and_are_excluded(self):
        """
        THE POSITIVE CONTROL ON THE EXCLUSION. "No test file appears in the
        census" is satisfied by a tree with no test files in it, so this row
        first proves the three known offenders are THERE to be excluded.
        """
        root = _anchor()
        offenders = (
            "clinical/tests/test_w132_login_refusal_parity.py",
            "clinical/tests/test_w133_revocation.py",
            "clinical/tests/test_w133_staff_revocation.py",
        )
        for relative in offenders:
            path = root / relative
            assert path.is_file(), f"{relative} is gone -- the exclusion row below would pass vacuously"
            assert re.search(r"disabled\s*=\s*TRUE", path.read_text(encoding="utf-8"), re.I), (
                f"{relative} no longer writes a disabled flag by direct SQL -- this row no longer "
                "proves the exclusion does anything"
            )
        result = analyse()
        from_tests = [w for w in result.writers if "tests/" in w.path or w.path.startswith("test_")]
        assert not from_tests, f"test source counted as a production writer: {from_tests}"
        assert not any("tests/" in relative for relative in result.scanned)


# ═══════════════════════════════════════════════════════════════════════════
# THE GUARD ITSELF
# ═══════════════════════════════════════════════════════════════════════════


def assert_the_invariant(result: Analysis) -> None:
    """
    THE ASSERTION, factored out so that the wrong-first rows can run THE SAME
    ASSERTION over source they control.

    THAT FACTORING IS NOT TIDINESS, IT IS THE MEASUREMENT. The first wrong
    version tried here -- the guard that asserts the census has size two --
    passed EVERY OTHER ROW IN THIS FILE, 21 of 21, because every other row
    inspects the analyser and the analyser is identical under it. A wrong
    version of the CONCLUSION can only be caught by a row that runs the
    conclusion against a tree whose right answer is known. That is what
    `TestTheConclusionIsNotACount` does, and it is why this function exists
    rather than living inline in one row.
    """
    assert result.writers, (
        "ZERO writers of any principal `disabled` column were found in production source under "
        f"{result.root}. This guard is absence-shaped, so zero is a SILENT GREEN, not a clean "
        "bill of health. Either the detection stopped matching or the tree is wrong."
    )
    failures = [w.failure() for w in result.writers if not w.satisfied]
    assert not failures, (
        "A PRINCIPAL'S DISABLED STATE IS WRITTEN WITHOUT INVALIDATING THAT PRINCIPAL'S "
        "SESSIONS.\n\n" + "\n\n".join(failures)
    )


class TestEveryWriterOfAPrincipalDisabledFlagAlsoInvalidatesSessions:
    """
    THE INVARIANT. Not "there are two writers" -- "every writer, whatever the
    count, carries the invalidation in the same transactional body".
    """

    def test_the_invariant_holds_for_every_production_writer(self):
        assert_the_invariant(analyse())


class TestTheConclusionIsNotACount:
    """
    THE ROW PAIR THAT CATCHES THE COUNTING GUARD, and the reason it exists is a
    measurement rather than a worry.

    A guard that asserts "there are exactly two writers" passes the real tree
    at `37a477c` and passed 21 of the 21 rows this file had before these two
    were added. It is wrong in BOTH directions, and one row each proves it:

      * the census can be exactly two and the tree still broken -- one writer
        correct, one not. A count passes; the invariant must RAISE.
      * the census can be three and the tree perfectly correct. A count fails;
        the invariant must NOT raise.

    Neither row may be deleted without the other: the first alone is satisfied
    by an assertion that refuses everything, the second alone by one that
    accepts everything.
    """

    _CORRECT_SECOND = """
class Sync:
    @transactional
    def apply_hr_offboarding(self, session, target_user_id):
        self._execute(
            "UPDATE users SET disabled = %s WHERE user_id = %s AND org_id = %s",
            (True, target_user_id, session.org_id),
        )
        self._execute(
            "UPDATE sessions SET terminated_at = %s, terminated_by = %s "
            "WHERE user_id = %s AND org_id = %s AND terminated_at IS NULL",
            (now, session.user_id, target_user_id, session.org_id),
        )
"""

    _SILENT_SECOND = """
class Sync:
    @transactional
    def apply_hr_offboarding(self, session, target_user_id):
        self._execute(
            "UPDATE users SET disabled = %s WHERE user_id = %s AND org_id = %s",
            (True, target_user_id, session.org_id),
        )
"""

    def test_two_writers_one_of_them_silent_still_fails_the_invariant(self, tmp_path):
        root = _synthetic_root(
            tmp_path, {"clinical/store.py": _CORRECT_WRITER, "clinical/hr_sync.py": self._SILENT_SECOND}
        )
        result = analyse(root)
        assert len(result.writers) == 2, (
            "this root must contain EXACTLY TWO writers, or it does not measure what it is for"
        )
        with pytest.raises(AssertionError) as exc:
            assert_the_invariant(result)
        assert "CONDITION 2" in str(exc.value) and "apply_hr_offboarding" in str(exc.value), (
            "the conclusion accepted a tree with the right NUMBER of writers and the wrong SHAPE. "
            "That is the counting guard, and it passes today's tree while proving nothing."
        )

    def test_three_correct_writers_still_pass_the_invariant(self, tmp_path):
        root = _synthetic_root(
            tmp_path,
            {
                "clinical/store.py": _CORRECT_WRITER,
                "clinical/hr_sync.py": self._CORRECT_SECOND,
                "clinical/bulk.py": self._CORRECT_SECOND.replace("apply_hr_offboarding", "apply_bulk_offboarding"),
            },
        )
        result = analyse(root)
        assert len(result.writers) == 3
        assert_the_invariant(result)  # must NOT raise: correctness is not a census


# ═══════════════════════════════════════════════════════════════════════════
# THE WRONG-FIRST ROWS — synthetic roots only
# ═══════════════════════════════════════════════════════════════════════════


class TestTheGuardFailsOnAWriterThatDoesNotInvalidate:
    """
    THE WRITER THAT SETS THE FLAG AND STOPS. A future writer that sets the flag and stops. This is the
    whole point of the file and the shape the audit named: a bulk offboarding
    job, an HR sync, a seed script.
    """

    def test_a_writer_with_no_invalidation_fails_naming_condition_two(self, tmp_path):
        root = _synthetic_root(
            tmp_path,
            {
                "clinical/offboarding.py": """
class Bulk:
    @transactional
    def disable_everyone(self, session, target_user_id):
        self._execute(
            "UPDATE users SET disabled = %s WHERE user_id = %s AND org_id = %s",
            (True, target_user_id, session.org_id),
        )
"""
            },
        )
        writers = analyse(root).writers
        assert len(writers) == 1 and writers[0].method == "disable_everyone"
        assert not writers[0].satisfied
        assert "CONDITION 2" in writers[0].failure()
        assert "CONDITION 1" not in writers[0].failure(), "it IS transactional -- only condition 2 is missing"

    def test_the_positive_twin_a_correct_writer_in_the_same_shape_passes(self, tmp_path):
        """
        Rule 4's twin. Without this, the row above is satisfied by an analyser
        that fails EVERYTHING, which would be useless in the opposite direction.
        """
        root = _synthetic_root(tmp_path, {"clinical/offboarding.py": _CORRECT_WRITER})
        writers = analyse(root).writers
        assert len(writers) == 1 and writers[0].satisfied
        assert writers[0].invalidates_via == "body"


class TestTheGuardFailsWhenTheBodyIsNotOneTransaction:
    """THE WRITE AND THE INVALIDATION IN TWO TRANSACTIONS. The statement is
    there; the single transactional body is not."""

    def test_a_writer_without_transactional_fails_naming_condition_one(self, tmp_path):
        source = _CORRECT_WRITER.replace("    @transactional\n", "")
        root = _synthetic_root(tmp_path, {"clinical/offboarding.py": source})
        writers = analyse(root).writers
        assert len(writers) == 1 and not writers[0].satisfied
        failure = writers[0].failure()
        assert "CONDITION 1" in failure
        assert "CONDITION 2" not in failure, "the invalidation IS present -- only the transaction is missing"


class TestInvalidationBehindAPrivateHelperIsRecognised:
    """
    SCENARIO 3, and the brief is explicit that this must PASS. `_require_role`
    already uses exactly this shape -- a private helper in the same module
    wrapping a query -- so a future writer legitimately may.

    EXACTLY ONE LEVEL of same-module resolution is implemented. Two levels are
    not, and the second row here PROVES the boundary rather than leaving it to
    a sentence. A helper in ANOTHER module is not resolved either: that is
    unresolvable, and unresolvable FAILS CLOSED.
    """

    HELPER_SOURCE = """
class Store:
    @transactional
    def set_user_disabled(self, session, target_user_id, disabled):
        self._execute(
            "UPDATE users SET disabled = %s WHERE user_id = %s AND org_id = %s",
            (disabled, target_user_id, session.org_id),
        )
        if disabled:
            self._end_live_sessions(session, target_user_id)

    def _end_live_sessions(self, session, target_user_id):
        self._execute(
            "UPDATE sessions SET terminated_at = %s, terminated_by = %s "
            "WHERE user_id = %s AND org_id = %s AND terminated_at IS NULL",
            (now, session.user_id, target_user_id, session.org_id),
        )
"""

    def test_one_level_of_same_module_helper_resolution_passes(self, tmp_path):
        root = _synthetic_root(tmp_path, {"clinical/store.py": self.HELPER_SOURCE})
        writers = analyse(root).writers
        assert len(writers) == 1 and writers[0].satisfied
        assert writers[0].invalidates_via == "_end_live_sessions"

    def test_two_levels_are_not_resolved_and_that_boundary_fails_closed(self, tmp_path):
        """THE STATED BOUNDARY, proved rather than promised. A writer whose
        invalidation is two calls deep FAILS -- conservatively, and on purpose."""
        source = self.HELPER_SOURCE.replace(
            "    def _end_live_sessions(self, session, target_user_id):\n        self._execute(",
            "    def _end_live_sessions(self, session, target_user_id):\n"
            "        self._really_end(session, target_user_id)\n\n"
            "    def _really_end(self, session, target_user_id):\n        self._execute(",
        )
        writers = analyse(root=_synthetic_root(tmp_path, {"clinical/store.py": source})).writers
        assert len(writers) == 1 and not writers[0].satisfied
        assert "CONDITION 2" in writers[0].failure()

    def test_a_helper_in_another_module_is_unresolvable_and_fails_closed(self, tmp_path):
        writer = """
from clinical.sessions import end_live_sessions


class Store:
    @transactional
    def set_user_disabled(self, session, target_user_id, disabled):
        self._execute(
            "UPDATE users SET disabled = %s WHERE user_id = %s AND org_id = %s",
            (disabled, target_user_id, session.org_id),
        )
        end_live_sessions(self, session, target_user_id)
"""
        elsewhere = """
def end_live_sessions(store, session, target_user_id):
    store._execute(
        "UPDATE sessions SET terminated_at = %s, terminated_by = %s "
        "WHERE user_id = %s AND org_id = %s AND terminated_at IS NULL",
        (now, session.user_id, target_user_id, session.org_id),
    )
"""
        root = _synthetic_root(tmp_path, {"clinical/store.py": writer, "clinical/sessions.py": elsewhere})
        writers = [w for w in analyse(root).writers]
        assert len(writers) == 1 and not writers[0].satisfied


class TestTheInvalidationMustBeKeyedOnThePrincipal:
    """
    AN INVALIDATION THAT ENDS ONE DEVICE. The statement is present, in the same transactional body, and
    ends ONE DEVICE. That is logout, not revocation -- the exact distinction
    w132 and w133 were built around, and a grep for `terminated_at` cannot see
    it.
    """

    def test_an_invalidation_keyed_on_the_session_id_does_not_count(self, tmp_path):
        source = _CORRECT_WRITER.replace(
            '"WHERE user_id = %s AND org_id = %s AND terminated_at IS NULL"',
            '"WHERE session_id = %s AND org_id = %s AND terminated_at IS NULL"',
        )
        root = _synthetic_root(tmp_path, {"clinical/offboarding.py": source})
        writers = analyse(root).writers
        assert len(writers) == 1 and not writers[0].satisfied


class TestTheInvalidationMustBeInTheWritersOwnMethod:
    """
    THE INVALIDATION IN THE WRONG METHOD, and the single most plausible WRONG guard: one that greps
    `terminated_at` anywhere in the FILE. Here the file is full of correct
    terminations -- in a completely different method -- and the writer has none.
    """

    def test_a_termination_elsewhere_in_the_same_file_does_not_count(self, tmp_path):
        source = """
class Store:
    @transactional
    def terminate_session(self, session, session_id):
        self._execute(
            "UPDATE sessions SET terminated_at = %s, terminated_by = %s "
            "WHERE user_id = %s AND org_id = %s AND terminated_at IS NULL",
            (now, session.user_id, session.user_id, session.org_id),
        )

    @transactional
    def bulk_disable(self, session, target_user_id):
        self._execute(
            "UPDATE users SET disabled = %s WHERE user_id = %s AND org_id = %s",
            (True, target_user_id, session.org_id),
        )
"""
        root = _synthetic_root(tmp_path, {"clinical/store.py": source})
        writers = [w for w in analyse(root).writers if w.method == "bulk_disable"]
        assert len(writers) == 1 and not writers[0].satisfied, (
            "a `terminated_at` elsewhere in the file was accepted as this writer's invalidation -- "
            "that is the file-grep guard, and it passes today's tree while proving nothing"
        )


class TestUnresolvableShapesFailClosed:
    """
    THE FAIL-CLOSED HALF, which is what separates this guard from the
    fail-open version that also passes today's tree.
    """

    def test_a_dynamically_built_statement_fails_rather_than_passing(self, tmp_path):
        source = """
class Store:
    @transactional
    def disable(self, session, target_user_id, column):
        self._execute(
            f"UPDATE users SET {column} disabled = %s WHERE user_id = %s",
            (True, target_user_id),
        )
        self._execute(
            "UPDATE sessions SET terminated_at = %s, terminated_by = %s "
            "WHERE user_id = %s AND org_id = %s AND terminated_at IS NULL",
            (now, session.user_id, target_user_id, session.org_id),
        )
"""
        root = _synthetic_root(tmp_path, {"clinical/store.py": source})
        writers = analyse(root).writers
        assert writers, "the dynamic statement was not seen at all -- that is the silent-pass failure"
        assert any(not w.satisfied and "built at run time" in (w.unresolved or "") for w in writers), (
            f"a run-time-assembled statement naming `UPDATE users` was accepted: {writers}"
        )

    def test_a_write_outside_any_method_fails_rather_than_passing(self, tmp_path):
        source = """
BOOTSTRAP = "UPDATE users SET disabled = %s WHERE user_id = %s AND org_id = %s"
"""
        root = _synthetic_root(tmp_path, {"clinical/bootstrap.py": source})
        writers = analyse(root).writers
        assert len(writers) == 1 and not writers[0].satisfied
        assert "module level" in writers[0].method

    def test_a_production_file_that_will_not_parse_is_an_error_not_a_zero(self, tmp_path):
        root = _synthetic_root(tmp_path, {"clinical/broken.py": "def f(:\n"})
        with pytest.raises(AssertionError) as exc:
            analyse(root)
        assert "did not parse" in str(exc.value)


class TestAThirdWriterIsJudgedOnItsShape:
    """
    THE FLOOR-NOT-CEILING PAIR, and the reason this guard is not a count.

    A count of writers fails the first row here -- a perfectly correct third
    writer -- and passes the second, which is the failure the guard exists for.
    Exactly backwards. Both rows run over the same synthetic root shape.
    """

    def test_a_correct_third_writer_passes(self, tmp_path):
        extra = """
class Sync:
    @transactional
    def apply_hr_offboarding(self, session, target_user_id):
        self._execute(
            "UPDATE users SET disabled = %s, updated_at = %s WHERE user_id = %s AND org_id = %s",
            (True, now, target_user_id, session.org_id),
        )
        self._execute(
            "UPDATE sessions SET terminated_at = %s, terminated_by = %s "
            "WHERE user_id = %s AND org_id = %s AND terminated_at IS NULL",
            (now, session.user_id, target_user_id, session.org_id),
        )
"""
        root = _synthetic_root(tmp_path, {"clinical/store.py": _CORRECT_WRITER, "clinical/hr_sync.py": extra})
        writers = analyse(root).writers
        assert len(writers) == 2, f"expected both writers to be seen, got {writers}"
        assert all(w.satisfied for w in writers), [w.failure() for w in writers if not w.satisfied]

    def test_a_third_writer_that_does_not_invalidate_fails(self, tmp_path):
        extra = """
class Sync:
    @transactional
    def apply_hr_offboarding(self, session, target_user_id):
        self._execute(
            "UPDATE users SET disabled = %s, updated_at = %s WHERE user_id = %s AND org_id = %s",
            (True, now, target_user_id, session.org_id),
        )
"""
        root = _synthetic_root(tmp_path, {"clinical/store.py": _CORRECT_WRITER, "clinical/hr_sync.py": extra})
        writers = analyse(root).writers
        assert len(writers) == 2
        bad = [w for w in writers if not w.satisfied]
        assert [w.method for w in bad] == ["apply_hr_offboarding"], (
            "the correct writer must still pass and the incorrect one must still fail -- the guard "
            "judges each writer's shape, it does not count them"
        )


class TestDocstringsAndCommentsAreNotStatements:
    """
    Structural, from the AST -- not a substring search. A comment never reaches
    the AST at all; a docstring is an `ast.Expr` wrapping a string and is
    skipped as one.

    THE POSITIVE TWIN IS IN THE SAME ROOT: a real writer sits in the same file
    as the prose, so "zero findings" cannot be what makes this row pass.
    """

    def test_prose_that_quotes_the_statement_is_not_counted_but_the_real_writer_is(self, tmp_path):
        source = '''
"""
Module prose. It quotes the statement on purpose:
    UPDATE users SET disabled = %s WHERE user_id = %s AND org_id = %s
"""


class Store:
    # UPDATE users SET disabled = %s WHERE user_id = %s -- a comment, historically
    @transactional
    def set_user_disabled(self, session, target_user_id, disabled):
        """Docstring: this method runs UPDATE users SET disabled = %s WHERE user_id = %s."""
        self._execute(
            "UPDATE users SET disabled = %s WHERE user_id = %s AND org_id = %s",
            (disabled, target_user_id, session.org_id),
        )
        if disabled:
            self._execute(
                "UPDATE sessions SET terminated_at = %s, terminated_by = %s "
                "WHERE user_id = %s AND org_id = %s AND terminated_at IS NULL",
                (now, session.user_id, target_user_id, session.org_id),
            )
'''
        root = _synthetic_root(tmp_path, {"clinical/store.py": source})
        writers = analyse(root).writers
        assert len(writers) == 1, f"prose was counted as a statement: {[(w.line, w.statement[:60]) for w in writers]}"
        assert writers[0].method == "set_user_disabled" and writers[0].satisfied


class TestTheRulingItselfIsUnchanged:
    """
    THE HUMAN REFUSED CONTINUOUS CHECKING, and this file must not have smuggled
    it in. Point-in-time stays; `session_valid` still reads one row from
    `sessions` and never the principal row. The w133 rows that pin that are in
    `test_w133_structural_guards.py::TestSessionValidationWasNotRedesigned` and
    are untouched; this row is the w133d-local restatement, so that a future
    reader of THIS file can see the boundary it did not cross.
    """

    def test_no_principal_read_was_added_to_the_session_validation_path(self):
        tree = ast.parse(_source(DATA_ACCESS))
        for name, table, principal in (
            ("session_valid", "sessions", "users"),
            ("patient_session_valid", "patient_sessions", "patient_logins"),
        ):
            found = [
                n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
            ]
            assert len(found) == 1, f"{name} not found exactly once -- this row would pass vacuously"
            selects = [s.value for s in _sql_literals(found[0]) if s.value.startswith("SELECT")]
            assert selects, f"{name} has no SELECT -- this row would pass vacuously"
            for statement in selects:
                assert f"FROM {table}" in statement
                assert principal not in statement, (
                    f"{name} now reads `{principal}`. That is CONTINUOUS checking on the hot path, "
                    "which the human refused. w133d did not add it and must not be the wave that did."
                )
                assert "JOIN" not in statement.upper()
