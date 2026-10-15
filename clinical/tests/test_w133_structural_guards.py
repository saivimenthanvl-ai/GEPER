"""
clinical/tests/test_w133_structural_guards.py
──────────────────────────────────────────────
w133 — the guards that keep the SHAPE of the two revocation methods after the
wave is forgotten. Tests only; no production code depends on this file.

Each row catches a change that is ONE LINE, looks like an improvement, and
that the behavioural suites would still pass without a database:

  * the organisation predicate dropped from a revocation UPDATE ("the
    precondition read already checked it");
  * the Administrator gate dropped ("the endpoint checks it" -- there is no
    endpoint);
  * `requires_session=True` or `resource_id_param` dropped from a decorator,
    which silently un-refuses patient sessions or records '<none>';
  * the session-termination statement re-keyed, in either direction;
  * session validation quietly taught to join the principal row, which is the
    CONTINUOUS design this wave deliberately did not build.

THREE THINGS THIS FILE DOES DELIBERATELY, each because the same mistake has
already been made on this floor:

  1. IT REUSES w132's ANCHOR rather than writing a fourth path resolution.
     `_anchor()` names landmark files and raises if the tree it is reading is
     not this repository; `_source()` proves the file non-empty. w132 measured
     a real vacuous pass -- a path-reading guard that found nothing and
     reported green -- and this file is the same shape.

  2. EVERY ROW ASSERTS THE TARGET WAS FOUND. An AST walk that matches nothing
     produces an empty list, and every `all(...)` over an empty list is True.
     `_method()` raises when the method is not found EXACTLY ONCE, so a
     renamed or deleted method fails these guards loudly instead of passing
     them quietly. `TestTheGuardsAreNotVacuous` proves that machinery itself.

  3. DECORATORS ARE READ FROM THE AST, NOT FROM `inspect.signature`.
     `auditable` does not apply `functools.wraps` and does not preserve the
     decorator arguments on the wrapper, so a signature-based or
     attribute-based check inspects the WRAPPER and not the declaration. A
     signature-based test in this repository already passed against a wrong
     implementation (w130). The source text is the only honest witness.
"""

from __future__ import annotations

import ast

import pytest

# THE REUSE, and it is the point: one anchor, shared, rather than a fourth
# private path resolution that can drift from the other three.
from clinical.tests.test_w132_structural_guards import _anchor, _source

DATA_ACCESS = "clinical/data_access.py"


def _module() -> ast.Module:
    """The parsed data_access module, anchored and proved non-vacuous."""
    _anchor()  # raises if this is not this repository's tree
    source = _source(DATA_ACCESS)
    tree = ast.parse(source)
    assert isinstance(tree, ast.Module), f"{DATA_ACCESS} did not parse to a module"
    assert tree.body, f"{DATA_ACCESS} parsed to an EMPTY module -- every guard here would pass vacuously"
    return tree


def _method(name: str) -> ast.FunctionDef:
    """
    One method, BY NAME, and proved to exist.

    THE NON-VACUITY ASSERTION IS THE WHOLE POINT OF THIS HELPER. Without it a
    renamed method makes every guard below iterate an empty list and report
    green -- the Phase 5d cannot-fail shape, applied to a test's own footing.
    """
    found = [
        node
        for node in ast.walk(_module())
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    assert len(found) == 1, (
        f"{name} was not found EXACTLY ONCE in {DATA_ACCESS} (found {len(found)}). "
        "These guards read the AST; a method they cannot find does not make them fail, it makes "
        "them find nothing and pass. Fix the name -- do not relax the assertion."
    )
    return found[0]


def _strings(node: ast.AST) -> list[str]:
    """Every string literal inside one node.

    Adjacent literals are joined by the PARSER, so a multi-line SQL statement
    written as several quoted fragments arrives here as one string -- which is
    what makes "does this statement carry the org predicate" answerable at all.
    """
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _statements_beginning(node: ast.AST, prefix: str) -> list[str]:
    return [s for s in _strings(node) if s.startswith(prefix)]


def _auditable_decorator(method: ast.FunctionDef) -> ast.Call:
    """The @auditable(...) call on a method, READ FROM THE AST."""
    for decorator in method.decorator_list:
        if (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Name)
            and decorator.func.id == "auditable"
        ):
            return decorator
    raise AssertionError(f"{method.name} carries no @auditable(...) decorator in the source")


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _requires_role_calls(method: ast.FunctionDef) -> list[str]:
    """The role names this method's body demands, structurally."""
    roles = []
    for node in ast.walk(method):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_require_role"
            and len(node.args) == 2
            and isinstance(node.args[1], ast.Constant)
        ):
            roles.append(node.args[1].value)
    return roles


# ═══════════════════════════════════════════════════════════════════════════
# THE MACHINERY'S OWN NEGATIVE TWIN
# ═══════════════════════════════════════════════════════════════════════════


class TestTheGuardsAreNotVacuous:
    """
    Rule 4 applied to this file. Every guard below is shaped "the method's
    source contains X", and that shape is satisfied by finding no method at
    all. These two rows prove the finder refuses that.
    """

    def test_a_method_that_does_not_exist_fails_loudly(self):
        with pytest.raises(AssertionError) as exc:
            _method("set_patient_login_disabled_but_renamed_by_a_later_wave")
        assert "not found EXACTLY ONCE" in str(exc.value)

    def test_the_matcher_finds_the_statements_that_already_existed(self):
        """
        THE DELIBERATE NEGATIVE CONTROL. `UPDATE patient_logins` statements
        existed at `aa37288` before this wave -- the lockout counter reset and
        the failed-attempt increment. If the matcher below finds only the one
        this wave added, it is matching too narrowly; if it finds none of them,
        it is broken and every guard using it is green for the wrong reason.
        """
        module_statements = _statements_beginning(_module(), "UPDATE patient_logins")
        assert len(module_statements) >= 3, (
            f"expected the two pre-existing UPDATE patient_logins statements plus this wave's, "
            f"found {len(module_statements)}: {module_statements}"
        )
        assert any("failed_login_attempts = 0" in s for s in module_statements)
        assert any("SET disabled" in s for s in module_statements)

    def test_the_anchor_is_the_shared_one(self):
        """Not a fourth path resolution: the helper imported here is w132's."""
        assert _anchor().is_dir()
        assert (_anchor() / DATA_ACCESS).is_file()


# ═══════════════════════════════════════════════════════════════════════════
# THE PATIENT REVOCATION METHOD
# ═══════════════════════════════════════════════════════════════════════════


class TestThePatientRevocationShape:
    METHOD = "set_patient_login_disabled"

    def test_r13_the_credential_update_carries_the_organisation_predicate(self):
        method = _method(self.METHOD)
        updates = _statements_beginning(method, "UPDATE patient_logins")
        assert len(updates) == 1, f"expected exactly one UPDATE patient_logins in {self.METHOD}, got {updates}"
        assert "org_id = %s" in updates[0], (
            "the credential UPDATE has lost its organisation predicate -- one Administrator could "
            "revoke another tenant's credential by id"
        )
        assert "patient_login_id = %s" in updates[0]

    def test_the_precondition_read_is_organisation_scoped(self):
        method = _method(self.METHOD)
        selects = _statements_beginning(method, "SELECT patient_login_id FROM patient_logins")
        assert len(selects) == 1, f"expected exactly one precondition SELECT, got {selects}"
        assert "org_id = %s" in selects[0]

    def test_the_refusal_is_the_module_constant_and_not_an_f_string(self):
        """Rule 2b, and the existence-oracle family w129b already fixed once:
        a message naming the id tells the caller which ids exist elsewhere."""
        method = _method(self.METHOD)
        raises = [n for n in ast.walk(method) if isinstance(n, ast.Raise)]
        assert raises, "the precondition raises nothing -- a cross-org attempt would be a silent no-op"
        for node in raises:
            assert isinstance(node.exc, ast.Call)
            for arg in node.exc.args:
                assert isinstance(arg, ast.Name) and arg.id == "PATIENT_NOT_FOUND", (
                    "the refusal must carry the module constant, never an f-string naming the id"
                )

    def test_r14_the_administrator_gate_is_in_the_body(self):
        assert _requires_role_calls(_method(self.METHOD)) == ["Administrator"]

    def test_the_termination_is_keyed_on_the_credential_and_the_organisation(self):
        """
        The statement w132 deliberately REFUSED for logout, and the one
        revocation requires. Both wrong keys are caught here: `session_id`
        would end one device, and dropping `patient_login_id` would end every
        patient session in the organisation.
        """
        method = _method(self.METHOD)
        updates = _statements_beginning(method, "UPDATE patient_sessions")
        assert len(updates) == 1, f"expected exactly one UPDATE patient_sessions, got {updates}"
        statement = updates[0]
        assert "terminated_at = %s" in statement and "terminated_by = %s" in statement
        assert "patient_login_id = %s" in statement, "re-keyed off the credential"
        assert "org_id = %s" in statement, "the organisation predicate is gone"
        assert "session_id = %s" not in statement, "keyed on one device -- that is logout, not revocation"
        assert "terminated_at IS NULL" in statement, "a second revocation would rewrite the first instant"

    def test_the_termination_only_happens_when_disabling(self):
        """Structural: the UPDATE lives inside an `if disabled:`. A version
        that terminates unconditionally signs the patient out on the very call
        that restored their access."""
        method = _method(self.METHOD)
        guarded = [
            node
            for node in ast.walk(method)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "disabled"
            and _statements_beginning(node, "UPDATE patient_sessions")
        ]
        assert len(guarded) == 1, "the session termination is not guarded by `if disabled:`"

    def test_r15_the_decorator_declares_what_the_audit_row_needs(self):
        """READ FROM THE AST. `auditable` does not preserve its arguments on
        the wrapper, so `inspect` cannot answer this and a test that asked it
        would be asking the wrong object."""
        decorator = _auditable_decorator(_method(self.METHOD))

        requires_session = _keyword(decorator, "requires_session")
        assert isinstance(requires_session, ast.Constant) and requires_session.value is True, (
            "requires_session=True is what refuses a PatientSession on a staff operation (w130 "
            "decision 7). Dropping it would let a patient revoke a credential."
        )

        resource_id_param = _keyword(decorator, "resource_id_param")
        assert isinstance(resource_id_param, ast.Constant) and resource_id_param.value == "target_patient_login_id", (
            "a `-> None` method with no resource_id_param records the literal '<none>' -- the w120 defect"
        )

        resource_type = _keyword(decorator, "resource_type")
        assert isinstance(resource_type, ast.Constant) and resource_type.value == "patient_login"

        assert _keyword(decorator, "details_builder") is not None

    def test_the_method_is_transactional(self):
        names = [d.id for d in _method(self.METHOD).decorator_list if isinstance(d, ast.Name)]
        assert "transactional" in names

    def test_one_method_one_body_and_it_calls_no_other_decorated_writer(self):
        """
        THE w128 LESSON, THIRD APPEARANCE, made structural.

        @auditable commits after every audit row it writes, so a revocation
        composed from two decorated calls commits "revoked" while the sessions
        run on. This asserts the body calls no other public writer of this
        class -- the reads it does make are inline `_query_one`/`_execute`.
        """
        method = _method(self.METHOD)
        forbidden = {
            "set_user_disabled",
            "terminate_session",
            "terminate_my_session",
            "terminate_my_patient_session",
            "enrol_patient_login",
        }
        called = {
            node.func.attr
            for node in ast.walk(method)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert not (called & forbidden), f"composed out of decorated calls: {called & forbidden}"


# ═══════════════════════════════════════════════════════════════════════════
# THE STAFF HALF
# ═══════════════════════════════════════════════════════════════════════════


class TestTheStaffRevocationShape:
    METHOD = "set_user_disabled"

    def test_the_administrator_gate_is_still_in_the_body(self):
        assert _requires_role_calls(_method(self.METHOD)) == ["Administrator"]

    def test_the_credential_update_still_carries_the_organisation_predicate(self):
        method = _method(self.METHOD)
        updates = _statements_beginning(method, "UPDATE users")
        assert len(updates) == 1, f"expected exactly one UPDATE users, got {updates}"
        assert "user_id = %s" in updates[0] and "org_id = %s" in updates[0]

    def test_the_termination_is_keyed_on_the_user_and_the_organisation(self):
        method = _method(self.METHOD)
        updates = _statements_beginning(method, "UPDATE sessions")
        assert len(updates) == 1, (
            f"expected exactly one UPDATE sessions in {self.METHOD}, got {updates}. "
            "Zero means staff offboarding has gone back to leaving live sessions running."
        )
        statement = updates[0]
        assert "terminated_at = %s" in statement and "terminated_by = %s" in statement
        assert "user_id = %s" in statement, "re-keyed off the user"
        assert "org_id = %s" in statement, "the organisation predicate is gone -- this would sign out the tenant"
        assert "session_id = %s" not in statement, "keyed on one device -- that is logout, not offboarding"
        assert "terminated_at IS NULL" in statement

    def test_the_termination_only_happens_when_disabling(self):
        method = _method(self.METHOD)
        guarded = [
            node
            for node in ast.walk(method)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "disabled"
            and _statements_beginning(node, "UPDATE sessions")
        ]
        assert len(guarded) == 1, "the session termination is not guarded by `if disabled:`"

    def test_it_calls_no_other_decorated_writer(self):
        method = _method(self.METHOD)
        called = {
            node.func.attr
            for node in ast.walk(method)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert "terminate_session" not in called, (
            "composed out of decorated calls -- @auditable would commit the disable before the termination could fail"
        )


# ═══════════════════════════════════════════════════════════════════════════
# THE DECISION THIS WAVE MADE, PINNED SO THAT CHANGING IT IS DELIBERATE
# ═══════════════════════════════════════════════════════════════════════════


class TestSessionValidationWasNotRedesigned:
    """
    POINT-IN-TIME, NOT CONTINUOUS -- as a structural fact rather than a
    sentence in a docstring.

    The alternative implementation of "invalidate existing live sessions" is a
    join in session validation: continuous, closes the residue, and changes
    what the hottest read in the layer does on every request. It was NOT
    built. These rows record that, and they FAIL THE DAY SOMEBODY BUILDS IT --
    which is the point. Whoever does should delete them in the same commit and
    say so, rather than discovering later that two designs are half-present.
    """

    def test_staff_session_validation_reads_only_the_sessions_table(self):
        method = _method("session_valid")
        selects = _statements_beginning(method, "SELECT")
        assert selects, "session_valid has no SELECT -- this guard would pass vacuously"
        for statement in selects:
            assert "FROM sessions" in statement
            assert "users" not in statement, (
                "session_valid now reads `users`. That is the CONTINUOUS design: it closes the "
                "residue w133 left open, and it changes the semantics of every authenticated "
                "request. Delete this row deliberately, in the commit that makes the change."
            )
            assert "JOIN" not in statement.upper()

    def test_patient_session_validation_reads_only_the_patient_sessions_table(self):
        method = _method("patient_session_valid")
        selects = _statements_beginning(method, "SELECT")
        assert selects, "patient_session_valid has no SELECT -- this guard would pass vacuously"
        for statement in selects:
            assert "FROM patient_sessions" in statement
            assert "patient_logins" not in statement, (
                "patient_session_valid now reads `patient_logins`. See the row above."
            )
            assert "JOIN" not in statement.upper()

    def test_logout_still_ends_exactly_one_session_on_both_sides(self):
        """The w132 property, pinned from the opposite direction: revocation
        keys on the principal BECAUSE logout keys on the session. If a later
        wave 'unifies' the two, this fails."""
        for name, table, key in (
            ("terminate_my_session", "UPDATE sessions", "session_id = %s"),
            ("terminate_my_patient_session", "UPDATE patient_sessions", "session_id = %s"),
        ):
            method = _method(name)
            updates = _statements_beginning(method, table)
            assert len(updates) == 1, f"{name}: expected one {table}, got {updates}"
            assert key in updates[0], f"{name} is no longer keyed on the session -- that is a 'log out everywhere'"
            assert "user_id = %s AND" not in updates[0]
            assert "patient_login_id = %s AND" not in updates[0]


class TestTheLockoutMechanismWasNotTouched:
    """
    `locked_until` is a CLOCK; `disabled` is a DECISION. Conflating them is the
    error the human's guard was written to prevent, and it would look like a
    convenience: "while we are here, let the Administrator clear the lockout
    too". No revocation method may write the lockout columns.
    """

    @pytest.mark.parametrize("name", ["set_patient_login_disabled", "set_user_disabled"])
    def test_no_revocation_method_writes_the_lockout_columns(self, name):
        for statement in _strings(_method(name)):
            assert "locked_until" not in statement, f"{name} writes the lockout clock"
            assert "failed_login_attempts" not in statement, f"{name} writes the lockout counter"
