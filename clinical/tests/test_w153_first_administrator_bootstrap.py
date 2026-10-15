        # translations, so a call there is the only way a route could reach it.
        #
        # THE INSTRUMENT CHANGED AT w155, AND THE PROPERTY DID NOT.
        # This was `assert "provision_organisation" not in source` — a
        # SUBSTRING scan over the whole file, docstrings included. That is the
        # defect this repository already has a name for: grep credits prose as
        # a caller, which is how `_release_report` came to be recorded with
        # thirteen callers and zero calls. It bit here the moment w155's
        # module docstring in `admin_endpoints.py` carried the honest caveat
        # this very row exists to state — that every administrative route is
        # exactly as reachable as an operator invoking `provision_organisation`
        # directly. A guard that forbids naming the problem is not a guard.
        #
        # So the scan is now an AST ATTRIBUTE-AND-CALL census, which is
        # STRICTLY STRONGER on code and silent on prose: it catches
        # `dao.provision_organisation(...)`, a bare reference handed to
        # `Depends`, and an alias assignment — none of which a substring
        # search distinguishes from a sentence.
        def _referenced(path):
            tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
            names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    names.add(node.attr)
                elif isinstance(node, ast.Name):
                    names.add(node.id)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    names.update(alias.name for alias in node.names)
            return names

        for module_name in (
            "clinical.app",
            "clinical.endpoints",
            "clinical.admin_endpoints",
            "clinical.portal_endpoints",
            "clinical.auth_endpoints",
            # w157 (WAVE 7). THE SIXTH. This list is the "every route this app
            # serves is defined in one of these" claim above, and that claim is
            # a CENSUS -- so it grows with the surface or it silently stops
            # covering it. `clinical/workflow_endpoints.py` defines the two
            # laboratory bench routes; adding it here would NOT have failed
            # this row, which is exactly why it had to be added deliberately:
            # a module missing from this tuple is not scanned at all, and an
            # unscanned module is where a `provision_organisation` call would
            # go unnoticed.
            "clinical.workflow_endpoints",
            # w162 (THE CLINIC SURFACE). THE SEVENTH, added for the reason the
            # note above gives: this tuple IS the "every route this app serves
            # is defined in one of these" claim, and a module missing from it
            # is not scanned at all. `clinical/clinic_endpoints.py` defines the
            # three clinician routes -- registration, consent, withdrawal.
            "clinical.clinic_endpoints",
        ):
            try:
                module = __import__(module_name, fromlist=["*"])
            except ImportError:
                continue
            assert "provision_organisation" not in _referenced(module.__file__), module_name

        # The non-vacuity twin for the scan: it CAN find a domain method name
        # in those files when one is there — and, added at w155, it can tell a
        # real reference from a mention in prose, which is the whole reason
        # the instrument changed.
        from clinical import admin_endpoints

        referenced = _referenced(admin_endpoints.__file__)
        assert "assign_role" in referenced
        assert "enrol_patient_login" in referenced
        assert "provision_organisation" in pathlib.Path(admin_endpoints.__file__).read_text(encoding="utf-8"), (
            "this file no longer MENTIONS provision_organisation, so the row above can no longer "
            "distinguish a prose mention from a call -- re-check that it still can"
        )


class TestItGrantsAdministratorAndNothingElse:
    """WRONG-FIRST (E): granting `'System'` to a human principal."""

    def test_the_role_is_a_sql_literal_with_no_parameter_behind_it(self):
        names, _ = _declared_parameters()
        assert "role" not in names

        target = _provision_organisation_ast()
        literals = [
            node.value
            for node in ast.walk(target)
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "role_assignments" in node.value
        ]
        assert literals, "no INSERT INTO role_assignments statement found in provision_organisation"
        assert all("'Administrator'" in sql for sql in literals), literals
        assert not any("System" in sql for sql in literals), literals

    def test_the_provisioned_user_holds_administrator_and_nothing_else(self, dao, conn):
        org_id = dao.provision_organisation("Lane", "admin@lane.test", "pw", operating_context=OPERATING_CONTEXT)
        session = dao.login("admin@lane.test", org_id, "pw")

        assert [a.role for a in dao.get_user_roles(session, session.user_id)] == ["Administrator"]
        assert _rows(conn, "SELECT role FROM role_assignments WHERE role = %s", ("System",)) == []

        # The positive twin for the absence above: the reader CAN see a System
        # row when one exists, so "no System row" is a measurement rather than
        # a query that never matches.
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                "VALUES (%s, %s, 'System', %s, %s)",
                # `assigned_at` only, on a row this test inserts and then rolls
                # back. Nothing reads it, nothing orders on it and nothing
                # asserts it, so any instant does; it reads the same clock as
                # the rest of the file rather than carrying a second literal.
                (session.user_id, org_id, session.user_id, _now()),
            )
        assert _rows(conn, "SELECT role FROM role_assignments WHERE role = %s", ("System",)) == [("System",)]
        conn.rollback()

    def test_no_approver_is_granted_and_no_retention_policy_is_seeded(self, dao, conn):
        """
        Both from the w128 ruling: Approver needs a qualification basis this
        method has no business inventing, and `_resolve_vcf_retention_days`
        LEFT JOINs and falls back to the code default, so absence is a valid
        and already-tested state.
        """
        org_id = dao.provision_organisation("Lane2", "admin@lane2.test", "pw", operating_context=OPERATING_CONTEXT)
        roles = {r[0] for r in _rows(conn, "SELECT role FROM role_assignments WHERE org_id = %s", (org_id,))}
        assert roles == {"Administrator"}
        assert _rows(conn, "SELECT artefact_class FROM retention_policies WHERE org_id = %s", (org_id,)) == []


# ═══════════════════════════════════════════════════════════════════════════
# clinical/bootstrap.py IS NOT THIS MECHANISM — pinned, so the filename
# cannot be mistaken for the model a second time.
# ═══════════════════════════════════════════════════════════════════════════


def test_clinical_bootstrap_is_a_database_bootstrap_not_an_identity_one():
    """
    The wave's first question, kept as a test rather than as a paragraph
    somebody can stop believing. `clinical/bootstrap.py` creates POSTGRES
    LOGIN ROLES and applies `schema.sql`. It writes no application row of any
    kind, and a later change that made it write one would be a new bootstrap
    model needing its own ruling.
    """
    import clinical.bootstrap as bootstrap

    source = pathlib.Path(bootstrap.__file__).read_text(encoding="utf-8")
    for table in ("organisations", "users", "role_assignments"):
        assert f"INSERT INTO {table}" not in source, table
    assert "Administrator" not in source
    # What it DOES do, so the absences above are a measurement of a real file.
    assert "CREATE ROLE" in source and "ALTER ROLE" in source
    assert bootstrap.APP_ROLE == "clinical_app"
    assert bootstrap.RETENTION_ROLE == "clinical_retention"
