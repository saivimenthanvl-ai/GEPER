                " ".join(c.value.split())
                for c in ast.walk(node)
                if isinstance(c, ast.Constant)
                and isinstance(c.value, str)
                and id(c) not in skip
                and any(kw in c.value for kw in ("SELECT ", "UPDATE ", "INSERT INTO", "DELETE FROM"))
            ]

        offenders = []
        for node in portal:
            body = ast.unparse(node)
            statements = sql_strings(node)
            for name, value in shared.items():
                if name in body:
                    statements += sql_strings(value)
            if not statements:
                offenders.append(f"{node.name}: issues no SQL this guard can see -- it would pass vacuously")
            for sql in statements:
                if "patient_id" not in sql:
                    offenders.append(f"{node.name}: statement does not mention patient_id: {sql}")
            if "patient_session.patient_id" not in body:
                offenders.append(f"{node.name}: never binds patient_session.patient_id")
        assert not offenders, "portal method(s) not bound to the session's patient:\n  " + "\n  ".join(offenders)


@requires_db
class TestAStaffSessionIsNotAPatientSession:
    """DECISION 8: patient access is explicit. A staff session does not become
    a patient session by being handed to a portal method."""

    def test_a_staff_session_is_refused_by_the_portal_surface(self, dao, staff_a, patient_a):
        with pytest.raises(AuthorizationError):
            _my_record(dao, staff_a, patient_a)

    def test_a_staff_session_is_refused_by_the_portal_orders_list(self, dao, staff_a, patient_a):
        with pytest.raises(AuthorizationError):
            try:
                dao.list_my_test_orders(staff_a, patient_a)
            except TypeError:
                dao.list_my_test_orders(staff_a)

    def test_the_positive_twin_a_patient_session_is_accepted(self, dao, alice_session, patient_a):
        assert _my_record(dao, alice_session, patient_a)["patient_id"] == patient_a


class TestTheGuardRailsCoverTheNewTables:
    """Source-reading; runs without a database."""

    def test_both_tables_are_declared_org_scoped(self):
        """
        Not a restatement of the derived guard, which already fails if a name
        is missing. This pins the DIRECTION: neither table may be moved to the
        exemption list later, and the exemption interlock refuses it anyway
        because both carry org_id.
        """
        assert "patient_logins" in ORG_SCOPED_TABLES
        assert "patient_sessions" in ORG_SCOPED_TABLES

    def test_the_patient_login_lookup_binds_org_id(self):
        """
        The statement the design named specifically. An email is unique only
        WITHIN an organisation, so a login lookup keyed on the address alone
        would authenticate one tenant's patient against another tenant's
        credential.
        """
        source = (pathlib.Path(__file__).resolve().parent.parent / "data_access.py").read_text(encoding="utf-8")
        assert "FROM patient_logins WHERE org_id = %s AND email = %s" in " ".join(source.split())

    def test_no_new_system_session_call_site_was_added(self):
        """
        The brief's hard constraint, restated where this wave can see it. The
        four sites are pinned by name in test_identity.py and that guard scans
        the tree; this asserts the same thing about the modules w130 adds, so
        the failure names w130 rather than arriving as a count mismatch.
        """
        clinical = pathlib.Path(__file__).resolve().parent.parent
        for name in ("data_access.py", "endpoints.py", "app.py"):
            source = (clinical / name).read_text(encoding="utf-8")
            w130_region = source.split("w130")
            for chunk in w130_region[1:]:
                assert "_create_system_session" not in chunk[:4000], (
                    f"a _create_system_session call site appears in w130 code in {name}"
                )

    def test_nothing_clinical_may_name_a_patient_principal_as_an_actor(self):
        """
        A CENSUS, not a sample (Standing Rule 3). The reason the principal is a
        separate table is that `REFERENCES users` occurs 22 times in
        schema.sql, nineteen of them clinical-record actor columns -- so a
        patient in `users` would be a database-legal report approver.

        That argument is only worth anything while patient_logins is referenced
        by NOTHING except the patient session table. This counts it. A future
        `reports.patient_approver_id`, or any other actor column pointed at the
        patient principal, fails here.
        """
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        referencing = [line.strip() for line in schema.splitlines() if "REFERENCES patient_logins" in line]
        assert len(referencing) == 1, f"patient_logins is referenced {len(referencing)} times: {referencing}"
        assert "patient_logins (patient_login_id, org_id)" in referencing[0]

    def test_no_patient_role_was_added(self):
        """
        Decision 1, asserted against both places a role could have been added.
        """
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        assert "'Patient'" not in schema
        source = (pathlib.Path(__file__).resolve().parent.parent / "data_access.py").read_text(encoding="utf-8")
        assert '"Patient"' not in source
        assert "role_assignments_role_known CHECK" in schema
        # The seven staff roles, unchanged.
        assert "role IN ('Orderer', 'Lab technician', 'Interpreter'," in schema
