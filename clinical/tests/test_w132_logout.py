
    def test_the_patient_logout_records_its_organisation_and_credential_in_details(self, dao, conn, world):
        """
        REWRITTEN BY w137, DELIBERATELY AND IN ONE COMMIT WITH THE FIX.

        This row used to assert `org_id IS NULL` and carried a docstring
        explaining the gap: the `@auditable` decorator bound the audit row's
        `org_id`/`user_id` columns from a STAFF `Session` and from nothing
        else, so a patient-principal method could not populate them. Its
        failure message named its own successor — "the decorator now populates
        org_id for a patient-principal method -- good, and this test's
        docstring is out of date" — and w137 is that wave.

        The decorator now reads the organisation from the acting principal for
        `requires_session=False` methods. DECISION 7 IS UNTOUCHED: the refusal
        of a `PatientSession` is keyed on `requires_session=True`, and w130's
        suite plus `test_w137_patient_backend.py::TestDecisionSevenWasNotWidened`
        are the tripwires for it.

        `details` STILL CARRIES BOTH FACTS and that is not redundancy: it is
        how a mismatch between the column and the payload would ever be
        noticed. `user_id` stays NULL because a patient is not a `users` row.

        The org-scoped question — can the organisation's own Auditor actually
        FIND this row, through `read_audit` rather than through a raw SELECT —
        is asked in `test_w137_patient_backend.py`, because a SELECT here sees
        the row either way and cannot tell the two versions apart.
        """
        session = dao.patient_login("alice@a.example", world["org_a"], PASSWORD)
        dao.terminate_my_patient_session(session)

        with conn.cursor() as cur:
            cur.execute(
                "SELECT org_id, user_id, details FROM audit_log "
                "WHERE action = 'patient_session_logged_out' ORDER BY log_id"
            )
            rows = cur.fetchall()
        conn.commit()

        assert len(rows) == 1, rows
        org_column, user_column, details = rows[0]
        assert org_column == world["org_a"], (
            "the patient logout row is filed under no organisation, or under the wrong one; "
            "read_audit is org-scoped, so the organisation that owns this session cannot find it"
        )
        assert user_column is None, (
            "audit_log.user_id means a users row and a patient is not one -- the acting credential "
            "belongs in details, not here"
        )
        assert details["org_id"] == str(world["org_a"]), details
        assert details["patient_login_id"] == str(world["alice_login_id"]), details


# ─── the schema did not change ───────────────────────────────────────────────


class TestNoSchemaChangeWasNeeded:
    """
    The whole of this wave rests on one reading: `terminated_by` carries NO
    foreign key on either session table, so a patient credential id is an
    acceptable value in it. Had it referenced `users (user_id, org_id)` —
    which `terminate_session` writing `session.user_id` there makes a
    reasonable assumption — patient self-logout would have needed a migration,
    and this repository has no migration mechanism and three schema changes
    already held unlanded.

    Read from `schema.sql` rather than asserted, because the claim is about
    the file and the file is what ships.
    """

    def test_terminated_by_has_no_foreign_key_on_either_session_table(self):
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        assert schema.strip(), f"schema.sql at {SCHEMA_PATH} is empty -- this guard would pass vacuously"

        for table in ("sessions", "patient_sessions"):
            start = schema.index(f"CREATE TABLE {table} (")
            body = schema[start : schema.index(");", start)]
            assert "terminated_by" in body, table
            fk_lines = [line for line in body.splitlines() if "FOREIGN KEY" in line or "REFERENCES" in line]
            assert not any("terminated_by" in line for line in fk_lines), (table, fk_lines)

    def test_the_grant_already_permits_the_update(self):
        """
        The grant was written in anticipation of exactly this write: its own
        comment names "the terminated_at stamp". No grant change either.
        """
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        assert schema.strip(), f"schema.sql at {SCHEMA_PATH} is empty -- this guard would pass vacuously"

        # The whole GRANT statement, comment lines stripped, from the keyword
        # to its terminating semicolon: it spans ten lines and names its
        # tables on several of them, so a line-at-a-time match cannot see it.
        statements = []
        for start in range(len(schema)):
            if not schema.startswith("GRANT  SELECT, INSERT, UPDATE", start):
                continue
            body = schema[start : schema.index(";", start)]
            statements.append("\n".join(line for line in body.splitlines() if not line.lstrip().startswith("--")))

        assert statements, "no `GRANT SELECT, INSERT, UPDATE` to clinical_app found -- wrong file?"
        granted = [s for s in statements if "TO clinical_app" in s]
        assert granted, statements

        joined = "\n".join(granted)
        assert "sessions" in joined, joined
        assert "patient_sessions" in joined, joined
        # The negative half: the same grant must still NOT carry DELETE.
        assert "DELETE" not in joined, joined
