"""
clinical/tests/test_w135_patient_report_access.py
─────────────────────────────────────────────────
w135 — patient-safe report access, and the four things it refuses to hand over.

WHAT A RELEASED REPORT CONSISTS OF IN THIS MODEL, BECAUSE EVERY ROW BELOW
DEPENDS ON IT. `reports` has NO CONTENT COLUMN. Its columns are org_id, id,
interpretation_id, created_at, created_by, state, approver_id, approved_at,
content_hash, tombstoned_at, tombstoned_by, retention_days. A row there is a
governance record ABOUT a document, not the document. So "read my report"
resolves, in this schema and not in some other one, to METADATA AND RELEASE
STATE — the report exists, it belongs to this test, it was delivered on this
date — and the surface under test here is exactly that and nothing more. No
report-content storage was invented to make it larger; that refusal is the
deliverable.

WHAT CANNOT HAPPEN IN PRODUCTION, STATED BEFORE THE FIRST ASSERTION.
`_release_report` has ZERO non-test callers in this repository (counted at
d6246cd; the one grep hit is prose in geper/review/signoff.py). Nothing here
releases a report, so in THIS deployment `GET /portal/me/reports` returns `[]`
for every patient for ever. The released state is therefore constructed in
these tests the only legitimate way there is — by calling `_release_report`
itself, behind its own Approver gate, through the same fixture w134 uses — and
never by an UPDATE that forges `state = 'released'`. What is proved is that the
surface is correct when the state exists; what is NOT proved, and is not
claimed, is that any production path reaches it.

THE FOUR REFUSALS THIS FILE EXISTS TO HOLD IN PLACE:

  1. ANOTHER PATIENT'S REPORT — same organisation, real, released.
  2. ANOTHER ORGANISATION'S REPORT — the tenant axis, tested separately from
     the patient axis because they are separate axes.
  3. AN UNRELEASED REPORT OF THE CALLER'S OWN — draft, under_review, and
     approved-but-never-released. This is the one a reasonable implementer
     gets wrong: the report IS the patient's, and it is still not theirs to
     have. "Your report exists but you may not read it yet" is a clinical
     fact, and the release gate exists to withhold it.
  4. RAW RESULT DATA — `run_document`, reached through `get_interpretation`,
     which applies NO report-state check of any kind.

RULE 2a — THE ROUTE OR THE METHOD, NEVER A RAW SELECT. Every access claim
below is read back through `GET /portal/me/reports`, through
`GET /portal/me/reports/{report_id}`, or through
`DataAccess.list_my_released_reports` / `get_my_released_report`. Raw SQL
appears three times and only to SET UP: the `tests` catalogue row and the role
grants (as every existing fixture does), and `_tombstone`, which writes two
columns `clinical_app` is REVOKED from writing at all.

RULE 8 — AN ORACLE CAN LIVE IN EITHER CHANNEL. The refusal is asserted as a
SET OF SIZE ONE over `(status_code, response.content)` across TWELVE cases —
anonymous, malformed credential, unknown credential, the other principal's
valid session under each of the two cookie names, a nonexistent report, a
malformed report id, another patient's report, another organisation's report,
and the caller's own draft, under_review and approved reports — with the
positive twin proving the owner's own released report is NOT in that set and
carries its own real values.

RULE 4 — EVERY ABSENCE HAS A POSITIVE TWIN. "The body does not contain X" is
satisfied completely by a surface that returns nothing at all, and this surface
returns nothing at all in production. Every absence row here is paired.

RETRACTION, AND WHY THERE IS NO RETRACTED-REPORT ROW. COUNTED at d6246cd:
`report_retractions` does not exist in schema.sql, `clinical/data_access.py`
has no unapprove/retract/rescind method, and enforce_content_immutability()
FORBIDS walking an approved report back at the database. A retracted report is
not constructible at this SHA, so the queue's "own retracted report WHERE
APPLICABLE" resolves to not applicable — and that is asserted as a measurement
below rather than left as a gap. The established policy, read from the held
w122-retraction branch, points AWAY from hiding: ruling E7 says a retracted
report must not become unfindable and E3 says retraction does not refuse at the
release gate. So this surface filters on RELEASE and never on retraction, and
`test_the_only_thing_that_hides_a_report_from_its_owner_is_release_state` holds
that shape in place.
"""

from __future__ import annotations

import ast
import datetime as dt
import hashlib
import inspect
import json
import os
import pathlib
import uuid

import pytest

DSN = os.getenv("CLINICAL_TEST_DSN")

APP_PASSWORD = "test-app-password"
RETENTION_PASSWORD = "test-retention-password"
PASSWORD = "correct horse battery staple"

PATIENT_COOKIE = "clinical_patient_session"
STAFF_COOKIE = "clinical_session"
CLIENT_IP = "203.0.113.11"

# The one answer every refusal on this surface gives, in BOTH channels.
THE_REFUSAL = (401, json.dumps({"detail": "Authentication failed."}, separators=(",", ":")).encode())

T0 = dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)

VCF_TEXT = (
    "##fileformat=VCFv4.2\n"
    "##assembly=GRCh38\n"
    "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tsample1\n"
    "chr1\t1000\t.\tA\tT\t30\tPASS\t.\tGT\t0/1\n"
)

# A MARKER THAT CANNOT ARRIVE BY COINCIDENCE. It is stored inside the
# interpretation's run_document -- the raw pipeline output that
# `get_interpretation` returns with no report-state check whatsoever -- so any
# body containing it was assembled from raw result data rather than from the
# report's governance record. Nothing else in this repository spells it.
RAW_DATA_MARKER = "w135-raw-pipeline-payload-must-never-reach-a-patient"
RUN_DOCUMENT = {
    "variants": [{"chrom": "1", "pos": 1000, "gene": RAW_DATA_MARKER}],
    "model_version": RAW_DATA_MARKER,
    "run_complete": True,
}


# ─── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def clinical_dsn(monkeypatch):
    psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")
    if not DSN:
        pytest.skip("CLINICAL_TEST_DSN not set")

    from clinical.bootstrap import apply_schema, ensure_roles

    connection = psycopg.connect(DSN, autocommit=False, connect_timeout=10)
    with connection.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    ensure_roles(connection, app_password=APP_PASSWORD, retention_password=RETENTION_PASSWORD)
    apply_schema(connection)
    connection.commit()
    connection.close()

    monkeypatch.setenv("CLINICAL_DSN", DSN)
    return DSN


@pytest.fixture(autouse=True)
def reset_the_login_throttle():
    """Ten attempts per source per minute is the shipped limit and several rows
    here log in as four different principals. A 429 is not the refusal any row
    in this file is about; the limiter has its own file."""
    from clinical.auth_endpoints import _LOGIN_THROTTLE

    _LOGIN_THROTTLE.reset()
    yield
    _LOGIN_THROTTLE.reset()


@pytest.fixture()
def conn(clinical_dsn):
    import psycopg

    connection = psycopg.connect(clinical_dsn, autocommit=False, connect_timeout=10)
    yield connection
    connection.close()


@pytest.fixture()
def dao(conn):
    from clinical.data_access import BcryptHasher, DataAccess

    return DataAccess(conn, password_hasher=BcryptHasher(rounds=4))


@pytest.fixture()
def client(clinical_dsn):
    from fastapi.testclient import TestClient

    from clinical.app import app

    return TestClient(app, client=(CLIENT_IP, 45678))


def _staff(dao, conn, org_id, email):
    """One account holding every role its organisation's work needs -- the same
    shape and the same stated reason as test_record_pipeline_result.py's and
    w134's fixtures. Roles are additive; nothing here relaxes a gate, and the
    Approver grant is what makes `_release_report` reachable at all."""
    user_id = dao.create_user(org_id, email, PASSWORD)
    with conn.cursor() as cur:
        for role in ("Administrator", "Auditor", "Orderer", "Lab technician", "Interpreter"):
            cur.execute(
                "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (user_id, org_id, role, user_id, T0),
            )
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at, basis) "
            "VALUES (%s, %s, 'Approver', %s, %s, %s)",
            (user_id, org_id, user_id, T0, "w135 test fixture: signs and releases the reports it interprets"),
        )
    conn.commit()
    return dao.login(email, org_id, PASSWORD)


def _catalogue_test(conn, org_id):
    test_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tests (test_id, org_id, name, assembly, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (test_id, org_id, "Panel", "GRCh38", "active", T0),
        )
    conn.commit()
    return test_id


@pytest.fixture()
def world(dao, conn):
    """
    TWO organisations; in each, one staff account, TWO enrolled patients and a
    catalogue test.

    TWO OF EVERYTHING, for w137's reason: every question here is "did it reach
    the RIGHT one", and one of anything cannot answer that. THE SAME PATIENT
    EMAIL EXISTS IN BOTH ORGANISATIONS, because `patient_logins_org_email_unique`
    is scoped to the organisation and a tenant test built on two distinct
    addresses would pass against a lookup keyed on the address alone.
    """
    orgs = {}
    for tag, name in (("a", "Org A"), ("b", "Org B")):
        org_id = dao.create_organisation(name)
        staff = _staff(dao, conn, org_id, f"admin@{tag}.example")
        test_id = _catalogue_test(conn, org_id)

        first = dao.create_patient(staff, f"First {tag.upper()}", dt.date(1990, 1, 1), "F")
        second = dao.create_patient(staff, f"Second {tag.upper()}", dt.date(1985, 5, 5), "M")
        dao.enrol_patient_login(staff, first, "patient@shared.example", PASSWORD)
        dao.enrol_patient_login(staff, second, f"second@{tag}.example", PASSWORD)

        orgs[tag] = {
            "org_id": org_id,
            "staff": staff,
            "staff_email": f"admin@{tag}.example",
            "test_id": test_id,
            "first_patient": first,
            "second_patient": second,
            "first_email": "patient@shared.example",
            "second_email": f"second@{tag}.example",
        }
    conn.commit()
    return orgs


@pytest.fixture()
def vcf(tmp_path):
    path = tmp_path / "run.vcf"
    path.write_text(VCF_TEXT, encoding="utf-8")
    return str(path), hashlib.sha256(path.read_bytes()).hexdigest()


# ─── driving the workflow, through the real writers only ─────────────────────


def _pipeline(dao, org, patient_id, vcf, upto):
    """
    Drive ONE order for `patient_id` as far as `upto`, THROUGH THE REAL
    WRITERS AND NO OTHERS, and return (order_id, report_id).

    `released` is reached by calling `_release_report` itself, behind its own
    `_require_role(session, "Approver")` gate and with an actor who separately
    holds Approver. THAT is what makes this a legitimate construction of a
    state no production path in this repository reaches: the state is built by
    the method that owns it, not forged by an UPDATE.
    """
    staff = org["staff"]
    consent_id = dao.record_consent(staff, patient_id, "testing")
    order_id = dao.create_order(
        staff,
        patient_id=patient_id,
        test_id=org["test_id"],
        required_scope="testing",
        consent_id=consent_id,
        priority="routine",
        clinical_indication="w135",
    )
    dao.place_order(staff, order_id)
    sample_id = dao.receive_sample(staff, order_id, "blood")
    dao.record_qc(staff, sample_id, "passed")

    vcf_path, vcf_hash = vcf
    system = dao._create_system_session(org["org_id"])
    result = dao.record_pipeline_result(system, sample_id, vcf_path, vcf_hash, RUN_DOCUMENT)
    report_id = result.report_id
    if upto == "draft":
        return order_id, report_id

    dao.record_sole_signatory_claim(
        staff,
        interpretation_id=result.interpretation_id,
        report_id=report_id,
        reason="w135 fixture: one signatory concurs",
    )
    dao.submit_for_review(staff, report_id)
    if upto == "under_review":
        return order_id, report_id

    dao.approve_report(staff, report_id)
    if upto == "approved":
        return order_id, report_id

    dao._release_report(staff, report_id, consumer="w135-consumer", actor_id=staff.user_id)
    if upto == "released":
        return order_id, report_id

    raise AssertionError(f"unknown stop point {upto!r}")


def _tombstone(conn, org_id, report_id):
    """
    Stamp a report and its delivery records as PURGED.

    RAW SQL DELIBERATELY, AND IT IS NOT A RULE-2a BREACH. `clinical_app` is
    REVOKED from writing tombstoned_at/tombstoned_by at the database (only
    `clinical_retention` may, clinical/retention.py), so there is no method on
    DataAccess that could do this and there must never be one. This is setup;
    the assertion that follows it still reads through the route.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT user_id FROM users WHERE org_id = %s LIMIT 1", (org_id,))
        actor = cur.fetchone()[0]
        cur.execute(
            "UPDATE reports SET tombstoned_at = %s, tombstoned_by = %s WHERE org_id = %s AND id = %s",
            (T0, actor, org_id, report_id),
        )
        cur.execute(
            "UPDATE release_events SET tombstoned_at = %s, tombstoned_by = %s WHERE org_id = %s AND report_id = %s",
            (T0, actor, org_id, report_id),
        )
    conn.commit()


def _portal_login(client, org_id, email, password=PASSWORD):
    from clinical.auth_endpoints import _LOGIN_THROTTLE

    _LOGIN_THROTTLE.reset()
    response = client.post("/portal/login", json={"email": email, "org_id": str(org_id), "password": password})
    assert response.status_code == 204, response.text
    header = response.headers.get_list("set-cookie")[0]
    return header.split("=", 1)[1].split(";", 1)[0]


def _staff_login(client, org_id, email):
    from clinical.auth_endpoints import _LOGIN_THROTTLE

    _LOGIN_THROTTLE.reset()
    response = client.post("/auth/login", json={"email": email, "org_id": str(org_id), "password": PASSWORD})
    assert response.status_code == 204, response.text
    header = response.headers.get_list("set-cookie")[0]
    return header.split("=", 1)[1].split(";", 1)[0]


def _reports_over_http(client, cookie):
    """The patient's reports AS THE ROUTE REPORTS THEM. An in-process call to
    the data layer is not what a patient is told."""
    response = client.get("/portal/me/reports", cookies={PATIENT_COOKIE: cookie})
    assert response.status_code == 200, response.text
    return response.json()


# ─── 1. what a released report consists of, and what it never carries ────────


class TestWhatAReleasedReportConsistsOfInThisModel:
    """
    THE MEASUREMENT FIRST. These rows state, executably, what the model
    supports -- so that a later reader who expects report content finds the
    reason rather than an apology.
    """

    def test_the_reports_table_has_no_content_column(self, conn, world):
        """
        THE PREMISE OF THE WHOLE WAVE, ESTABLISHED RATHER THAN ASSERTED IN
        PROSE. Read from information_schema, which is the database's own
        account of itself.

        Catches: a later wave adding report-content storage without revisiting
        this surface -- at which point every refusal below needs re-deciding,
        because there would at last be something to withhold. Vacuous against:
        anything about who may read what; it is a statement about the schema.
        """
        with conn.cursor() as cur:
            cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'reports' AND table_schema = 'public'"
            )
            columns = {row[0] for row in cur.fetchall()}
        assert columns, "no columns found -- this row would pass vacuously"
        assert columns == {
            "org_id",
            "id",
            "interpretation_id",
            "created_at",
            "created_by",
            "state",
            "approver_id",
            "approved_at",
            "content_hash",
            "tombstoned_at",
            "tombstoned_by",
            "retention_days",
        }, columns
        for suspicious in ("content", "body", "document", "pdf", "html", "text", "narrative"):
            assert suspicious not in columns, f"reports now stores {suspicious!r} -- w135's premise has changed"

    def test_a_released_report_carries_three_fields_and_they_are_all_real(self, client, dao, conn, world, vcf):
        """
        THE POSITIVE TWIN FOR EVERY ABSENCE ROW IN THIS FILE, and it asserts
        VALUES, not shape: the report id the writers actually produced, the
        order it belongs to, and a release timestamp that parses.

        Catches: a surface that returns an empty list for everybody, which
        satisfies every "does not contain" row in this file completely -- and
        which is, measured, what this deployment returns in production.
        """
        order_id, report_id = _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, "released")
        conn.commit()
        cookie = _portal_login(client, world["a"]["org_id"], world["a"]["first_email"])

        body = _reports_over_http(client, cookie)
        assert len(body) == 1, body
        item = body[0]
        assert set(item) == {"report_id", "order_id", "released_at"}, item
        assert item["report_id"] == str(report_id), item
        assert item["order_id"] == str(order_id), item
        assert dt.datetime.fromisoformat(item["released_at"]) is not None, item

    def test_no_interpretation_id_approver_or_content_hash_is_returned(self, client, dao, conn, world, vcf):
        """
        THE FOUR DELIBERATE OMISSIONS, asserted on the body of a REAL released
        report so the row cannot pass on an empty one.

        `interpretation_id` is the one that matters: it is the handle that
        addresses the raw run_document, and `get_interpretation` reads that
        with no report-state check at all. Catches: a "helpful" widening of
        PortalReportItem. Vacuous against: a leak of the run_document's
        CONTENTS without its id -- which is the next class.
        """
        _, report_id = _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, "released")
        conn.commit()
        cookie = _portal_login(client, world["a"]["org_id"], world["a"]["first_email"])

        raw = client.get("/portal/me/reports", cookies={PATIENT_COOKIE: cookie}).content
        assert str(report_id).encode() in raw, "the positive half failed -- this row would be vacuous"
        for forbidden in (b"interpretation", b"approver", b"content_hash", b"created_by", b"vcf"):
            assert forbidden not in raw.lower(), (forbidden, raw)


# ─── 2. only a released report is reachable ──────────────────────────────────


class TestOnlyAReleasedReportIsReachableByItsOwnPatient:
    """
    THE HARDEST REFUSAL ON THIS SURFACE, because the report really is the
    patient's. Each row drives the workflow through the real writers to exactly
    one state and reads back through the real route.
    """

    @pytest.mark.parametrize("state", ["draft", "under_review", "approved"])
    def test_an_unreleased_report_of_the_patients_own_is_not_listed(self, client, dao, conn, world, vcf, state):
        """
        Catches: a surface filtering on `reports.state IN ('approved',
        'released')` -- which is what `require_release` admits, and is WRONG
        for a patient, because approval is authority to release and release is
        the delivery that actually happened. Also catches no filter at all.
        Vacuous against: a surface that lists nothing (twin above).
        """
        _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, state)
        conn.commit()
        cookie = _portal_login(client, world["a"]["org_id"], world["a"]["first_email"])
        assert _reports_over_http(client, cookie) == []

    @pytest.mark.parametrize("state", ["draft", "under_review", "approved"])
    def test_an_unreleased_report_of_the_patients_own_is_refused_by_id(self, client, dao, conn, world, vcf, state):
        """
        The addressable half. A patient who has learned a report id -- from an
        earlier release, from a letter, by guessing -- still cannot read the
        unreleased one, and the refusal is THE refusal, carrying no hint that
        the id is real.
        """
        _, report_id = _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, state)
        conn.commit()
        cookie = _portal_login(client, world["a"]["org_id"], world["a"]["first_email"])
        response = client.get(f"/portal/me/reports/{report_id}", cookies={PATIENT_COOKIE: cookie})
        assert (response.status_code, response.content) == THE_REFUSAL, response.text

    def test_the_positive_twin_releasing_that_same_report_makes_it_readable(self, client, dao, conn, world, vcf):
        """
        THE ROW THE THREE ABOVE CANNOT DO WITHOUT. They are satisfied
        completely by a route that refuses every report in every state.

        The SAME report, driven one method further -- `_release_report`, the
        real writer -- flips from the refusal to a 200 carrying its own id.
        Catches: a surface that refuses everything, and a release predicate
        that never admits anything.
        """
        _, report_id = _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, "approved")
        conn.commit()
        cookie = _portal_login(client, world["a"]["org_id"], world["a"]["first_email"])

        before = client.get(f"/portal/me/reports/{report_id}", cookies={PATIENT_COOKIE: cookie})
        assert (before.status_code, before.content) == THE_REFUSAL, before.text

        dao._release_report(world["a"]["staff"], report_id, consumer="w135-twin", actor_id=world["a"]["staff"].user_id)
        conn.commit()

        after = client.get(f"/portal/me/reports/{report_id}", cookies={PATIENT_COOKIE: cookie})
        assert after.status_code == 200, after.text
        assert after.json()["report_id"] == str(report_id), after.text
        assert (after.status_code, after.content) != THE_REFUSAL

    def test_a_state_column_forged_to_released_without_a_delivery_record_is_not_shown(
        self, client, dao, conn, world, vcf
    ):
        """
        THE ROW THE WRONG-FIRST MEASUREMENT ASKED FOR, and it is here because
        the measurement said the others could not do this job.

        WHAT WAS MEASURED. Wrong version W3 -- the release filter widened to
        `state IN ('approved','released')`, i.e. `require_release`'s own
        predicate -- passed EVERY behavioural row in this file. The reason is
        that the two halves of the release test are redundant **given the real
        writers**: an approved report has no `release_events` row either, so
        the lateral delivery requirement excludes it whatever the state
        predicate says. No row driven through the real writers can tell the two
        apart, because the real writers never separate them.

        SO THIS ROW SEPARATES THEM THE ONLY WAY THE PLATFORM ACTUALLY CAN.
        `clinical_app` holds `GRANT UPDATE (state, approver_id, approved_at,
        content_hash) ON reports` (schema.sql), and the content-immutability
        trigger permits exactly `approved -> released`. So a defective code
        path CAN move that column without inserting a delivery record, and the
        result is a report the summary calls released and the record of
        deliveries has never heard of.

        Catches: a surface that trusts `reports.state` alone -- which is the
        cheap version of this query, and which `_release_report`'s own
        docstring warns against by calling the column "a DERIVED SUMMARY …
        not itself the record of who received what and when". Vacuous against:
        every isolation question, and against W3, which is why the structural
        rows are not deleted either.
        """
        org = world["a"]
        _, report_id = _pipeline(dao, org, org["first_patient"], vcf, "approved")
        conn.commit()
        cookie = _portal_login(client, org["org_id"], org["first_email"])
        assert _reports_over_http(client, cookie) == []

        with conn.cursor() as cur:
            cur.execute(
                "UPDATE reports SET state = 'released' WHERE org_id = %s AND id = %s",
                (org["org_id"], report_id),
            )
            cur.execute(
                "SELECT count(*) FROM release_events WHERE org_id = %s AND report_id = %s",
                (org["org_id"], report_id),
            )
            assert cur.fetchone()[0] == 0, "the premise failed -- a delivery record exists after all"
        conn.commit()

        assert _reports_over_http(client, cookie) == [], (
            "a report whose state column says 'released' but for which no delivery was ever "
            "recorded reached its patient. release_events is the record of what left the platform; "
            "reports.state is a derived summary of it."
        )
        one = client.get(f"/portal/me/reports/{report_id}", cookies={PATIENT_COOKIE: cookie})
        assert (one.status_code, one.content) == THE_REFUSAL, one.text

    def test_a_report_released_twice_appears_once_and_dates_from_the_first(self, client, dao, conn, world, vcf):
        """
        THE FAN-OUT, one table over from w134's. `release_events` is an EVENT
        table: releasing to a second consumer inserts a second row. A plain
        JOIN would show the patient the same report twice.

        Catches: exactly that -- and a `released_at` taken as `max`, which
        would move the date a patient was told their report was issued every
        time the laboratory sent it somewhere else. Vacuous against: every
        isolation question.
        """
        _, report_id = _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, "released")
        conn.commit()
        cookie = _portal_login(client, world["a"]["org_id"], world["a"]["first_email"])
        first_seen = _reports_over_http(client, cookie)[0]["released_at"]

        dao._release_report(
            world["a"]["staff"], report_id, consumer="a-second-consumer", actor_id=world["a"]["staff"].user_id
        )
        conn.commit()

        body = _reports_over_http(client, cookie)
        assert len(body) == 1, body
        assert body[0]["report_id"] == str(report_id), body
        assert body[0]["released_at"] == first_seen, body


# ─── 3. raw result data does not bypass the release rules ────────────────────


class TestRawResultDataDoesNotBypassTheReleaseRules:
    """
    The queue's fourth requirement, and the trap w137 named: `get_interpretation`
    returns the entire raw `run_document` with NO report-state check.
    """

    def test_no_run_document_content_reaches_the_patient_on_a_released_report(self, client, dao, conn, world, vcf):
        """
        BEHAVIOURAL, not structural. A marker string is stored inside the
        interpretation's run_document by the real pipeline writer and must
        appear in NEITHER report route's body, on a report that IS released --
        so the row cannot pass merely because the report was withheld.

        Catches: any future widening that reaches through interpretation_id to
        "show the patient their results". Vacuous against: a leak of report
        metadata, which the rows above cover.
        """
        _, report_id = _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, "released")
        conn.commit()
        cookie = _portal_login(client, world["a"]["org_id"], world["a"]["first_email"])

        listed = client.get("/portal/me/reports", cookies={PATIENT_COOKIE: cookie})
        one = client.get(f"/portal/me/reports/{report_id}", cookies={PATIENT_COOKIE: cookie})
        assert listed.status_code == 200 and one.status_code == 200, (listed.text, one.text)
        assert str(report_id).encode() in one.content, "the positive half failed -- this row would be vacuous"

        for response in (listed, one):
            assert RAW_DATA_MARKER.encode() not in response.content, response.text
            assert b"variants" not in response.content, response.text

    def test_the_marker_really_is_in_the_raw_interpretation(self, dao, conn, world, vcf):
        """
        THE PREMISE OF THE ROW ABOVE, ESTABLISHED RATHER THAN ASSUMED (Rule 4
        in miniature, and the shape w138 learned the hard way). If the marker
        were not actually stored, the absence row above would pass against a
        surface that leaked everything.

        Read through `get_interpretation` -- the real method, the actual trap --
        with a STAFF session, which is the only principal that can reach it.
        """
        _, report_id = _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, "released")
        conn.commit()
        report = dao.get_report(world["a"]["staff"], report_id)
        raw = dao.get_interpretation(world["a"]["staff"], report["interpretation_id"])
        assert raw is not None
        assert RAW_DATA_MARKER in json.dumps(raw["run_document"]), raw["run_document"]

    def test_no_portal_handler_reaches_raw_result_data(self):
        """
        THE STRUCTURAL COMPANION, with its own non-vacuity check. The
        behavioural row above sees one response; this sees the whole module,
        including a route nobody remembered to probe.

        The search is PROVED TO WORK by asserting the same needles DO occur in
        `data_access.py` -- so a typo in a needle fails here instead of passing
        silently, which is how an absence assertion normally goes wrong.

        DOCSTRINGS ARE STRIPPED THROUGH THE AST, not by splitting on `\"\"\"`.
        The first version of this row split the file on the third quote and
        searched the rest -- and FAILED AGAINST CORRECT CODE, because the
        module docstring is not the only documentation in the file: the new
        response model and the new handler both EXPLAIN, in their own
        docstrings, why they do not touch `run_document`. Documentation saying
        a thing is absent must not be what makes the guard think it is
        present. The fix was to the test.
        """
        import clinical.data_access
        import clinical.portal_endpoints

        needles = ("run_document", "get_interpretation", "find_interpretations_by_criteria", "variants")
        data_access_source = pathlib.Path(inspect.getfile(clinical.data_access)).read_text(encoding="utf-8")
        for needle in needles:
            assert needle in data_access_source, f"needle {needle!r} spells nothing -- the search is broken"

        tree = ast.parse(pathlib.Path(inspect.getfile(clinical.portal_endpoints)).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                body = node.body
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    body[0].value.value = ""
        executable = ast.unparse(tree)
        assert "PortalReportItem" in executable, "the AST strip removed too much -- this row would be vacuous"
        for needle in needles:
            assert needle not in executable, f"clinical/portal_endpoints.py now mentions {needle!r} in executable code"


# ─── 4. patient isolation and tenant isolation, separately ───────────────────


class TestThePatientReachesOnlyTheirOwnReport:
    def test_two_patients_in_one_organisation_get_two_different_lists(self, client, dao, conn, world, vcf):
        """
        THE PATIENT AXIS ALONE -- one organisation, so an org predicate cannot
        be doing the work. Both patients have a released report; each must see
        exactly their own.

        Catches: the patient predicate dropped from the anchor, which leaves a
        surface that is still perfectly tenant-isolated. Vacuous against: a
        surface that returns nothing (both lists would be empty and unequal to
        the asserted contents, so in fact it is not -- the assertion is on
        CONTENT).
        """
        org = world["a"]
        _, first_report = _pipeline(dao, org, org["first_patient"], vcf, "released")
        _, second_report = _pipeline(dao, org, org["second_patient"], vcf, "released")
        conn.commit()

        first_cookie = _portal_login(client, org["org_id"], org["first_email"])
        second_cookie = _portal_login(client, org["org_id"], org["second_email"])

        first_ids = {r["report_id"] for r in _reports_over_http(client, first_cookie)}
        second_ids = {r["report_id"] for r in _reports_over_http(client, second_cookie)}
        assert first_ids == {str(first_report)}, first_ids
        assert second_ids == {str(second_report)}, second_ids
        assert first_ids.isdisjoint(second_ids)

    def test_the_same_email_in_two_organisations_reaches_two_different_reports(self, client, dao, conn, world, vcf):
        """
        THE TENANT AXIS ALONE, and it is built the only way that proves
        anything: THE SAME ADDRESS is enrolled in both organisations, so a
        lookup keyed on the address rather than on (org, address) fails here.

        Catches: an org predicate dropped from the anchor or from any join in
        the six-table chain. Vacuous against: patient-axis leaks within one
        organisation -- the row above.
        """
        _, a_report = _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, "released")
        _, b_report = _pipeline(dao, world["b"], world["b"]["first_patient"], vcf, "released")
        conn.commit()
        assert a_report != b_report

        a_cookie = _portal_login(client, world["a"]["org_id"], world["a"]["first_email"])
        b_cookie = _portal_login(client, world["b"]["org_id"], world["b"]["first_email"])

        assert {r["report_id"] for r in _reports_over_http(client, a_cookie)} == {str(a_report)}
        assert {r["report_id"] for r in _reports_over_http(client, b_cookie)} == {str(b_report)}

    def test_a_patient_id_supplied_in_any_channel_cannot_change_whose_reports_come_back(
        self, client, dao, conn, world, vcf
    ):
        """
        THE QUEUE'S "no patient-supplied identifier may override session
        identity", on the new routes specifically rather than inherited from
        `/portal/me`'s rows.

        Five channels, the victim's REAL patient id, on BOTH new routes. The
        answer must be identical to the answer with no parameter at all.

        Catches: a handler that grew a `patient_id` parameter. Vacuous against:
        a leak that needs no parameter -- the two rows above.
        """
        org = world["a"]
        _, mine = _pipeline(dao, org, org["first_patient"], vcf, "released")
        _pipeline(dao, org, org["second_patient"], vcf, "released")
        conn.commit()

        cookie = _portal_login(client, org["org_id"], org["first_email"])
        victim = str(org["second_patient"])
        baseline = client.get("/portal/me/reports", cookies={PATIENT_COOKIE: cookie}).content
        assert str(mine).encode() in baseline, "the positive half failed -- this row would be vacuous"

        attempts = [
            client.get(f"/portal/me/reports?patient_id={victim}", cookies={PATIENT_COOKIE: cookie}),
            client.get(f"/portal/me/reports?patient={victim}", cookies={PATIENT_COOKIE: cookie}),
            client.request("GET", "/portal/me/reports", json={"patient_id": victim}, cookies={PATIENT_COOKIE: cookie}),
            client.get(
                "/portal/me/reports",
                headers={"X-Patient-Id": victim},
                cookies={PATIENT_COOKIE: cookie},
            ),
            client.get(f"/portal/me/reports?org_id={world['b']['org_id']}", cookies={PATIENT_COOKIE: cookie}),
        ]
        for response in attempts:
            assert response.status_code == 200, response.text
            assert response.content == baseline, response.text
            assert victim.encode() not in response.content, response.text


# ─── 5. the refusal is one pair, over every case, in both channels ───────────


class TestEveryRefusalOnTheReportRoutesIsOnePair:
    """
    RULE 8 IN ITS FULL FORM. Not a per-case equality -- a SET, so a leak in a
    case nobody thought to list still fails; and over `(status, content)`, so
    an oracle that lives only in the status channel is visible.

    The measured house result this shape exists for: a wrong version passing
    159 of 161 rows, caught by two -- both of them set rows, both new.
    """

    def _cases(self, client, dao, conn, world, vcf):
        org, other = world["a"], world["b"]
        _, own_released = _pipeline(dao, org, org["first_patient"], vcf, "released")
        _, own_draft = _pipeline(dao, org, org["first_patient"], vcf, "draft")
        _, own_under_review = _pipeline(dao, org, org["first_patient"], vcf, "under_review")
        _, own_approved = _pipeline(dao, org, org["first_patient"], vcf, "approved")
        _, neighbours = _pipeline(dao, org, org["second_patient"], vcf, "released")
        _, foreign = _pipeline(dao, other, other["first_patient"], vcf, "released")
        conn.commit()

        mine = _portal_login(client, org["org_id"], org["first_email"])
        staff_cookie = _staff_login(client, org["org_id"], org["staff_email"])

        nonexistent = uuid.uuid4()
        good = {PATIENT_COOKIE: mine}
        return own_released, {
            # EVERY case carries a NON-EMPTY report id, including the ones
            # where the credential is what is wrong. An empty string would make
            # `report_id.encode() not in response.content` vacuously false in
            # the body-channel row below -- b"" is in everything. Found by that
            # row failing against correct code; the fix was to the test.
            "anonymous": (str(nonexistent), {}),
            "malformed credential": (str(nonexistent), {PATIENT_COOKIE: "not-a-uuid"}),
            "unknown credential": (str(nonexistent), {PATIENT_COOKIE: str(uuid.uuid4())}),
            "a valid STAFF session": (str(own_released), {PATIENT_COOKIE: staff_cookie}),
            "the staff cookie name": (str(own_released), {STAFF_COOKIE: staff_cookie}),
            "a nonexistent report": (str(nonexistent), good),
            "a malformed report id": ("not-a-uuid", good),
            "another patient, same org": (str(neighbours), good),
            "another organisation": (str(foreign), good),
            "my own draft": (str(own_draft), good),
            "my own under_review": (str(own_under_review), good),
            "my own approved": (str(own_approved), good),
        }

    def test_twelve_cases_on_the_report_route_are_one_pair(self, client, dao, conn, world, vcf):
        """
        THE ROW THIS WAVE IS FOR.

        Catches: any divergence at all between the twelve -- a 404 for the
        nonexistent one and a 401 for the anonymous one (status channel), or a
        body that names the report id in one of them (body channel). Vacuous
        against: a route that refuses EVERYTHING, which is why the twin below
        is not optional.
        """
        _, cases = self._cases(client, dao, conn, world, vcf)
        assert len(cases) == 12, "a case left the list without being replaced"

        observed = {}
        for name, (report_id, cookies) in cases.items():
            response = client.get(f"/portal/me/reports/{report_id}", cookies=cookies)
            observed[name] = (response.status_code, response.content)

        assert len(set(observed.values())) == 1, {k: (s, b[:160]) for k, (s, b) in observed.items()}
        assert set(observed.values()) == {THE_REFUSAL}, observed

    def test_no_refusal_names_any_identifier_it_was_given(self, client, dao, conn, world, vcf):
        """
        THE BODY CHANNEL ON ITS OWN. A set of size one is already violated by
        bodies that DIFFER -- this row exists so that a future change leaking
        the SAME shape of identifier into ALL twelve (and so keeping the set at
        size one) still fails.

        Catches: `f"Report {report_id} not found"` reaching the caller, which
        is the exact spelling `get_my_released_report` avoids by using a module
        constant.
        """
        _, cases = self._cases(client, dao, conn, world, vcf)
        for name, (report_id, cookies) in cases.items():
            response = client.get(f"/portal/me/reports/{report_id}", cookies=cookies)
            assert report_id.encode() not in response.content, (name, response.text)
            for word in (b"report", b"patient", b"organisation", b"draft", b"released", b"approved"):
                assert word not in response.content.lower(), (name, word, response.text)

    def test_the_positive_twin_the_owner_of_a_released_report_is_not_in_that_set(self, client, dao, conn, world, vcf):
        """
        THE TWIN WITHOUT WHICH BOTH ROWS ABOVE ARE SATISFIED BY A ROUTE THAT
        REFUSES EVERYONE -- and in this deployment, where nothing releases a
        report, that is not a hypothetical.

        Asserted on CONTENT, not merely "not the refusal pair": a 200 carrying
        the WRONG report is worse than a refusal.
        """
        own_released, cases = self._cases(client, dao, conn, world, vcf)
        cookies = cases["my own draft"][1]

        response = client.get(f"/portal/me/reports/{own_released}", cookies=cookies)
        assert response.status_code == 200, response.text
        assert (response.status_code, response.content) != THE_REFUSAL
        assert response.json()["report_id"] == str(own_released), response.text
        assert response.json()["report_id"] != cases["another patient, same org"][0]

    def test_the_list_route_is_not_an_existence_oracle_either(self, client, dao, conn, world, vcf):
        """
        THE OTHER CHANNEL THE LIST ROUTE HAS. It takes no identifier, so its
        oracle -- if it had one -- would be the SUCCESS answer: a patient whose
        neighbours and whose other-organisation namesake have released reports
        must be indistinguishable from a patient in an empty world.

        A SET OF SIZE ONE over `(status, content)` across three shapes, all
        `(200, b"[]")`, with the owner's twin asserted NOT in it.
        """
        org, other = world["a"], world["b"]
        _pipeline(dao, org, org["second_patient"], vcf, "released")
        _pipeline(dao, other, other["first_patient"], vcf, "released")
        _, own_draft_only = _pipeline(dao, org, org["first_patient"], vcf, "draft")
        conn.commit()

        mine = _portal_login(client, org["org_id"], org["first_email"])
        elsewhere = _portal_login(client, other["org_id"], other["second_email"])

        observed = {
            "a patient whose only report is a draft": client.get("/portal/me/reports", cookies={PATIENT_COOKIE: mine}),
            "the same request with an invented patient_id": client.get(
                f"/portal/me/reports?patient_id={org['second_patient']}", cookies={PATIENT_COOKIE: mine}
            ),
            "a patient in the other organisation with nothing": client.get(
                "/portal/me/reports", cookies={PATIENT_COOKIE: elsewhere}
            ),
        }
        pairs = {name: (r.status_code, r.content) for name, r in observed.items()}
        assert len(set(pairs.values())) == 1, pairs
        assert set(pairs.values()) == {(200, b"[]")}, pairs

        # AND THE DRAFT REALLY IS UNRELEASABLE, so the `[]` above is produced
        # by the release predicate rather than by an empty world:
        # `_release_report` refuses a report that was never approved, which is
        # spec 13.4 enforced by the writer itself.
        with pytest.raises(ValueError):
            dao._release_report(org["staff"], own_draft_only, consumer="twin", actor_id=org["staff"].user_id)

    def test_the_positive_twin_a_released_report_is_not_the_empty_answer(self, client, dao, conn, world, vcf):
        """Catches: a list route that returns `[]` for everybody, which
        satisfies the set row above completely."""
        org = world["a"]
        _, released = _pipeline(dao, org, org["first_patient"], vcf, "released")
        conn.commit()
        cookie = _portal_login(client, org["org_id"], org["first_email"])
        response = client.get("/portal/me/reports", cookies={PATIENT_COOKIE: cookie})
        assert (response.status_code, response.content) != (200, b"[]"), response.text
        assert response.json()[0]["report_id"] == str(released), response.text


# ─── 6. the data layer, below the route ──────────────────────────────────────


class TestTheDataLayerMethodIsTheOneThatEnforcesIt:
    """
    RULE 2a AT THE LAYER BELOW THE ROUTE. A route test cannot tell whether the
    refusal came from the handler or from the query, and a later caller of the
    data layer that is not this handler gets whatever the query does.
    """

    def test_a_staff_session_is_refused_by_both_methods(self, dao, conn, world, vcf):
        """
        DECISION 8: a staff session does not become a patient session by
        duck-typing. Both carry org_id, so a staff session handed to a portal
        method would satisfy the org predicate and then fail on the missing
        patient_id with an AttributeError -- an accident that looks like a bug.
        This makes it a refusal.
        """
        from clinical.data_access import AuthorizationError

        _, report_id = _pipeline(dao, world["a"], world["a"]["first_patient"], vcf, "released")
        conn.commit()
        with pytest.raises(AuthorizationError):
            dao.list_my_released_reports(world["a"]["staff"])
        with pytest.raises(AuthorizationError):
            dao.get_my_released_report(world["a"]["staff"], report_id)

    def test_the_method_refuses_another_patients_report_with_the_module_constant(self, dao, conn, world, vcf):
        """
        The refusal the ROUTE collapses onto its 401 -- asserted here, where it
        is still distinguishable, so that the constant is what the data layer
        actually raises and not a sentence assembled per call site.
        """
        from clinical.data_access import REPORT_NOT_FOUND, NotFoundError

        org = world["a"]
        _pipeline(dao, org, org["first_patient"], vcf, "released")
        _, neighbours = _pipeline(dao, org, org["second_patient"], vcf, "released")
        conn.commit()

        session = dao.patient_login(org["first_email"], org["org_id"], PASSWORD)
        with pytest.raises(NotFoundError) as excinfo:
            dao.get_my_released_report(session, neighbours)
        assert str(excinfo.value) == REPORT_NOT_FOUND, str(excinfo.value)
        assert str(neighbours) not in str(excinfo.value)

    def test_the_two_methods_share_one_sql_text(self):
        """
        THE STRUCTURAL GUARANTEE THAT THE LIST AND THE SINGLE READ CANNOT
        DISAGREE. Two copies of a six-table join is two places for an org
        predicate to be dropped from, and only one of them is exercised by the
        isolation tests somebody remembers to write.

        Catches: a later editor inlining one of them. Non-vacuity: the shared
        text is asserted to contain the two session-bound predicates, so this
        row fails if the constant is emptied rather than merely copied.
        """
        import clinical.data_access
        from clinical.data_access import DataAccess

        shared = DataAccess._MY_RELEASED_REPORTS_SQL
        assert "p.patient_id = %s AND p.org_id = %s" in shared, shared
        assert "rep.state = 'released'" in shared, shared

        # Read from the FILE rather than through `inspect.getsource` on the
        # methods: both carry @auditable and @transactional, and w138 measured
        # that getsource on a decorated method here returns the DECORATOR's
        # body -- an eleven-thousand-character wrapper containing none of the
        # method's own text. A row built on that would have compared nothing
        # to nothing.
        source = pathlib.Path(inspect.getfile(clinical.data_access)).read_text(encoding="utf-8")
        assert source.count("JOIN sequencing_runs r ON r.org_id = s.org_id") == 1, (
            "the patient report join is written more than once -- two places for an org predicate "
            "to be dropped from, and only one of them is tested"
        )
        assert source.count("_MY_RELEASED_REPORTS_SQL") == 3, (
            "expected one definition and exactly two callers of the shared SQL"
        )


# ─── 7. retraction: the measurement, and the shape it forces ─────────────────


class TestTheRetractionQuestionAsItStandsAtThisSHA:
    """
    THE QUEUE ASKS FOR "own retracted report WHERE APPLICABLE". These rows
    establish, executably, that it is NOT applicable at this SHA -- and pin the
    shape that keeps this surface correct when the held model lands.
    """

    def test_no_retraction_mechanism_exists_in_this_schema(self, conn, world):
        """
        THE MEASUREMENT. `report_retractions` is on the held, unmerged
        w122-retraction branch; it does not exist here, so a retracted report
        cannot be constructed and no row in this file pretends to.

        Catches: w122 being merged without anyone revisiting this surface --
        at which point rulings E3 and E7 have to be applied to the patient
        view, and this row is where whoever merges it finds out.
        """
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.report_retractions'), to_regclass('public.reports')")
            retractions, reports = cur.fetchone()
        assert reports is not None, "the probe is broken -- `reports` should exist"
        assert retractions is None, (
            "report_retractions now exists. w122's rulings E3/E7 say a retracted report must NOT be "
            "hidden or made unfindable -- decide what the PATIENT sees and revisit w135."
        )

    def test_the_clinical_layer_has_no_operation_that_retracts_an_approval(self):
        """
        THE OTHER HALF OF THE SAME MEASUREMENT, at the code rather than the
        schema, and the reason the first is not merely an omission: the
        database FORBIDS walking an approved report back
        (enforce_content_immutability), so retraction cannot be simulated by
        moving `state` either.

        Non-vacuity: the same search is asserted to FIND the verbs that do
        exist, so a typo fails here rather than passing silently.
        """
        import clinical.data_access

        source = pathlib.Path(inspect.getfile(clinical.data_access)).read_text(encoding="utf-8")
        for present in ("def approve_report", "def _release_report", "def create_amendment"):
            assert present in source, f"{present!r} spells nothing -- the search is broken"
        for absent in ("def retract_report", "def unapprove_report", "def rescind_report"):
            assert absent not in source, f"{absent} now exists -- w135's retraction verdict needs revisiting"

    def test_the_only_thing_that_hides_a_report_from_its_owner_is_release_state(self):
        """
        THE FORWARD-SAFE SHAPE, PINNED. w122's ruling E7 is explicit that a
        retracted report must not become UNFINDABLE, and E3 that retraction
        does not refuse at the release gate -- the retraction travels with the
        document instead. So the correct predicate on this surface is release,
        and only release.

        Catches: a later implementer adding `AND NOT EXISTS (SELECT 1 FROM
        report_retractions ...)` or a tombstone filter to this query, which
        would contradict E7 and would have to be removed again. Vacuous
        against: everything about who may read what -- it is a statement about
        one SQL text, and it is paired with the behavioural rows above.
        """
        from clinical.data_access import DataAccess

        shared = DataAccess._MY_RELEASED_REPORTS_SQL
        assert "rep.state = 'released'" in shared, shared
        assert "retract" not in shared.lower(), shared
        assert "tombston" not in shared.lower(), shared

    def test_a_tombstoned_report_still_appears_and_that_is_an_open_ruling(self, client, dao, conn, world, vcf):
        """
        RECORDED BEHAVIOUR, NOT AN ENDORSEMENT -- and it is recorded as a test
        precisely so that it is visible rather than accidental.

        MEASURED at d6246cd: `tombstoned_at IS NULL` appears ZERO times in
        clinical/data_access.py. No reader in that file filters it and this one
        follows the established convention rather than inventing a second.

        THE RULING IS EXPLICITLY OPEN, by the human ruling this surface would
        otherwise be deciding by accident. clinical/retention.py, D4: "tombstone,
        not delete ... Content redaction beyond that is NOT implemented here --
        D4's ruling settles that this is not a real delete, NOT WHAT, IF
        ANYTHING, GETS REDACTED INSIDE A TOMBSTONED ROW. That is a narrower,
        still-open question." A purged report carries no content in this schema
        to begin with, so what the patient loses is the FACT that a report was
        issued to them -- which is a retention ruling and not a security one.

        Carded as W135-C4. If the ruling comes back the other way, this row is
        the one that changes, and its failure message says so.
        """
        org = world["a"]
        _, report_id = _pipeline(dao, org, org["first_patient"], vcf, "released")
        conn.commit()
        cookie = _portal_login(client, org["org_id"], org["first_email"])
        assert {r["report_id"] for r in _reports_over_http(client, cookie)} == {str(report_id)}

        _tombstone(conn, org["org_id"], report_id)

        still_there = {r["report_id"] for r in _reports_over_http(client, cookie)}
        assert still_there == {str(report_id)}, (
            "a tombstoned report is no longer listed. That may well be right -- but it is a RETENTION "
            "ruling (retention.py D4, explicitly left open) and not something this surface may decide "
            "by accident. See card W135-C4."
        )
