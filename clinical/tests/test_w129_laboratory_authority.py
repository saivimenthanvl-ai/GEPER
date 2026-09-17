"""
clinical/tests/test_w129_laboratory_authority.py
────────────────────────────────────────────────

w129 phase B item 6, second half: the Lab technician role gates the
sample / laboratory-processing / QC operations.

Like `Orderer`, `Lab technician` appeared exactly ONCE in all non-test Python
of clinical/ and geper/ before this wave -- inside the ROLES tuple at
data_access.py:67. Assignable, recorded, and consulted by nothing. Receiving a
specimen and signing off its QC were permitted to every authenticated session
in the organisation equally.

WHICH OPERATIONS REQUIRE IT IS READ OFF THE CODE. The complete list of
sample / laboratory / QC operations in clinical/data_access.py, from scanning
every method definition in the file:

    receive_sample        -- the specimen arrives; received_by and
                             collected_by are stamped from the session
    record_qc             -- the QC verdict; qc_recorded_by from the session
    create_sequencing_run -- the run performed on that sample, created_by
                             from the session
    create_vcf            -- the variant-call artefact that run produced,
                             created_by from the session

All four write laboratory PROVENANCE out of the session -- who received it,
who passed it, who ran it -- which is precisely the claim a role is for. The
readers beside them (get_sample, get_sequencing_run, get_vcf, check_qc_passed)
are deliberately untouched: the ruling leaves reads on the existing model.

`record_pipeline_result` is NOT gated and NOT in the list. It is the automatic
submission path and it runs under the System principal
(`_create_system_session`), which the ruling names as an internal principal
that must not be treated as a normal human staff role. `record_fastq_set` and
`find_fastq_set_by_checksums` are also excluded, for a harder reason: they
take a raw `org_id` and NO session, so there is no session whose roles could
be consulted. That is reported, not worked around -- inventing a session for
them would be the parallel mechanism this wave is forbidden to build.

THE FOUR CELLS are tested for each operation: right role + right organisation
allowed; wrong role + right organisation refused; right role + WRONG
organisation refused; wrong role + wrong organisation refused.
"""

from __future__ import annotations

import datetime
from datetime import date, timezone
import os
import uuid

import pytest

from clinical.data_access import (
    AuthorizationError,
    BcryptHasher,
    DataAccess,
    NotFoundError,
    SystemClock,
)

DSN = os.getenv("CLINICAL_TEST_DSN")
SCHEMA_PATH = __import__("pathlib").Path(__file__).parent.parent / "schema.sql"

_CREATE_ROLE = "DO $$ BEGIN CREATE ROLE clinical_app; EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
_CREATE_ROLE_RETENTION = (
    "DO $$ BEGIN CREATE ROLE clinical_retention; EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
)

T0 = datetime.datetime(2026, 9, 1, tzinfo=timezone.utc)

_MINIMAL_VCF = "##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n"


@pytest.fixture()
def conn():
    psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")
    if not DSN:
        pytest.skip("CLINICAL_TEST_DSN not set")
    connection = psycopg.connect(DSN, autocommit=False, connect_timeout=10)
    with connection.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        cur.execute(_CREATE_ROLE)
        cur.execute(_CREATE_ROLE_RETENTION)
        cur.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture
def dao(conn):
    return DataAccess(conn, clock=SystemClock(), password_hasher=BcryptHasher(rounds=4))


@pytest.fixture
def org_a(dao):
    return dao.create_organisation("Org A")


@pytest.fixture
def org_b(dao):
    return dao.create_organisation("Org B")


def _admin_session(dao, conn, org_id, email):
    user_id = dao.create_user(org_id, email, "password")
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO role_assignments (user_id, org_id, role, assigned_by, assigned_at) "
            "VALUES (%s, %s, 'Administrator', %s, %s)",
            (user_id, org_id, user_id, T0),
        )
    conn.commit()
    return dao.login(email, org_id, "password")


@pytest.fixture
def admin_a(dao, conn, org_a):
    """Authenticated, real, right organisation -- and not a Lab technician."""
    return _admin_session(dao, conn, org_a, "admin@org-a.test")


@pytest.fixture
def admin_b(dao, conn, org_b):
    return _admin_session(dao, conn, org_b, "admin@org-b.test")


def _role_session(dao, admin_session, org_id, email, *roles):
    user_id = dao.create_user(org_id, email, "password")
    for role in roles:
        dao.assign_role(admin_session, user_id, role, basis=f"w129 test fixture: {role}")
    return dao.login(email, org_id, "password")


@pytest.fixture
def orderer_a(dao, admin_a, org_a):
    return _role_session(dao, admin_a, org_a, "orderer@org-a.test", "Orderer")


@pytest.fixture
def orderer_b(dao, admin_b, org_b):
    return _role_session(dao, admin_b, org_b, "orderer@org-b.test", "Orderer")


@pytest.fixture
def lab_a(dao, admin_a, org_a):
    return _role_session(dao, admin_a, org_a, "lab@org-a.test", "Lab technician")


@pytest.fixture
def lab_b(dao, admin_b, org_b):
    """Right role, wrong organisation."""
    return _role_session(dao, admin_b, org_b, "lab@org-b.test", "Lab technician")


@pytest.fixture
def placed_order_a(dao, conn, admin_a, orderer_a):
    """
    A placed order in org A. Built by the Orderer, because ordering is the
    Orderer's job -- the roles do not overlap and this fixture is where that
    shows.
    """
    test_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tests (test_id, org_id, name, assembly, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (test_id, admin_a.org_id, "Panel", "GRCh38", "active", T0),
        )
    conn.commit()
    patient_id = dao.create_patient(admin_a, "Test", date(1990, 1, 1), "M")
    consent_id = dao.record_consent(admin_a, patient_id, "testing")
    order_id = dao.create_order(
        orderer_a,
        patient_id=patient_id,
        test_id=test_id,
        required_scope="testing",
        consent_id=consent_id,
        priority="routine",
    )
    dao.place_order(orderer_a, order_id)
    return order_id


def _sample_count(conn, org_id):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM samples WHERE org_id = %s", (org_id,))
        return cur.fetchone()[0]


def _qc(conn, sample_id):
    with conn.cursor() as cur:
        cur.execute("SELECT qc_status, qc_recorded_by FROM samples WHERE sample_id = %s", (sample_id,))
        return cur.fetchone()


def _run_count(conn, org_id):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM sequencing_runs WHERE org_id = %s", (org_id,))
        return cur.fetchone()[0]


def _vcf_count(conn, org_id):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM vcfs WHERE org_id = %s", (org_id,))
        return cur.fetchone()[0]


class TestReceiveSampleRequiresTheLabTechnicianRole:
    def test_a_lab_technician_may_receive_the_sample(self, dao, conn, lab_a, placed_order_a):
        """
        Right role + right organisation: the positive twin every refusal in
        this class needs, and it checks the provenance column too -- a
        receive that recorded the wrong person would pass a bare count.
        """
        sample_id = dao.receive_sample(lab_a, placed_order_a, "blood")
        assert isinstance(sample_id, uuid.UUID)
        with conn.cursor() as cur:
            cur.execute("SELECT received_by, collected_by FROM samples WHERE sample_id = %s", (sample_id,))
            received_by, collected_by = cur.fetchone()
        assert received_by == lab_a.user_id
        assert collected_by == lab_a.user_id

    def test_an_administrator_may_not_receive_the_sample(self, dao, conn, admin_a, placed_order_a):
        with pytest.raises(AuthorizationError, match="Lab technician"):
            dao.receive_sample(admin_a, placed_order_a, "blood")
        assert _sample_count(conn, admin_a.org_id) == 0

    def test_an_orderer_may_not_receive_the_sample(self, dao, conn, orderer_a, placed_order_a):
        """
        The two operational roles this wave introduces do NOT overlap. An
        Orderer may order and may not do bench work; the test below proves
        the converse.
        """
        with pytest.raises(AuthorizationError, match="Lab technician"):
            dao.receive_sample(orderer_a, placed_order_a, "blood")
        assert _sample_count(conn, orderer_a.org_id) == 0

    def test_a_lab_technician_of_another_organisation_may_not_receive_it(self, dao, conn, lab_b, placed_order_a, org_a):
        """Right role + WRONG organisation. Nothing written in either org."""
        with pytest.raises(NotFoundError):
            dao.receive_sample(lab_b, placed_order_a, "blood")
        assert _sample_count(conn, org_a) == 0
        assert _sample_count(conn, lab_b.org_id) == 0

    def test_wrong_role_and_wrong_organisation_is_refused(self, dao, conn, orderer_b, placed_order_a, org_a):
        with pytest.raises((AuthorizationError, NotFoundError)):
            dao.receive_sample(orderer_b, placed_order_a, "blood")
        assert _sample_count(conn, org_a) == 0
        assert _sample_count(conn, orderer_b.org_id) == 0


class TestRecordQcRequiresTheLabTechnicianRole:
    """
    The QC verdict decides whether a specimen is fit to sequence. It is the
    operation in this file with the clearest patient-safety consequence, and
    before w129 any authenticated session could sign it.
    """

    @pytest.fixture
    def sample_a(self, dao, lab_a, placed_order_a):
        return dao.receive_sample(lab_a, placed_order_a, "blood")

    def test_a_lab_technician_may_record_qc(self, dao, conn, lab_a, sample_a):
        dao.record_qc(lab_a, sample_a, "passed")
        status, recorded_by = _qc(conn, sample_a)
        assert status == "passed"
        assert recorded_by == lab_a.user_id

    def test_an_administrator_may_not_record_qc(self, dao, conn, admin_a, sample_a):
        with pytest.raises(AuthorizationError, match="Lab technician"):
            dao.record_qc(admin_a, sample_a, "passed")
        status, recorded_by = _qc(conn, sample_a)
        # 'pending' is the schema default on samples.qc_status, NOT a verdict:
        # the column is never NULL, so "unjudged" is asserted as the default
        # value plus an unstamped qc_recorded_by. The positive twin above
        # asserts 'passed' and the recorder's id, so a record_qc that wrote
        # nothing at all would fail there rather than pass here.
        assert status == "pending", "the refusal must leave the sample unjudged"
        assert recorded_by is None

    def test_an_orderer_may_not_record_qc(self, dao, conn, orderer_a, sample_a):
        with pytest.raises(AuthorizationError, match="Lab technician"):
            dao.record_qc(orderer_a, sample_a, "passed")
        assert _qc(conn, sample_a) == ("pending", None)

    def test_a_lab_technician_of_another_organisation_may_not_record_qc(self, dao, conn, lab_b, sample_a):
        with pytest.raises(NotFoundError):
            dao.record_qc(lab_b, sample_a, "failed")
        assert _qc(conn, sample_a) == ("pending", None)

    def test_wrong_role_and_wrong_organisation_may_not_record_qc(self, dao, conn, orderer_b, sample_a):
        with pytest.raises((AuthorizationError, NotFoundError)):
            dao.record_qc(orderer_b, sample_a, "failed")
        assert _qc(conn, sample_a) == ("pending", None)


class TestSequencingRunAndVcfRequireTheLabTechnicianRole:
    """
    The run performed on a specimen and the variant-call artefact it produced.
    Both stamp `created_by` from the session, which is the laboratory
    provenance the role exists to qualify.

    Neither is reached by the automatic pipeline: record_pipeline_result is
    the System principal's path and does not call these methods -- counted,
    `self.create_sequencing_run(` and `self.create_vcf(` occur zero times in
    clinical/data_access.py -- so gating them cannot break the worker.
    """

    @pytest.fixture
    def qc_passed_sample(self, dao, lab_a, placed_order_a):
        sample_id = dao.receive_sample(lab_a, placed_order_a, "blood")
        dao.record_qc(lab_a, sample_id, "passed")
        return sample_id

    @pytest.fixture
    def vcf_file(self, tmp_path):
        path = tmp_path / "w129.vcf"
        path.write_text(_MINIMAL_VCF, encoding="utf-8")
        return str(path)

    def test_a_lab_technician_may_create_the_run_and_the_vcf(self, dao, conn, lab_a, qc_passed_sample, vcf_file):
        run_id = dao.create_sequencing_run(lab_a, qc_passed_sample)
        vcf_id = dao.create_vcf(lab_a, run_id, vcf_file)
        assert _run_count(conn, lab_a.org_id) == 1
        assert _vcf_count(conn, lab_a.org_id) == 1
        with conn.cursor() as cur:
            cur.execute("SELECT created_by FROM sequencing_runs WHERE id = %s", (run_id,))
            assert cur.fetchone()[0] == lab_a.user_id
            cur.execute("SELECT created_by FROM vcfs WHERE id = %s", (vcf_id,))
            assert cur.fetchone()[0] == lab_a.user_id

    def test_an_administrator_may_not_create_a_sequencing_run(self, dao, conn, admin_a, qc_passed_sample):
        with pytest.raises(AuthorizationError, match="Lab technician"):
            dao.create_sequencing_run(admin_a, qc_passed_sample)
        assert _run_count(conn, admin_a.org_id) == 0

    def test_an_orderer_may_not_create_a_sequencing_run(self, dao, conn, orderer_a, qc_passed_sample):
        with pytest.raises(AuthorizationError, match="Lab technician"):
            dao.create_sequencing_run(orderer_a, qc_passed_sample)
        assert _run_count(conn, orderer_a.org_id) == 0

    def test_a_lab_technician_of_another_organisation_may_not_create_the_run(
        self, dao, conn, lab_b, qc_passed_sample, org_a
    ):
        with pytest.raises(NotFoundError):
            dao.create_sequencing_run(lab_b, qc_passed_sample)
        assert _run_count(conn, org_a) == 0
        assert _run_count(conn, lab_b.org_id) == 0

    def test_wrong_role_and_wrong_organisation_may_not_create_the_run(
        self, dao, conn, orderer_b, qc_passed_sample, org_a
    ):
        with pytest.raises((AuthorizationError, NotFoundError)):
            dao.create_sequencing_run(orderer_b, qc_passed_sample)
        assert _run_count(conn, org_a) == 0

    def test_an_administrator_may_not_create_a_vcf(self, dao, conn, admin_a, lab_a, qc_passed_sample, vcf_file):
        run_id = dao.create_sequencing_run(lab_a, qc_passed_sample)
        with pytest.raises(AuthorizationError, match="Lab technician"):
            dao.create_vcf(admin_a, run_id, vcf_file)
        assert _vcf_count(conn, admin_a.org_id) == 0

    def test_an_orderer_may_not_create_a_vcf(self, dao, conn, orderer_a, lab_a, qc_passed_sample, vcf_file):
        run_id = dao.create_sequencing_run(lab_a, qc_passed_sample)
        with pytest.raises(AuthorizationError, match="Lab technician"):
            dao.create_vcf(orderer_a, run_id, vcf_file)
        assert _vcf_count(conn, orderer_a.org_id) == 0

    def test_a_lab_technician_of_another_organisation_may_not_create_a_vcf(
        self, dao, conn, lab_a, lab_b, qc_passed_sample, vcf_file, org_a
    ):
        run_id = dao.create_sequencing_run(lab_a, qc_passed_sample)
        with pytest.raises(NotFoundError):
            dao.create_vcf(lab_b, run_id, vcf_file)
        assert _vcf_count(conn, org_a) == 0
        assert _vcf_count(conn, lab_b.org_id) == 0

    def test_wrong_role_and_wrong_organisation_may_not_create_a_vcf(
        self, dao, conn, lab_a, orderer_b, qc_passed_sample, vcf_file, org_a
    ):
        run_id = dao.create_sequencing_run(lab_a, qc_passed_sample)
        with pytest.raises((AuthorizationError, NotFoundError)):
            dao.create_vcf(orderer_b, run_id, vcf_file)
        assert _vcf_count(conn, org_a) == 0


class TestTheGateIsTheLabTechnicianRoleSpecifically:
    """
    Rule 4 again: every refusal above is also produced by a gate naming any
    role the refused session happens to lack. These two make the assertions
    mean "Lab technician".
    """

    def test_a_session_holding_only_lab_technician_can_do_all_four(self, dao, conn, lab_a, placed_order_a, tmp_path):
        held = {a.role for a in dao.get_user_roles(lab_a)}
        assert held == {"Lab technician"}, f"fixture drifted: {held}"

        path = tmp_path / "only.vcf"
        path.write_text(_MINIMAL_VCF, encoding="utf-8")

        sample_id = dao.receive_sample(lab_a, placed_order_a, "blood")
        dao.record_qc(lab_a, sample_id, "passed")
        run_id = dao.create_sequencing_run(lab_a, sample_id)
        dao.create_vcf(lab_a, run_id, str(path))

        assert _qc(conn, sample_id)[0] == "passed"
        assert _run_count(conn, lab_a.org_id) == 1
        assert _vcf_count(conn, lab_a.org_id) == 1

    def test_holding_every_other_role_but_lab_technician_is_still_refused(
        self, dao, conn, admin_a, org_a, placed_order_a
    ):
        """
        Administrator, Orderer, Interpreter, Approver and Auditor together --
        every assignable human role except the one that matters -- and the
        bench is still closed. Excludes "the gate just wants a role" and every
        reading in which Administrator subsumes the operational roles.
        """
        loaded = _role_session(
            dao,
            admin_a,
            org_a,
            "everything-but@org-a.test",
            "Administrator",
            "Orderer",
            "Interpreter",
            "Approver",
            "Auditor",
        )
        with pytest.raises(AuthorizationError, match="Lab technician"):
            dao.receive_sample(loaded, placed_order_a, "blood")
        assert _sample_count(conn, org_a) == 0
