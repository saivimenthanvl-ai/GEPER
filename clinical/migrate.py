"""
clinical/migrate.py
───────────────────
THE MIGRATION MECHANISM. Ordered migration identity, an authoritative
applied-state history that lives IN the database, no silent re-application,
serialised concurrent execution, and a verdict `/readyz` can act on.

WHY A RUNNER IN THIS REPOSITORY AND NOT A LIBRARY -- justified from what is
actually here, not from habit:

  * There is no ORM. `clinical/schema.sql` is raw DDL and the only `.sql`
    file in the tree; `clinical/data_access.py` writes SQL strings through
    psycopg directly. Alembic -- the obvious candidate -- is an extension of
    SQLAlchemy and carries SQLAlchemy with it. Adopting it would add a large
    dependency to `clinical/requirements.txt` (which `.github/workflows/
    pytest.yml` installs wholesale for the clinical job) to gain autogenerate,
    a feature that needs a `MetaData` this repository does not have and will
    not have. Every migration would be `op.execute("<raw sql>")`. The
    dependency buys the version table and the runner and nothing else.
  * And its version table is the wrong shape for what was asked. Alembic's
    `alembic_version` holds ONE row -- the current revision string. The
    requirement here is an authoritative applied-state HISTORY: which
    versions ran, when, as whom, over which bytes. That is a table alembic
    does not keep, so a library adoption would still need this one.
  * `clinical/bootstrap.py` already is the deployment entry point: an
    argparse CLI, an administrative DSN read from `CLINICAL_BOOTSTRAP_DSN`,
    psycopg with `autocommit=False`, one transaction. This module reuses all
    four rather than inventing a second database abstraction beside it.

NO NEW DEPENDENCY IS ADDED BY THIS MODULE. It imports psycopg, which
`clinical/requirements.txt` already declares, and nothing else outside the
standard library.

FORWARD-ONLY, AND THAT IS A DECISION RATHER THAN AN OMISSION. Nothing in this
deployment model asks for reversal: there is no blue-green manifest, no
replica count, no orchestrator config and no deploy script anywhere in the
tree, so there is no automated roll-back to unwind a migration for. Against
that, the schema's governing ruling is append-only and no-delete -- twelve
REVOKE statements and the D0b ruling "NOTHING DELETES" -- and a mechanism
that can run DROP COLUMN and DROP TABLE on a clinical database is a mechanism
that can be pointed at the wrong one. Roll FORWARD: a mistake becomes a new
migration with a higher number, which leaves a history row where an undo
would leave nothing. If a deployment model that requires rollback ever turns
up, this decision is the thing to revisit, and it is written down here so it
can be.

THE ONE THING THAT MAKES THIS SAFE RATHER THAN MERELY CONVENIENT. A fresh
database is created from `clinical/schema.sql` (which stamps the history in
the same transaction); an existing database is upgraded by the migrations.
Two paths to one state, and nothing in a migration runner compares them --
so they drift apart silently and every test still passes. The comparison is
`clinical/tests/test_w126m_schema_equivalence.py`, which builds one database
each way and diffs the CATALOGS. It is the centrepiece of this mechanism and
it is not optional: adding a migration without the matching edit to
`schema.sql` fails it.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import os
import pathlib
import re
import sys
from typing import Dict, Optional, Sequence, Tuple

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parent / "migrations"

HISTORY_TABLE = "schema_migrations"

# The version at which `clinical/migrations/0002_baseline.sql` sits -- a frozen
# byte copy of `clinical/schema.sql` as it stood at 86522c4, before this
# mechanism existed. It is the ONLY migration that may be stamped without
# being executed, and only by `adopt_existing`, and only on a database that
# demonstrably already holds it. See adopt_existing's docstring.
BASELINE_VERSION = 2

# The table whose presence separates "Postgres is up" from "this is the
# clinical database" -- the same probe `clinical/app.py` has used since it was
# written. It is RESTATED here rather than imported from there, deliberately:
# app.py imports THIS module for its readiness verdict, so importing back
# would be a cycle, and a migration CLI that has to construct a FastAPI
# application and mount four routers before it can read a table name is a
# worse trade than one duplicated string. The duplication is pinned by
# test_w126m_migration_mechanism.py::test_the_sentinel_table_matches_the_service,
# which fails if the two ever disagree.
SENTINEL_TABLE = "sessions"

# Only ONE process may apply migrations to a database at a time. The image
# ships `ENTRYPOINT ["python", "-m", "uvicorn"]` with an overridable CMD whose
# own comment names `--workers`, so more than one process against one database
# is an expected deployment, not a hypothetical.
#
# A Postgres ADVISORY lock, not a row lock and not a table: it is held by the
# SESSION rather than by a transaction, which is what lets each migration have
# its own transaction while one lock spans the whole run. Derived rather than
# picked so the derivation is checkable -- the first 8 bytes of
# SHA-256("clinical.schema_migrations") read as a signed 64-bit integer, which
# is what pg_advisory_lock takes. Pinned by
# test_w126m_migration_mechanism.py::test_the_advisory_lock_key_is_pinned so a
# rename of that string cannot silently move the lock and let two runners
# through.
ADVISORY_LOCK_KEY = int.from_bytes(hashlib.sha256(b"clinical.schema_migrations").digest()[:8], "big", signed=True)

# How long a second runner waits for the first before giving up. It bounds the
# wait; it does not shorten it to a race. MEASURED, not assumed (PostgreSQL 16,
# 2026-09-17): `lock_timeout` DOES apply to advisory-lock waits -- a blocked
# `pg_advisory_lock` raises psycopg.errors.LockNotAvailable, SQLSTATE 55P03,
# at the timeout. Without the timeout a runner queued behind a forgotten open
# transaction waits for ever with nothing in its output saying so.
DEFAULT_LOCK_TIMEOUT = "30s"

_FILENAME = re.compile(r"^(\d{4})_([a-z0-9][a-z0-9_]*)\.sql$")

# A migration may state, in its own header, what must be TRUE OF THE CATALOG
# once it has run:
#
#     -- MIGRATION-ASSERT: to_regclass('schema_migrations') IS NOT NULL
#
# This is the answer to the sharpest failure this mechanism can have: the
# history says a version is applied and the database does not have the thing
# that version was for. A history row is a claim; the assertion is the
# measurement, read from pg_catalog, and `inspect_state` re-evaluates every
# applied migration's assertions on every call -- so `/readyz` reports a
# database whose history lies as NOT ready rather than as ready.
_ASSERT = re.compile(r"^--\s*MIGRATION-ASSERT:\s*(.+?)\s*$", re.MULTILINE)


# ─── GENERATION INVARIANTS ──────────────────────────────────────────────────
#
# WHY THESE EXIST AT ALL, AND WHY THEY ARE NOT IN THE MIGRATION FILE.
#
# Every `MIGRATION-ASSERT` line in `migrations/0002_baseline.sql` is a bare
# `to_regclass('<table>') IS NOT NULL` probe, and that vocabulary is
# STRUCTURALLY INCAPABLE of separating this schema generation from the one
# before it: every security change in this stack is a COLUMN ADDED TO A TABLE
# THAT ALREADY EXISTED. `exception_events` exists in both generations; only
# `exception_events.org_id` -- the tenant-isolation column -- does not.
# Measured, not assumed: a database built from `7b034e5:clinical/schema.sql`
# (blob da97f847), the real pre-security schema, satisfies all five of the
# baseline's own post-conditions, so `adopt_existing` stamped it as the
# baseline and `/readyz` then answered 200 ready on a database with no
# tenant-isolation column and no patient credential table.
#
# THE INVARIANTS LIVE HERE AND NOT IN THE MIGRATION FILE, DELIBERATELY.
# `0002_baseline.sql` is frozen and `checksum_of` hashes the WHOLE file,
# comments included; its checksum is the value `clinical/schema.sql`'s
# stamping INSERT records. Adding assertion comments to it would change that
# checksum, break the stamp, force a `schema.sql` edit, and make every
# already-adopted database raise MigrationChecksumMismatch. The cost of
# keeping them here instead is that the post-conditions of a migration are no
# longer all in one file: a future migration that wants generation invariants
# must add them to this table as well as its own header. That cost is paid
# knowingly and the non-vacuity test below pins it.
#
# KEYED BY (version, name), NOT BY VERSION ALONE: the test suite discovers
# throwaway migration sets from tmp_path that also number their files 0001 and
# 0002, and those must not inherit the real baseline's invariants.


@dataclasses.dataclass(frozen=True)
class CatalogInvariant:
    """
    ONE FACT ABOUT THE CATALOG, with the words to say what it was.

    `expression` is a boolean SQL expression evaluated exactly the way a
    `MIGRATION-ASSERT` line is -- same `_failed_assertions` loop, same
    inside-the-transaction timing, same refuse-and-roll-back path. What is new
    is the VOCABULARY: `kind` is "column" or "constraint" or "table", and
    only the first two can see the change this stack actually makes.

    Read from `pg_catalog`, NOT from `information_schema`.
    `information_schema.columns` is privilege-filtered -- it shows a role only
    the columns of relations that role has some privilege on -- and `/readyz`
    evaluates these as `clinical_app`, which is deliberately denied privileges
    on parts of this schema. A privilege-filtered answer would report a
    present column as absent and fail readiness for the wrong reason.
    `pg_attribute`/`pg_constraint` are readable by every role.
    """

    kind: str
    description: str
    expression: str


def _table_invariant(table: str) -> CatalogInvariant:
    """A relation exists AND is an ordinary table. Weakest of the three: use
    it only alongside a column or constraint invariant."""
    return CatalogInvariant(
        kind="table",
        description=f"table {table!r} exists",
        expression=(f"EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass('{table}') AND relkind = 'r')"),
    )


def _column_invariant(table: str, column: str) -> CatalogInvariant:
    """
    A COLUMN exists on a table. `to_regclass` rather than a literal schema
    name so this follows the same `search_path` every other probe in this
    module follows; an absent table makes `attrelid = NULL`, which matches no
    row, so the invariant is false rather than an error.
    """
    return CatalogInvariant(
        kind="column",
        description=f"column {table}.{column} exists",
        expression=(
            "EXISTS (SELECT 1 FROM pg_attribute "
            f"WHERE attrelid = to_regclass('{table}') AND attname = '{column}' "
            "AND attnum > 0 AND NOT attisdropped)"
        ),
    )


def _constraint_invariant(table: str, constraint: str, contype: str = "f") -> CatalogInvariant:
    """A named CONSTRAINT of a given type exists on a table. Stronger than a
    column probe: a column can be added back by hand, a composite foreign key
    cannot be satisfied by a database whose rows do not support it."""
    return CatalogInvariant(
        kind="constraint",
        description=f"constraint {constraint!r} on {table} exists",
        expression=(
            "EXISTS (SELECT 1 FROM pg_constraint "
            f"WHERE conrelid = to_regclass('{table}') AND conname = '{constraint}' "
            f"AND contype = '{contype}')"
        ),
    )


# What separates the baseline generation from every earlier one. Each line is
# a real change made by a real wave, chosen because a database of the earlier
# generation DEMONSTRABLY lacks it -- verified by building both schemas and
# diffing pg_catalog, not by reading a changelog:
#
#   exception_events.org_id + the composite FK  -- w129b tenant isolation
#   reviewer_claims.report_id + fk_claim_report -- a claim belongs to a report
#   users.registration_number                   -- clinician identity
#   patient_logins / patient_sessions           -- w130 patient credentials
#
# NOTE WHAT IS DELIBERATELY ABSENT: `exception_events.amends_event_id`. It
# belongs to w126, which is HELD and NOT merged, so it is not in this
# baseline. Asserting it -- as one audit proposed -- would reject a genuinely
# current database, which is the opposite defect.
BASELINE_GENERATION_INVARIANTS: Tuple[CatalogInvariant, ...] = (
    _column_invariant("exception_events", "org_id"),
    _constraint_invariant("exception_events", "exception_events_org_exception_fk"),
    _column_invariant("reviewer_claims", "report_id"),
    _constraint_invariant("reviewer_claims", "fk_claim_report"),
    _column_invariant("users", "registration_number"),
    _table_invariant("patient_logins"),
    _column_invariant("patient_logins", "password_hash"),
    _table_invariant("patient_sessions"),
    _column_invariant("patient_sessions", "patient_id"),
)

# What separates the RETRACTION generation (migration 0003) from the baseline
# one. Same rule as above and the same evidence: MEASURED by building a
# database each way and diffing pg_catalog, not by reading the migration file.
#
# THE MEASURED DIFF, before -> after. Two real databases on PostgreSQL 16, one
# with `0002_baseline.sql` applied and one with `0002` then `0003`, diffed row
# by row across pg_class, pg_attribute, pg_constraint, pg_trigger, pg_proc and
# the two privilege views (2026-09-18):
#
#   +2  pg_class relkind 'r'   report_retractions, retraction_notifications
#                              (28 -> 30)
#   +7  pg_class relkind 'i'   the two named indexes --
#                              idx_retraction_org_report and
#                              idx_retraction_notification_org_retraction --
#                              plus the five Postgres builds for the two
#                              primary keys and the three UNIQUE constraints
#                              (84 -> 91)
#   +20 pg_attribute rows      the two tables' own columns, 10 each
#                              (273 -> 293)
#   +17 pg_constraint rows     report_retractions: 4 FK, 3 CHECK, 1 PK,
#                              1 UNIQUE. retraction_notifications: 3 FK,
#                              2 CHECK, 1 PK, 2 UNIQUE. (137 -> 154)
#   +6  role_table_grants      clinical_app SELECT/INSERT on both tables,
#       rows for the two        clinical_retention SELECT on both -- from the
#       granted roles           six privilege statements. (+72 column_privilege
#                               rows, of which 4 are the column-scoped
#                               tombstone UPDATE ruling E8 asks for.)
#    0 pg_trigger rows         (3 -> 3)
#    0 pg_proc rows            (37 -> 37)
#    0 rows REMOVED in any section, and no definition changed -- which is the
#      measurement "additive" actually means here.
#
# WHAT IS CHOSEN OUT OF THAT DIFF, AND WHY NOT ALL OF IT. A generation
# invariant is evaluated on EVERY `/readyz`, so it is a cost per request and
# the list is a sample, not a census. Three probes per table, one of each
# strength, in the order that makes the next meaningful:
#
#   * the TABLE probe alone is the one a pre-security database defeated in
#     w143 -- a name can exist in an older generation. It is here only to make
#     the two below readable when they fail.
#   * a COLUMN that a hand-rebuilt table would have to know about:
#     `report_retractions.retracted_from_state` (human ruling E1, the stored
#     rather than inferred state) and `retraction_notifications.status`
#     (ruling E6's one-value debt vocabulary).
#   * a named COMPOSITE FOREIGN KEY, which is the strongest of the three: it
#     cannot exist unless `reports (org_id, id)` and
#     `report_retractions (org_id, id)` carry the composite unique keys the
#     tenant-isolation generation introduced. A database that merely has two
#     tables of the right names cannot satisfy it.
#
# DELIBERATELY ABSENT: anything from the rest of the held stack. `w122`'s
# `retract_report` verb, `w123`'s reader matcher and `w124`'s report-builder
# changes are NOT in this repository, and an invariant asserting a column they
# would add would reject a database that is correctly at this generation --
# the same defect, in the other direction, that the baseline list avoids by
# not asserting `exception_events.amends_event_id`.
RETRACTION_GENERATION_INVARIANTS: Tuple[CatalogInvariant, ...] = (
    _table_invariant("report_retractions"),
    _column_invariant("report_retractions", "retracted_from_state"),
    _constraint_invariant("report_retractions", "fk_retraction_report"),
    _table_invariant("retraction_notifications"),
    _column_invariant("retraction_notifications", "status"),
    _constraint_invariant("retraction_notifications", "fk_retraction_notification_retraction"),
)

_GENERATION_INVARIANTS: Dict[Tuple[int, str], Tuple[CatalogInvariant, ...]] = {
    (BASELINE_VERSION, "baseline"): BASELINE_GENERATION_INVARIANTS,
    (3, "report_retraction"): RETRACTION_GENERATION_INVARIANTS,
}


def generation_invariants(migration: "Migration") -> Tuple[CatalogInvariant, ...]:
    """The invariants that apply to this migration, or none."""
    return _GENERATION_INVARIANTS.get((migration.version, migration.name), ())


class MigrationError(Exception):
    """Base for every refusal this module makes."""


class MigrationSetError(MigrationError):
    """The migration files on disk are not a usable ordered set."""


class MigrationStateError(MigrationError):
    """The database is not in a state this operation can act on."""


class MigrationLockUnavailable(MigrationError):
    """Another process is migrating this database."""


class MigrationChecksumMismatch(MigrationError):
    """An already-applied migration file has been edited since it ran."""


@dataclasses.dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: pathlib.Path
    sql: str
    checksum: str
    assertions: Tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class AppliedMigration:
    version: int
    name: str
    checksum: str


@dataclasses.dataclass(frozen=True)
class MigrationState:
    """The verdict. `ok` is the only field a caller should branch on."""

    ok: bool
    reason: Optional[str]
    detail: Optional[str]
    applied: Tuple[int, ...]
    pending: Tuple[int, ...]
    current_version: Optional[int]


def checksum_of(data: bytes) -> str:
    """
    SHA-256 over the file's bytes with line endings NORMALISED to LF first.

    The normalisation is not cosmetic and it is measured, not assumed: this
    repository sets `core.autocrlf=true` and `.gitattributes` pins `eol=lf`
    for `*.sh` ONLY, so the same committed `.sql` blob is checked out with
    CRLF on Windows (108381 bytes for the baseline) and LF on the Linux CI
    container (106386 bytes). A checksum over raw bytes would therefore be a
    different number on the two machines, and the stamp `schema.sql` carries
    would match on exactly one of them -- a failure that cannot reproduce
    locally, which is the worst kind.
    """
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def discover(directory: Optional[pathlib.Path] = None) -> Tuple[Migration, ...]:
    """
    The ordered migration set, read off the filenames.

    ORDER COMES FROM THE INTEGER, NOT FROM THE STRING. `sorted()` on filenames
    puts `0010_x.sql` before `0009_x.sql` the day the set passes nine, and the
    resulting wrong order is silent -- every file still runs, every history
    row still appears, and the schema is wrong. The version is parsed out of
    the name and sorted as a number.

    A FILE THAT DOES NOT MATCH THE PATTERN IS A REFUSAL, NOT A SKIP. A runner
    that ignores what it does not recognise turns a typo (`002_thing.sql`,
    `0003-thing.sql`, an editor's `.sql.bak`) into a migration that never runs
    and never says so. Two files claiming one version is likewise refused
    rather than resolved: there is no correct way to pick.
    """
    directory = pathlib.Path(directory) if directory is not None else MIGRATIONS_DIR
    if not directory.is_dir():
        raise MigrationSetError(f"migration directory does not exist: {directory}")

    seen: Dict[int, pathlib.Path] = {}
    found = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        match = _FILENAME.match(path.name)
        if match is None:
            raise MigrationSetError(
                f"{path.name!r} is in {directory} but is not a migration: a migration is "
                "named NNNN_lower_snake_name.sql (four digits). Refusing to guess -- a "
                "runner that skips what it does not recognise turns a typo into a "
                "migration that never runs."
            )
        version = int(match.group(1))
        if version in seen:
            raise MigrationSetError(
                f"two files claim migration version {version}: {seen[version].name} and "
                f"{path.name}. There is no correct order for these; fix the names."
            )
        seen[version] = path
        raw = path.read_bytes()
        # read_text, NOT raw.decode(): text mode applies universal-newline
        # translation, so a CRLF checkout sends LF -- which is exactly what
        # `clinical/bootstrap.py::apply_schema` and every test fixture have
        # always done with schema.sql. It matters far more than it looks, and
        # it was MEASURED by the equivalence proof rather than reasoned:
        # Postgres stores a PL/pgSQL function's SOURCE TEXT verbatim, so the
        # same CREATE FUNCTION sent with CRLF and with LF yields two
        # `pg_get_functiondef` outputs that differ on every line. A database
        # built from schema.sql and one built from these migrations would then
        # hold literally different `enforce_content_immutability` functions --
        # on Windows only, invisibly, with every other test still green.
        # `checksum_of` hashes the RAW bytes and normalises separately, so
        # identity and content never disagree.
        text = path.read_text(encoding="utf-8")
        found.append(
            Migration(
                version=version,
                name=match.group(2),
                path=path,
                sql=text,
                checksum=checksum_of(raw),
                assertions=tuple(_ASSERT.findall(text)),
            )
        )
    if not found:
        raise MigrationSetError(f"no migrations found in {directory}")
    return tuple(sorted(found, key=lambda m: m.version))


def history_table_exists(connection) -> bool:
    with connection.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (HISTORY_TABLE,))
        row = cur.fetchone()
    return row is not None and row[0] is not None


def schema_is_present(connection) -> bool:
    """Does this database already hold the clinical schema? Same probe
    `/readyz` has always used, for the same reason."""
    with connection.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (SENTINEL_TABLE,))
        row = cur.fetchone()
    return row is not None and row[0] is not None


def read_history(connection) -> Tuple[AppliedMigration, ...]:
    """Every applied migration, in version order, READ FROM THE DATABASE."""
    with connection.cursor() as cur:
        cur.execute(f"SELECT version, name, checksum FROM {HISTORY_TABLE} ORDER BY version")
        rows = cur.fetchall()
    return tuple(AppliedMigration(version=r[0], name=r[1], checksum=r[2]) for r in rows)


def _evaluate(connection, expression: str) -> bool:
    with connection.cursor() as cur:
        cur.execute(f"SELECT ({expression})")  # noqa: S608 -- from the repo's own files
        row = cur.fetchone()
    return bool(row and row[0] is True)


def _failed_assertions(connection, migration: Migration) -> Tuple[str, ...]:
    """
    Which of this migration's catalog post-conditions are NOT true.

    TWO SOURCES, ONE LOOP, AND THAT IS THE POINT. The migration file's own
    `MIGRATION-ASSERT` lines come first, unchanged; then the generation
    invariants held in this module for that migration. Putting both here --
    rather than only in `adopt_existing` -- is what makes the fix reach
    `/readyz`: `inspect_state` calls this for every applied migration on every
    call, so a database that was stamped by an older build of this runner, or
    by a hand-written history row, is reported `schema_drift` instead of ready.
    """
    failed = [expression for expression in migration.assertions if not _evaluate(connection, expression)]
    failed.extend(
        invariant.description
        for invariant in generation_invariants(migration)
        if not _evaluate(connection, invariant.expression)
    )
    return tuple(failed)


def inspect_state(connection, migrations: Optional[Sequence[Migration]] = None) -> MigrationState:
    """
    THE VERDICT, and it is a judgement rather than a count.

    It is not enough to compare how MANY rows the history has against how many
    files are on disk; that number is equal in a database whose history was
    written by a runner that never ran the DDL. So this asks four separate
    questions, in the order in which each makes the next meaningful, and the
    last one reads the CATALOG:

      1. does the history table exist at all?
      2. is every migration on disk recorded as applied?
      3. does every recorded row's checksum match the bytes on disk?
      4. is every applied migration's stated post-condition actually TRUE of
         this database's catalog right now?

    Question 4 is the one that costs a query per assertion and it is the one
    worth having: 1-3 can all be satisfied by a history table somebody filled
    in by hand.
    """
    on_disk = tuple(migrations) if migrations is not None else discover()

    if not history_table_exists(connection):
        return MigrationState(
            ok=False,
            reason="schema_not_initialised",
            detail=(
                f"table {HISTORY_TABLE!r} does not exist; this database has no migration "
                "history. Run python -m clinical.migrate --migrate (empty database) or "
                "--adopt-existing (a database created before this mechanism)."
            ),
            applied=(),
            pending=tuple(m.version for m in on_disk),
            current_version=None,
        )

    applied = {a.version: a for a in read_history(connection)}
    pending = tuple(m.version for m in on_disk if m.version not in applied)
    current = max(applied) if applied else None

    if pending:
        return MigrationState(
            ok=False,
            reason="schema_migrations_pending",
            detail=(
                "this database is behind the code: migration(s) "
                + ", ".join(str(v) for v in pending)
                + " have not been applied."
            ),
            applied=tuple(sorted(applied)),
            pending=pending,
            current_version=current,
        )

    for migration in on_disk:
        recorded = applied[migration.version]
        if recorded.checksum != migration.checksum:
            return MigrationState(
                ok=False,
                reason="schema_migration_checksum_mismatch",
                detail=(
                    f"migration {migration.version} ({migration.name}) was applied from "
                    "different bytes than the file now on disk; the file has been edited "
                    "since it ran, so this database does not hold what the repository says."
                ),
                applied=tuple(sorted(applied)),
                pending=(),
                current_version=current,
            )

    for migration in on_disk:
        failed = _failed_assertions(connection, migration)
        if failed:
            return MigrationState(
                ok=False,
                reason="schema_drift",
                detail=(
                    f"migration {migration.version} ({migration.name}) is recorded as "
                    "applied, but the database does not satisfy it: " + "; ".join(failed)
                ),
                applied=tuple(sorted(applied)),
                pending=(),
                current_version=current,
            )

    return MigrationState(
        ok=True,
        reason=None,
        detail=None,
        applied=tuple(sorted(applied)),
        pending=(),
        current_version=current,
    )


def _acquire(connection, lock_timeout: str) -> None:
    """
    Take the advisory lock, or refuse. Never proceed without it.

    The refusal is the point. Two runners that both proceed produce, at best,
    one crash-looping replica and, at worst, a second run of a migration's
    non-DDL half. One runner waits; if the wait is longer than `lock_timeout`
    it raises with an actionable message rather than hanging in a deploy.
    """
    with connection.cursor() as cur:
        # set_config(), not `SET lock_timeout = %s`: SET is a utility
        # statement and Postgres accepts no bound parameters in one -- it
        # raises `syntax error at or near "$1"`. The alternative, composing
        # the value into the statement text, is how an injection gets in.
        # `false` is is_local: this is a session setting, so it outlives each
        # migration's transaction the way the advisory lock does.
        cur.execute("SELECT set_config('lock_timeout', %s, false)", (lock_timeout,))
        try:
            cur.execute("SELECT pg_advisory_lock(%s)", (ADVISORY_LOCK_KEY,))
        except Exception as exc:  # noqa: BLE001 -- re-raised as a domain error below
            sqlstate = getattr(exc, "sqlstate", None)
            if sqlstate != "55P03":  # lock_not_available
                raise
            connection.rollback()
            raise MigrationLockUnavailable(
                "another process holds the clinical migration lock "
                f"(pg_advisory_lock {ADVISORY_LOCK_KEY}) and did not release it within "
                f"{lock_timeout}. Exactly one migration runner may touch a database at a "
                "time; this one applied nothing."
            ) from exc
    connection.commit()


def _release(connection) -> None:
    """
    ROLL BACK FIRST, THEN UNLOCK. The ordering is load-bearing and it was found
    by a test rather than by reasoning. `_release` runs in a `finally`, so it
    also runs after a migration has FAILED -- and a failed statement leaves the
    connection in an ABORTED transaction, where Postgres rejects every further
    command with InFailedSqlTransaction. The unlock therefore raised inside the
    `finally`, the SESSION-level advisory lock stayed held for the life of the
    connection, and the next runner queued behind a process that had already
    given up. The symptom is a deploy that hangs, and it names nothing.
    """
    connection.rollback()
    with connection.cursor() as cur:
        cur.execute("SELECT pg_advisory_unlock(%s)", (ADVISORY_LOCK_KEY,))
    connection.commit()


def _record(cur, migration: Migration) -> None:
    """The history row. INSERT, never UPSERT, and always in the caller's
    transaction -- see `_apply`."""
    cur.execute(
        f"INSERT INTO {HISTORY_TABLE} (version, name, checksum) VALUES (%s, %s, %s)",
        (migration.version, migration.name, migration.checksum),
    )


def _apply(connection, migration: Migration) -> None:
    """
    ONE MIGRATION, ONE TRANSACTION, THE DDL AND THE HISTORY ROW INSIDE IT.

    Postgres has transactional DDL, so this is available and it is the whole
    failure story: if any statement in the migration fails, the transaction
    rolls back and the history row goes with it -- the database is exactly as
    it was and the next run retries the same step. If the history row were
    written first, or in its own transaction, a step that failed halfway would
    leave the database RECORDED as upgraded and actually not, and every later
    run would skip it for ever.

    It is also why re-application cannot be silent: `version` is the PRIMARY
    KEY of `schema_migrations`, so a second INSERT of the same version is a
    duplicate-key violation in the same transaction as the DDL, and takes the
    DDL down with it. The refusal is structural, not a check to remember.

    The one DDL statement Postgres cannot run inside a transaction block is
    CREATE INDEX CONCURRENTLY. A migration that needs one cannot use this
    function's guarantee and must say so; no migration in this repository
    needs one today.
    """
    with connection.cursor() as cur:
        cur.execute(migration.sql)
        _record(cur, migration)
    connection.commit()


def migrate(
    connection,
    migrations: Optional[Sequence[Migration]] = None,
    *,
    lock_timeout: str = DEFAULT_LOCK_TIMEOUT,
) -> Tuple[int, ...]:
    """
    Apply every pending migration, in order. Returns the versions applied.

    Refuses, rather than guesses, on the one ambiguous state there is: a
    database that already holds the clinical schema but has no migration
    history. Running the baseline against it would abort at 42P07 with nothing
    applied (a clean failure, but an opaque one); stamping it silently would
    be a runner deciding on its own that an unknown database is at a known
    version. `--adopt-existing` is that decision made by a person, once.
    """
    on_disk = tuple(migrations) if migrations is not None else discover()

    if not history_table_exists(connection) and schema_is_present(connection):
        raise MigrationStateError(
            f"this database already holds the clinical schema (table {SENTINEL_TABLE!r} "
            f"exists) but has no {HISTORY_TABLE} table. It predates the migration "
            "mechanism. Run `python -m clinical.migrate --adopt-existing` once to record "
            "the baseline it is already at, then migrate. Nothing was applied."
        )

    _acquire(connection, lock_timeout)
    try:
        applied = {a.version: a for a in read_history(connection)} if history_table_exists(connection) else {}
        for migration in on_disk:
            recorded = applied.get(migration.version)
            if recorded is not None and recorded.checksum != migration.checksum:
                raise MigrationChecksumMismatch(
                    f"migration {migration.version} ({migration.name}) is recorded as "
                    f"applied from checksum {recorded.checksum[:12]}..., but the file on "
                    f"disk hashes to {migration.checksum[:12]}.... An applied migration is "
                    "immutable; add a new one instead. Nothing was applied."
                )

        done = []
        for migration in on_disk:
            if migration.version in applied:
                continue
            _apply(connection, migration)
            done.append(migration.version)
        return tuple(done)
    finally:
        _release(connection)


def adopt_existing(
    connection,
    migrations: Optional[Sequence[Migration]] = None,
    *,
    lock_timeout: str = DEFAULT_LOCK_TIMEOUT,
) -> Tuple[int, ...]:
    """
    ONE-TIME ADOPTION of a database created before this mechanism existed.

    Such a database holds the baseline schema and no history, and there is no
    way for it to acquire one by running migrations: migration 2 IS that
    schema, and applying it would abort at 42P07.

    So: migration 1 (the history table) is APPLIED for real, because that
    table genuinely is not there; migration 2 (the baseline) is STAMPED
    WITHOUT RUNNING, because its post-image demonstrably already is. Both in
    ONE transaction, so a database is never left with a history table and no
    baseline row. Everything above the baseline runs normally, by `migrate`.

    THE THREE REFUSALS, each of which is a state where stamping would be a
    lie:
      * the schema is NOT present -- this is an empty or unknown database and
        the baseline should actually run. Use --migrate.
      * a history table already exists -- adoption has happened, or this
        database is further along than the caller thinks.
      * the baseline's post-conditions do not hold -- the sentinel table
        exists but this is not the baseline GENERATION. This is the refusal
        the false-positive defeated: the file's own five post-conditions are
        table probes over tables that predate every security change, so a
        real pre-security database satisfied all five and was stamped as
        current. `_failed_assertions` now also evaluates
        `BASELINE_GENERATION_INVARIANTS` -- column- and constraint-level facts
        that a database of the earlier generation cannot have -- so adoption
        proves the database IS this generation rather than merely holding
        tables of the right names.
    """
    on_disk = tuple(migrations) if migrations is not None else discover()
    by_version = {m.version: m for m in on_disk}
    if BASELINE_VERSION not in by_version or 1 not in by_version:
        raise MigrationSetError(
            f"adoption needs migrations 1 and {BASELINE_VERSION} on disk; found {sorted(by_version)}"
        )

    if history_table_exists(connection):
        raise MigrationStateError(
            f"{HISTORY_TABLE} already exists; this database has a migration history and "
            "does not need adopting. Nothing was changed."
        )
    if not schema_is_present(connection):
        raise MigrationStateError(
            f"this database does not hold the clinical schema (no table "
            f"{SENTINEL_TABLE!r}), so there is no baseline to adopt. Use --migrate, which "
            "will create it. Nothing was changed."
        )

    baseline = by_version[BASELINE_VERSION]
    _acquire(connection, lock_timeout)
    try:
        with connection.cursor() as cur:
            cur.execute(by_version[1].sql)
            _record(cur, by_version[1])
            _record(cur, baseline)
        # The post-condition check happens INSIDE the transaction, so a
        # database that is not actually at the baseline is never stamped.
        failed = _failed_assertions(connection, baseline)
        if failed:
            connection.rollback()
            raise MigrationStateError(
                f"refusing to stamp the baseline: table {SENTINEL_TABLE!r} exists but this "
                "database is not at the baseline schema generation -- it does not satisfy: "
                + "; ".join(failed)
                + ". This database is an EARLIER generation than the code expects; stamping "
                "it would record a version it does not hold and every later migration would "
                "compound the lie. Nothing was changed."
            )
        connection.commit()
        return (1, BASELINE_VERSION)
    finally:
        _release(connection)


# ─── CLI ────────────────────────────────────────────────────────────────────
# `CLINICAL_BOOTSTRAP_DSN`, the same ADMINISTRATIVE DSN clinical/bootstrap.py
# reads, and deliberately not `CLINICAL_DSN`: a migration needs privileges the
# entire GRANT/REVOKE block exists to deny clinical_app, and the service must
# DETECT a version mismatch (it does, at /readyz) rather than fix one.

_BOOTSTRAP_DSN_ENV = "CLINICAL_BOOTSTRAP_DSN"


def _print_state(state: MigrationState) -> None:
    print(f"applied       : {', '.join(str(v) for v in state.applied) or '(none)'}")
    print(f"pending       : {', '.join(str(v) for v in state.pending) or '(none)'}")
    print(f"version       : {state.current_version if state.current_version is not None else '(none)'}")
    print(f"verdict       : {'OK' if state.ok else state.reason}")
    if state.detail:
        print(f"  {state.detail}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m clinical.migrate",
        description="Apply and verify clinical schema migrations. Forward-only.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true", help="report what this database is at")
    group.add_argument("--migrate", action="store_true", help="apply every pending migration, in order")
    group.add_argument(
        "--adopt-existing",
        action="store_true",
        help="record the baseline on a database created before this mechanism (once)",
    )
    group.add_argument(
        "--verify",
        action="store_true",
        help="exit non-zero unless the database matches the migration set (for CI and deploys)",
    )
    parser.add_argument("--lock-timeout", default=DEFAULT_LOCK_TIMEOUT)
    args = parser.parse_args(argv)

    dsn = os.environ.get(_BOOTSTRAP_DSN_ENV)
    if not dsn:
        print(
            f"clinical.migrate: {_BOOTSTRAP_DSN_ENV} is not set. It is the ADMINISTRATIVE "
            "DSN (the one clinical/bootstrap.py uses), not CLINICAL_DSN.",
            file=sys.stderr,
        )
        return 1

    import psycopg

    try:
        with psycopg.connect(dsn, autocommit=False) as connection:
            if args.migrate:
                done = migrate(connection, lock_timeout=args.lock_timeout)
                print(f"applied: {', '.join(str(v) for v in done) or '(nothing pending)'}")
            elif args.adopt_existing:
                done = adopt_existing(connection, lock_timeout=args.lock_timeout)
                print(f"adopted: baseline recorded as {', '.join(str(v) for v in done)}")
            state = inspect_state(connection)
            _print_state(state)
    except MigrationError as exc:
        print(f"clinical.migrate: {exc}", file=sys.stderr)
        return 2

    # EXIT NON-ZERO WHENEVER THE DATABASE IS NOT AT THE VERSION THIS CODE
    # EXPECTS -- not only under --verify. A deploy step that runs `--migrate`
    # and exits 0 on a database whose history claims a version the catalog
    # does not have is the falsely-ready report this mechanism exists to end,
    # moved from /readyz into the pipeline. "Nothing was pending" is not
    # "everything is right": a drifted or checksum-mismatched database has
    # nothing pending and is still wrong.
    #
    # --status is the exception and stays 0 always: it is a QUERY. An operator
    # asking what a database is at has not failed by getting an answer, and a
    # non-zero status would make `--status` unusable in a shell pipeline.
    if not args.status and not state.ok:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
