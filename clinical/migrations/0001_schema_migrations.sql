-- clinical/migrations/0001_schema_migrations.sql
-- ───────────────────────────────────────────────
-- THE MIGRATION HISTORY TABLE. It is migration 0001 and it is the only
-- migration that has to exist before the mechanism can record anything, so
-- read the ordering carefully: `clinical/migrate.py` runs each migration's
-- SQL and then INSERTs its history row INSIDE THE SAME TRANSACTION. Postgres
-- has transactional DDL, so by the time 0001's history row is inserted the
-- table it is inserted into exists, and if anything in that transaction
-- fails the table and the row disappear together. There is no bootstrap
-- special case, no CREATE TABLE IF NOT EXISTS, and no "create the history
-- table outside the mechanism" step -- the mechanism records its own
-- arrival by the same rule it records everything else.
--
-- WHY A TABLE AND NOT A FILE, A COMMENT OR A CHECKSUM OF schema.sql. The
-- question a deployment has to answer is "what state is THIS database in",
-- and only the database can answer it. `clinical/schema.sql` is authoritative
-- about what a NEW database gets and about nothing else: nothing in the
-- repository linked it to any live database, so a running system could not be
-- asked what it was -- only introspected object by object, and `/readyz`
-- proved nothing because it probed a table that exists in every variant.
--
-- WHY version IS AN INTEGER PRIMARY KEY AND NOT A TIMESTAMP OR A HASH.
-- The primary key is the whole no-silent-re-application guarantee: a second
-- attempt to apply version 1 is a duplicate-key violation inside the same
-- transaction as the DDL, so the DDL rolls back with it. That property is
-- structural, not a check someone remembers to write. An INTEGER also orders
-- the way the filenames order (0001, 0002, ... ), so "apply in order" and
-- "apply in filename order" cannot diverge -- see migrate.py::discover, which
-- reads the integer OUT OF the filename rather than sorting the strings.
--
-- WHY checksum IS STORED. `version` says WHICH migration ran; `checksum`
-- says WHICH BYTES ran. Without it, editing an already-applied migration
-- file is invisible: the history still says "1 applied", the database still
-- holds the old shape, and the new bytes never run anywhere. The checksum is
-- SHA-256 over the file's bytes, computed by migrate.py::checksum_of.
--
-- WHY applied_at AND applied_by. A migration runs with more privilege than
-- clinical_app has ever had, against append-only tables clinical_app is
-- structurally forbidden to modify, and no audit_log row records it -- the
-- platform spec says as much. These two columns are the only trace such a
-- run leaves. `current_user` is the role the migration actually connected
-- as, recorded by the server rather than claimed by the client.
--
-- THE POST-CONDITION, which is what makes "applied" a measurement rather than
-- a claim. clinical/migrate.py::inspect_state re-evaluates this against
-- pg_catalog every time it is asked -- including on every /readyz -- so a
-- history row saying version 1 is applied cannot outlive the table it says
-- was created.
--
-- MIGRATION-ASSERT: to_regclass('schema_migrations') IS NOT NULL
CREATE TABLE schema_migrations (
    version     INTEGER     PRIMARY KEY,
    name        TEXT        NOT NULL,
    checksum    TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_by  TEXT        NOT NULL DEFAULT current_user
);

-- THE APPLICATION MAY READ ITS OWN VERSION AND MAY NEVER WRITE IT.
--
-- SELECT, because `/readyz` connects as clinical_app (CLINICAL_DSN) and has
-- to be able to tell a database this code can serve from one it cannot. A
-- readiness probe that cannot read the history is the false-green probe
-- again, one level up.
--
-- and nothing else, because a service that can INSERT into schema_migrations
-- can declare itself migrated without migrating -- which is exactly the
-- failure the history exists to make impossible. The REVOKEs are declarative:
-- nothing above grants those privileges, and stating the refusal is how this
-- schema says "not an oversight" everywhere else (see the audit_log and
-- fastq_sets blocks). clinical_retention is given nothing at all: retention
-- tombstones clinical rows and has no business reading deployment state.
REVOKE ALL                    ON schema_migrations FROM PUBLIC;
GRANT  SELECT                 ON schema_migrations TO clinical_app;
REVOKE INSERT, UPDATE, DELETE ON schema_migrations FROM clinical_app;
