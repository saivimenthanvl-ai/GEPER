"""
clinical/tests/test_w126m_schema_equivalence.py
───────────────────────────────────────────────
THE CENTREPIECE. Two ways to build one database; nothing compared them until
this file.

THE FAILURE MODE IT EXISTS FOR, stated before anything else. Every FRESH
database comes from `clinical/schema.sql`, which creates the current state
directly and stamps the history as applied. Every EXISTING database is brought
forward by the ordered migrations. Those are two independent descriptions of
one schema, maintained by hand, in two places. Six months and four migrations
from now they describe different databases -- and every other test in this
repository still passes, because every other test builds its database from
`schema.sql` and never runs a migration at all. Nothing anywhere would say so.

    Database X: created from clinical/schema.sql.
    Database Y: created by running the ordered migrations from empty.
    Compare the CATALOGS. Any difference fails, and prints itself.

READ FROM information_schema AND pg_catalog, NEVER FROM THE FILES. A
comparison of the two files would be a comparison of two texts, and the whole
point is that the texts are allowed to differ -- one is a post-image, the
other is a sequence of operations that reaches it. Only the server can say
whether they arrive at the same place. NINE catalogs are compared -- counted,
not estimated, and the count is `len(_CATALOG_QUERIES)` below: tables; columns
(with type, nullability and default); constraints (by definition, which is how
a CHECK's expression and a FOREIGN KEY's target get compared); indexes (by
definition); table privileges and column privileges (the grants this schema
relies on); sequences; functions; triggers.

THE ONE THING DELIBERATELY NOT COMPARED, said out loud rather than left to be
discovered: `ordinal_position`. A column added by `ALTER TABLE ... ADD COLUMN`
lands at the end of the table, while `schema.sql` will naturally write it
where it belongs in the CREATE TABLE. That divergence is real -- `SELECT *`
returns columns in a different order -- and it is the accepted cost of
fresh-database option A. Everything about the column except where it sits is
compared. If a future change makes column ORDER load-bearing, this is the
line to revisit.
"""

from __future__ import annotations

import pathlib

from clinical import migrate
from clinical.tests.migration_db import connect, scratch_database

SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"

# Every query is ORDER BY'd, so a difference is a difference and never a row
# order. `pg_get_constraintdef` and `pg_get_indexdef` are used rather than the
# constraint's component columns because they render the WHOLE definition --
# a CHECK's expression, a FOREIGN KEY's referenced columns and its actions --
# in a form the server itself normalises, so two spellings of one constraint
# compare equal and two different constraints never do.
_CATALOG_QUERIES = {
    "tables": """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name
    """,
    "columns": """
        SELECT table_name, column_name, data_type, udt_name, is_nullable,
               column_default, character_maximum_length, numeric_precision, numeric_scale
        FROM information_schema.columns
        WHERE table_schema = 'public'
        ORDER BY table_name, column_name
    """,
    "constraints": """
        SELECT cl.relname, con.conname, pg_get_constraintdef(con.oid)
        FROM pg_constraint con
        JOIN pg_class cl ON cl.oid = con.conrelid
        JOIN pg_namespace ns ON ns.oid = cl.relnamespace
        WHERE ns.nspname = 'public'
        ORDER BY cl.relname, con.conname
    """,
    "indexes": """
        SELECT tablename, indexname, indexdef
        FROM pg_indexes
        WHERE schemaname = 'public'
        ORDER BY tablename, indexname
    """,
    "table_privileges": """
        SELECT grantee, table_name, privilege_type
        FROM information_schema.role_table_grants
        WHERE table_schema = 'public'
        ORDER BY grantee, table_name, privilege_type
    """,
    "column_privileges": """
        SELECT grantee, table_name, column_name, privilege_type
        FROM information_schema.column_privileges
        WHERE table_schema = 'public'
        ORDER BY grantee, table_name, column_name, privilege_type
    """,
    "sequences": """
        SELECT sequence_name, data_type, start_value, increment
        FROM information_schema.sequences
        WHERE sequence_schema = 'public'
        ORDER BY sequence_name
    """,
    "functions": """
        SELECT p.proname, pg_get_functiondef(p.oid)
        FROM pg_proc p
        JOIN pg_namespace ns ON ns.oid = p.pronamespace
        WHERE ns.nspname = 'public'
        ORDER BY p.proname
    """,
    "triggers": """
        SELECT cl.relname, tg.tgname, pg_get_triggerdef(tg.oid)
        FROM pg_trigger tg
        JOIN pg_class cl ON cl.oid = tg.tgrelid
        JOIN pg_namespace ns ON ns.oid = cl.relnamespace
        WHERE ns.nspname = 'public' AND NOT tg.tgisinternal
        ORDER BY cl.relname, tg.tgname
    """,
}


def catalog_of(connection) -> dict:
    """The database's shape as the SERVER reports it."""
    snapshot = {}
    for section, query in _CATALOG_QUERIES.items():
        with connection.cursor() as cur:
            cur.execute(query)
            snapshot[section] = tuple(tuple(row) for row in cur.fetchall())
    return snapshot


def describe_difference(left_name: str, left: dict, right_name: str, right: dict) -> str:
    """Every difference, printed. Not "they differ" -- WHICH rows, and which
    side each is on, because a diff nobody can read is a failure nobody can
    act on."""
    lines = []
    for section in _CATALOG_QUERIES:
        only_left = [row for row in left[section] if row not in right[section]]
        only_right = [row for row in right[section] if row not in left[section]]
        if not only_left and not only_right:
            continue
        lines.append(f"\n── {section} ──")
        for row in only_left:
            lines.append(f"  only in {left_name}:  {row!r}")
        for row in only_right:
            lines.append(f"  only in {right_name}: {row!r}")
    return "\n".join(lines)


def _build_from_schema_sql(connection) -> None:
    with connection.cursor() as cur:
        cur.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
    connection.commit()


class TestTheTwoWaysOfBuildingThisDatabaseAgree:
    def test_schema_sql_and_the_migration_set_produce_the_same_catalog(self):
        """
        THE PROOF. X from `clinical/schema.sql`; Y from the ordered
        migrations, from empty. Nine catalogs, any difference fails.

        CATCHES: a migration added without the matching edit to `schema.sql`,
        and an edit to `schema.sql` without the migration that reaches it --
        in either direction, which is why both `only in X` and `only in Y` are
        reported. It is the guard that makes fresh-database option A safe
        rather than merely convenient.

        VACUOUS AGAINST: everything about the RUNNER. Two identical catalogs
        say nothing about whether the history was recorded, whether a second
        run is a no-op, or whether two runners can collide. Those are the
        other three files.
        """
        with scratch_database("w126m_canon") as dsn_x, scratch_database("w126m_mig") as dsn_y:
            with connect(dsn_x) as x, connect(dsn_y) as y:
                _build_from_schema_sql(x)
                migrate.migrate(y)

                left = catalog_of(x)
                right = catalog_of(y)

            difference = describe_difference("schema.sql", left, "migrations", right)
            assert not difference, (
                "clinical/schema.sql and clinical/migrations/ have drifted apart. A fresh "
                "database and an upgraded one are no longer the same database:" + difference
            )

    def test_both_ways_arrive_at_the_same_recorded_version(self):
        """
        The catalogs can match while the HISTORIES do not -- a fresh database
        stamped at the wrong version would report pending migrations for ever
        and the next deploy would try to re-run the baseline. So the history
        is compared too, by content: version, name and checksum.
        """
        with scratch_database("w126m_canon") as dsn_x, scratch_database("w126m_mig") as dsn_y:
            with connect(dsn_x) as x, connect(dsn_y) as y:
                _build_from_schema_sql(x)
                migrate.migrate(y)

                def history(connection):
                    with connection.cursor() as cur:
                        cur.execute("SELECT version, name, checksum FROM schema_migrations ORDER BY version")
                        return tuple(cur.fetchall())

                assert history(x) == history(y)
                assert migrate.inspect_state(x).ok is True
                assert migrate.inspect_state(y).ok is True

    def test_the_comparison_can_actually_fail(self):
        """
        THE NON-VACUITY CHECK, and this file needs one more than most: a
        comparison that returns "no difference" because it compared nothing
        would pass the two rows above for ever, on any pair of databases, and
        nobody would ever look at it again.

        So: build both, then ADD ONE COLUMN to one of them, and require the
        comparison to name that column. An equivalence proof that cannot
        report a difference is not a proof.
        """
        with scratch_database("w126m_canon") as dsn_x, scratch_database("w126m_mig") as dsn_y:
            with connect(dsn_x) as x, connect(dsn_y) as y:
                _build_from_schema_sql(x)
                migrate.migrate(y)
                with y.cursor() as cur:
                    cur.execute("ALTER TABLE organisations ADD COLUMN w126m_drift TEXT")
                y.commit()

                difference = describe_difference("schema.sql", catalog_of(x), "migrations", catalog_of(y))

        assert difference
        assert "w126m_drift" in difference
        assert "only in migrations" in difference

    def test_the_comparison_reads_more_than_table_names(self):
        """
        The second half of non-vacuity. A snapshot of table names alone would
        pass the row above (the column changed, not the table list) -- so
        prove the CONSTRAINT and INDEX channels are live too, by dropping a
        constraint and an index rather than adding a column.

        CATCHES: a catalog query that silently returns nothing (a wrong
        schema name, a typo'd system view) -- the shape of failure that makes
        an equivalence proof a decoration.
        """
        with scratch_database("w126m_canon") as dsn_x, scratch_database("w126m_mig") as dsn_y:
            with connect(dsn_x) as x, connect(dsn_y) as y:
                _build_from_schema_sql(x)
                migrate.migrate(y)
                with y.cursor() as cur:
                    cur.execute("ALTER TABLE organisations DROP CONSTRAINT organisations_pkey CASCADE")
                y.commit()

                left, right = catalog_of(x), catalog_of(y)

        assert left["constraints"] and left["indexes"] and left["table_privileges"]
        difference = describe_difference("schema.sql", left, "migrations", right)
        assert "organisations_pkey" in difference
