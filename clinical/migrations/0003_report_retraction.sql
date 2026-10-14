-- clinical/migrations/0003_report_retraction.sql
-- ───────────────────────────────────────────────
-- THE RETRACTION OBJECT SET, AND NOTHING ELSE. Two tables, two indexes, six
-- privilege statements. No existing object is dropped, renamed, or altered,
-- and no application behaviour arrives with it: this migration lands SCHEMA.
-- The verbs that write these tables, and the patient-facing `is_retracted`
-- flag the human approved, are a later commit; this one makes them possible.
--
-- WHERE THESE BYTES CAME FROM, AND WHY YOU SHOULD NOT TRUST A HUMAN READING
-- OF THE DIFF. The DDL below is not transcribed. It was EXTRACTED
-- MECHANICALLY from the held branch `w124-claim-fix` (8a1bfe2), whose stack
-- is `w122-retraction` (a4907d3) -> `w123-e10-matcher` (e821c23) ->
-- `w124-claim-fix` (8a1bfe2) and is LINEAR, so only the tip matters for DDL:
-- `clinical/schema.sql` was read as bytes at 9bc3abd and at 8a1bfe2,
-- line-diffed with difflib.SequenceMatcher, and every opcode that was not
-- `equal` or `insert` was a REFUSAL that produced no output. The run reported
-- four insert blocks, 204 lines, zero non-additive opcodes. The same script
-- then placed those four blocks into `clinical/schema.sql` at fade14e by
-- unique context match and re-diffed the result, requiring it to be purely
-- additive AND byte-identical to the blocks it set out to insert. Additivity
-- here is therefore a MEASUREMENT that failed closed, not an assertion.
--
-- THE COMMENTS BELOW ARE THE HELD BRANCH'S OWN AND ARE NOT EDITED. Two of
-- them point at "below" and "the bottom of this file" and mean
-- `clinical/schema.sql`, where they were written -- `enforce_content_
-- immutability()` and the column-scoped `GRANT UPDATE ... ON reports`. Those
-- references dangle here. Rewriting them would put a human edit between the
-- held branch and this file and cost the property that makes this migration
-- checkable: every line below this header also appears, in the same order,
-- in `clinical/schema.sql`, because both came from the same four derived
-- blocks. `test_w147_migration_0003_retraction.py` asserts exactly that, so
-- an edit to either side that is not made to the other fails a test rather
-- than drifting.
--
-- WHY THE HELD BRANCH'S SCHEMA MAY LAND WHILE ITS CODE MAY NOT. The patient
-- report and trends surfaces have to derive `is_retracted` from this
-- mechanism, and at fade14e the mechanism does not exist -- `git show
-- fade14e:clinical/schema.sql | grep -c "CREATE TABLE report_retractions"`
-- answers 0. Their tests cannot pass before this table does. The rest of the
-- held stack (the `retract_report` verb, the report builder's banners, the
-- E10 reader matcher) is NOT here and is not implied by anything below.
--
-- ORDERING. This migration depends on `reports (org_id, id)` and
-- `users (org_id, user_id)` -- the COMPOSITE unique keys the tenant-isolation
-- generation added -- because four of its foreign keys reference them. That
-- dependency is what makes the ordering proof in
-- `clinical/tests/test_w147_migration_0003_retraction.py` non-vacuous: run
-- this file against a database that is not at the baseline generation and
-- Postgres RAISES (SQLSTATE 42830, "there is no unique constraint matching
-- the given keys") rather than refusing politely. That is measured in that
-- file, and it is the same hazard w146 recorded for a third migration that
-- indexes a column a wrong-generation database lacks: the DDL is the thing
-- that fails, so the refusal is Postgres's, not the runner's. The runner's
-- own refusal happens EARLIER, at adoption, and is what a wrong-generation
-- database actually meets first.
--
-- THE POST-CONDITIONS BELOW ARE THE WEAK HALF, AND SAY SO. A
-- `MIGRATION-ASSERT` line is a bare `to_regclass` probe and can see only that
-- a relation of that name exists. The facts that separate THIS generation
-- from the one before it -- columns and named constraints -- are the
-- GENERATION INVARIANTS, and they live in `clinical/migrate.py` under
-- `(3, "report_retraction")`, for the reason stated at length there: this
-- file's checksum is stamped by `clinical/schema.sql`, so its bytes are
-- frozen the moment it ships. Both sets are evaluated by the same
-- `_failed_assertions` loop on every `inspect_state`, so `/readyz` sees both.
--
-- MIGRATION-ASSERT: to_regclass('report_retractions') IS NOT NULL
-- MIGRATION-ASSERT: to_regclass('retraction_notifications') IS NOT NULL
-- MIGRATION-ASSERT: to_regclass('idx_retraction_org_report') IS NOT NULL
-- MIGRATION-ASSERT: to_regclass('idx_retraction_notification_org_retraction') IS NOT NULL

-- ─── w122: Report retraction (model 3, human-approved 2026-09-13) ──────────
--
-- A retraction says "DO NOT ACT ON THIS DOCUMENT". It is NOT a state, NOT a
-- sixth value of reports.state, and NOT a column on reports. The approved
-- `reports` row stays BYTE-IDENTICAL: the report WAS approved on the day it
-- was approved, and a row rewritten to say otherwise would destroy THE
-- REPORT'S OWN record of that approval. Not the last trace of it -- w124
-- checked before letting "the only record" stand: _approve_report is
-- @auditable, so an audit_log 'report_approved' entry keeps the actor and the
-- moment. But no reader of this platform asks audit_log whether a report is
-- approved, and reports_approval_complete and
-- reports_released_states_need_approval force the three approval facts to
-- travel with the state, so "un-approving" cannot be done truthfully.
--
-- THE TRIGGER IS NOT BEING WORKED AROUND, IT IS BEING SERVED. The walk-back
-- clause in enforce_content_immutability() below exists because an approved
-- report could be "effectively WITHDRAWN FROM THE RECORD without touching a
-- single content column" -- the harm it names is INVISIBILITY, not
-- withdrawal. A row carrying an actor, a timestamp, a reason and a composite
-- FK to the report is the maximally visible withdrawal. No clause of that
-- trigger changes, no CHECK on reports.state changes, and the
-- GRANT UPDATE (state, approver_id, approved_at, content_hash) ON reports
-- line at the bottom of this file is untouched.
--
-- Append-only, exactly as reviewer_claims/release_events/amendments are, and
-- for the same reason: a retraction quietly edited or deleted after the fact
-- would leave no trace. There is no UPDATE grant for clinical_app and there
-- should never be one -- see the "WITH NO EXCEPTION" note in the grant block
-- below. E5 (human ruling): retraction is NOT reversible in this wave and no
-- reversal is built; if it is ever ruled in, its shape is already settled by
-- the rest of this schema -- a second row superseding the first, never an
-- edit -- and adding a self-FK to an append-only table is additive.

CREATE TABLE report_retractions (
    org_id              UUID        NOT NULL,
    id                  UUID        PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),

    -- The report being retracted. Composite FK: a retraction of another
    -- organisation's report is structurally impossible, not merely unlikely
    -- (the same reasoning as reports.approver_id).
    report_id           UUID        NOT NULL,

    retracted_at        TIMESTAMPTZ NOT NULL,
    retracted_by        UUID        NOT NULL,

    -- Reason (NOT NULL), following amendments.reason and
    -- reviewer_claims.reason: the reason a document was withdrawn must be
    -- retrievable, and a retraction nobody can account for is the invisible
    -- withdrawal this table exists to replace.
    reason              TEXT        NOT NULL,

    -- HUMAN RULING E1: a retraction may be recorded against a report that is
    -- 'approved' OR 'released', AND THE ROW RECORDS WHICH. Stored rather than
    -- inferred from reports.state, for the same reason the banners carry an
    -- explicit *_basis (ruling R2): reports.state advances after this row is
    -- written -- an approved report retracted today can be released
    -- tomorrow -- so reading it back later would silently change what this
    -- row claims. A report that was approved but never issued must never be
    -- described to a clinician as having been issued.
    retracted_from_state TEXT       NOT NULL
        CHECK (retracted_from_state IN ('approved', 'released')),

    -- HUMAN RULING E4: a replacement is OPTIONAL. A report issued against the
    -- wrong patient's sample has nothing to replace it with, and requiring a
    -- replacement would force a false row into existence to satisfy a
    -- constraint -- the exact shape reviewer_claims' sole_signatory ruling
    -- was created to avoid. NULL means "no replacement report has been
    -- issued", which the banner states rather than glossing over.
    replacement_report_id UUID,

    -- HUMAN RULING E8: no change to the retention clock. A retraction is an
    -- artefact of a specific clinical action on a specific report, not a
    -- record with standing of its own, so it cascade-tombstones WITH the
    -- report it retracts, in the same transaction, exactly like
    -- release_events and amendments (RetentionPrincipal
    -- ::_cascade_tombstone_report_dependents).
    tombstoned_at       TIMESTAMPTZ,
    tombstoned_by       UUID,

    CONSTRAINT fk_retraction_report
        FOREIGN KEY (org_id, report_id) REFERENCES reports (org_id, id),
    CONSTRAINT fk_retraction_retractor
        FOREIGN KEY (org_id, retracted_by) REFERENCES users (org_id, user_id),
    CONSTRAINT fk_retraction_replacement
        FOREIGN KEY (org_id, replacement_report_id) REFERENCES reports (org_id, id),
    CONSTRAINT fk_retraction_tombstoner
        FOREIGN KEY (org_id, tombstoned_by) REFERENCES users (org_id, user_id),
    CONSTRAINT retraction_tombstone_complete CHECK (
        (tombstoned_at IS NULL) = (tombstoned_by IS NULL)
    ),
    -- A report cannot be its own replacement: that would render a banner
    -- instructing the reader to obtain the document they are already holding.
    CONSTRAINT retraction_replacement_is_not_itself CHECK (
        replacement_report_id IS NULL OR replacement_report_id <> report_id
    ),
    CONSTRAINT uk_retraction_org_id UNIQUE (org_id, id)
);

CREATE INDEX idx_retraction_org_report
    ON report_retractions (org_id, report_id, retracted_at);


-- ─── w122: Retraction notification obligations (human ruling E6) ───────────
--
-- E6: notification of a retraction to the parties who already hold the report
-- is OWED, is RECORDED, and does NOT BLOCK the retraction. A lab that has
-- discovered a dangerous report must never be prevented from recording that
-- fact because an email did not send -- and no email can send, because THERE
-- IS NO DELIVERY TRANSPORT ANYWHERE IN THIS PLATFORM.
--
-- PER CONSUMER, NOT PER ROLE (human ruling E6, stated in those words). This
-- is the difference the RULING names, not the only structural difference from
-- amendment_notifications -- w124 counted them: that table has no `status`
-- column at all (see the paragraph below) and no uniqueness on its recipient,
-- so this one carries two columns and one constraint it has no counterpart
-- for. What E6 settled is the recipient column: amendment_notifications
-- hardcodes delivered_to_role = 'ordering_clinician'. release_events.consumer
-- is free text and names "a clinician, a patient, a LIMS, any consumer"
-- (spec 13.4): a release event's consumer may be a LIMS, and a role is an
-- abstraction over people that a LIMS is not. One obligation per DISTINCT
-- consumer that received this report, deduplicated by the unique constraint
-- below -- re-delivery to the same consumer is one debt, not two, the same
-- way D3 rules that re-delivery does not restart the retention clock.
--
-- WHAT `status` DOES NOT SAY. amendment_notifications' docstring says
-- notifications are "Recorded as sent" while the sentence before it says the
-- transport is deferred; only one of those can be true and it is the first.
-- A row here asserts a DEBT, never a transmission. The vocabulary therefore
-- has exactly one value today: there is no 'sent' and no 'discharged',
-- because nothing in this platform can send or discharge one. A discharge
-- value is added by the commit that builds the transport, which is the
-- commit that can honestly write it.
CREATE TABLE retraction_notifications (
    org_id              UUID        NOT NULL,
    id                  UUID        PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    retraction_id       UUID        NOT NULL,

    -- The downstream recipient, copied from release_events.consumer -- the
    -- party that actually received the retracted report.
    consumer            TEXT        NOT NULL,

    -- Denormalized from report_retractions.reason, for the same reason
    -- amendment_notifications denormalizes amendments.reason: the recipient
    -- has to be able to understand why without a join.
    reason_for_retraction TEXT      NOT NULL,

    status              TEXT        NOT NULL DEFAULT 'notification_owed'
        CHECK (status = 'notification_owed'),

    created_at          TIMESTAMPTZ NOT NULL,
    created_by          UUID        NOT NULL,

    tombstoned_at       TIMESTAMPTZ,
    tombstoned_by       UUID,

    CONSTRAINT fk_retraction_notification_retraction
        FOREIGN KEY (org_id, retraction_id) REFERENCES report_retractions (org_id, id),
    CONSTRAINT fk_retraction_notification_creator
        FOREIGN KEY (org_id, created_by) REFERENCES users (org_id, user_id),
    CONSTRAINT fk_retraction_notification_tombstoner
        FOREIGN KEY (org_id, tombstoned_by) REFERENCES users (org_id, user_id),
    CONSTRAINT retraction_notification_tombstone_complete CHECK (
        (tombstoned_at IS NULL) = (tombstoned_by IS NULL)
    ),
    -- One outstanding debt per consumer per retraction. Enforced here rather
    -- than by the writer's SELECT DISTINCT alone, so a second delivery path
    -- cannot double-count the same recipient.
    CONSTRAINT uk_retraction_notification_consumer
        UNIQUE (org_id, retraction_id, consumer),
    CONSTRAINT uk_retraction_notification_org_id UNIQUE (org_id, id)
);

CREATE INDEX idx_retraction_notification_org_retraction
    ON retraction_notifications (org_id, retraction_id);

-- w122: report_retractions and retraction_notifications join the append-only
-- block above, under the same "WITH NO EXCEPTION" rule and for the sharpest
-- version of the same reason: a retraction is a deliberate safety act, and a
-- retraction that could be edited or deleted after the fact would let a
-- withdrawal be un-said with no trace -- which is the invisible withdrawal
-- the immutability trigger exists to forbid, arriving by the other door.
--
-- A SEPARATE GRANT LINE, NOT AN ADDITION TO THE ONE ABOVE, so this wave's
-- diff cannot be misread as having touched the five tables that were already
-- there.
GRANT  SELECT, INSERT ON report_retractions, retraction_notifications TO clinical_app;
REVOKE UPDATE, DELETE ON report_retractions, retraction_notifications FROM clinical_app;
REVOKE UPDATE, DELETE ON report_retractions, retraction_notifications FROM PUBLIC;

-- w122, human ruling E8: a retraction and its notification obligations
-- cascade-tombstone WITH the report they are about -- same category as the
-- five above ("artefacts of a specific clinical action ... not records with
-- standing of their own"), same COLUMN-LEVEL grant shape rather than the
-- table-level one, so this wave introduces no fresh instance of the
-- over-broad-grant shape. E8 also settles what does NOT change: the purge
-- eligibility query in RetentionPrincipal::_purge_reports is untouched -- a
-- retraction neither shortens the window nor blocks the purge the way a live
-- amendment does (D6).
GRANT  SELECT                      ON report_retractions, retraction_notifications TO clinical_retention;
GRANT  UPDATE (tombstoned_at, tombstoned_by)
    ON report_retractions, retraction_notifications
    TO clinical_retention;

REVOKE DELETE ON report_retractions, retraction_notifications FROM clinical_retention;
