"""
clinical/tests/test_w156_retraction_reachability.py
───────────────────────────────────────────────────
WAVE 6, AND THE FIRST THING IT DID WAS TEST ITS OWN PREMISE.

The wave's text says "make the already-implemented capabilities reachable" and
"use the existing retraction domain mechanism". MEASURED AT `w126m-migrations`
tip `7bb6f8c`, by walking the syntax tree of all 299 non-test Python files in
the repository rather than by grepping (a substring scan credits prose as a
definition, and this floor has already had a guard fire on a docstring):

  * `retract_report`          — ZERO definitions in production. NOT
                                "implemented but unreachable". ABSENT.
  * exception AMENDMENT verb  — ZERO definitions. Migration `0004` landed the
                                tenant-safe composite relationship;
                                `exception_events.action` was still CHECKed to
                                exactly ('open', 'resolve', 'reopen').
                                UPDATED w161: migration `0005` widened that
                                CHECK to admit 'amend_resolution', so the verb
                                is no longer stopped on the schema — it is
                                stopped on being unwritten. STILL ZERO
                                definitions.
  * `read_audit`              — DEFINED (`clinical/data_access.py`) and
                                REACHABLE: `GET /admin/audit` calls it,
                                Auditor-gated, wired in w152 (WAVE 2).

So one of the three was "make reachable" and it was already made reachable two
waves ago; one was "write from nothing"; and one is STOPPED. Said plainly,
because the distinction decides what this file is:

  AUDIT-LOG ACCESS — REACHABLE ALREADY. Nothing was built for it. Its
  properties are proved in `test_w152_admin_surface.py`
  (`test_an_auditor_can_read_the_audit_trail`,
  `test_an_administrator_is_not_an_auditor`,
  `test_an_auditor_cannot_see_the_other_organisations_trail_and_the_row_is_planted`).
  This file adds ONE row about it and only one: the Approver — a role that
  reaches this surface for the first time this wave — is not an Auditor. A
  second copy of w152's rows would be a second answer to the same question.

  REPORT RETRACTION — WRITTEN FROM NOTHING, in this tree's own idiom, and
  made reachable at `POST /admin/reports/{report_id}/retraction`. Every
  product question it carries was already settled by something IN THIS TREE
  (rulings E1, E3, E4, E5, E6, E7, E8, recorded in
  `clinical/migrations/0003_report_retraction.sql`, `clinical/schema.sql` and
  `clinical/data_access.py`) except ONE — which role may retract — and the
  note above `retract_report` says exactly how that was answered and why it
  is the existing role model rather than a new decision.

  EXCEPTION AMENDMENT — STOPPED AND CARDED. Writing the verb requires the
  value `'amend_resolution'` in `exception_events.action`'s CHECK. Widening
  an inline CHECK is DROP CONSTRAINT + ADD CONSTRAINT — a destructive
  statement — so it is a migration, and migration `0004`'s own header records
  that this is precisely where the held branch stops being additive. This
  wave was instructed to add no schema. The relationship's behaviour is
  ALREADY fully proved by `test_w149_migration_0004_amendment.py`
  (same-org accepted, cross-org refused with SQLSTATE 23503 named,
  the two refusals asserted as a set of size one, audit attribution, and
  `test_5b_nothing_in_the_repository_writes_an_amendment`, which is a
  tripwire this wave deliberately leaves green). Nothing here duplicates it.

WHY THE VERB WAS WRITTEN RATHER THAN LIFTED. The held branch `w122-retraction`
(`a4907d3`) defines `retract_report` and was READ — `git show`, never merged,
never modified. Migration `0003` lifted its DDL MECHANICALLY under an approved
schema decision; no decision approved importing its APPLICATION code, and
application code is more decision-laden than DDL. It was therefore written
fresh against this tip, whose idiom has moved (`REPORT_NOT_FOUND`, the w129
phase-B authority rework, the `is_retracted` projection, the administrative
surface's `_target`/`_forbidden`/`_not_found` model — none of which existed at
`a4907d3`). Where the result converges with the held branch, that is the
schema and the recorded rulings forcing the shape, and it is said out loud in
the note above the method rather than left for a reader to guess.

THE TWO TRIPWIRES FIRED, AS THE BRIEF SAID THEY WOULD.
`test_w135_patient_report_access.py` and `test_w136_trends_retraction.py` each
carried a row asserting `def retract_report` is absent, and each said in its
own failure message that the verdict "needs revisiting" if it ever appeared.
Both are RE-AUTHORED INTO POSITIVE ROWS — the verb exists AND its first
statement is the Approver gate — and neither is deleted, skipped or weakened.
Both were re-authored onto the SYNTAX TREE rather than the file text, because
this wave added roughly a hundred lines of docstring naming the verb and a
substring row of the opposite polarity would have been satisfied by the prose.
The helper they share, `_first_role_gate`, lives here and has its non-vacuity
twin in w135.

WHAT "NO UNSAFE PATIENT EXPOSURE" MEANS HERE, AND IT IS PROVED RATHER THAN
ASSUMED. The approved patient decisions are unchanged: the patient surfaces
expose `is_retracted` ONLY. w135 and w136 already prove that for a retraction
ARRANGED BY DIRECT INSERT. What this file proves is the half that only exists
now: the same surfaces still expose only `is_retracted` when the row was
written by the VERB, through the HTTP ROUTE, by a real Approver, WITH a
replacement report present — the one field E4 makes optional and human
decision 1 refuses to the patient. That combination could not be constructed
before this wave, and it is the one a leak would ride in on.

THE SIX MEASURED HAZARDS, AND WHERE EACH IS ANSWERED:
  1. `@auditable` has no `functools.wraps` — signature inspection answers
