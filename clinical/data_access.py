        reason="idempotency probe on every scan; auditing it would bury the detections in noise",
    )
    def find_fastq_set_by_checksums(self, session: Session, r1_checksum: str, r2_checksum: str) -> Optional[uuid.UUID]:
        """
        The existing row for this exact pair of file contents, if any.

        THE CHECKSUM PAIR IS THE IDEMPOTENCY KEY, NOT THE PATH (human ruling,
        2026-09-08). A moved or renamed file with the same content is the SAME
        observation; a reused path with new content is a DIFFERENT one. This is
        why `fastq_sets` deliberately carries no `UNIQUE (org_id, r1_path)`: a
        path-based constraint would have been wrong in both directions.

        w129c: THE ORGANISATION IS READ OFF THE SESSION, NOT OFF AN ARGUMENT.
        This used to take a raw `org_id`, which made the tenant scope a CLAIM
        the caller asserted rather than a property of an authenticated
        principal -- and a checksum probe that can name any organisation is an
        existence oracle over another tenant's file contents. The ruling left
        the READ PATH's AUTHORISATION alone and it is left alone: no role gate,
        still `auditable=False` for the reason above. Only the source of the
        org_id changed, which is what `Session`'s own docstring already
        requires of every call that takes one.
        """
        row = self._query_one(
            "SELECT fastq_set_id FROM fastq_sets WHERE org_id = %s AND r1_checksum = %s AND r2_checksum = %s",
            (session.org_id, r1_checksum, r2_checksum),
        )
        return None if row is None else row[0]

    @auditable(
        action="fastq_set_detected",
        resource_type="fastq_set",
        requires_session=True,
    )
    def record_fastq_set(
        self,
        session: Session,
        sample_id: uuid.UUID,
        r1_path: str,
        r2_path: str,
        r1_checksum: str,
        r2_checksum: str,
        detected_at: _datetime.datetime,
    ) -> uuid.UUID:
        """
        Append one `fastq_sets` row for a sample IN THIS ORGANISATION.

        Raises `NotFoundError` if the sample does not resolve. That exception
        already carries the property this needs and its docstring says so:
        "deliberately indistinguishable from does not exist at all". ANOTHER
        ORGANISATION'S SAMPLE MUST BE INDISTINGUISHABLE FROM UNKNOWN, not
        merely refused -- a distinct error for "exists but not yours" tells the
        caller which sample ids exist elsewhere. So the resolution below
        filters on org_id and the caller cannot tell the two cases apart.

        w129c: IT TAKES A SESSION AND THE SESSION MUST HOLD `System`.

        This paragraph used to read "No `session` argument: a scheduled scan
        has no logged-in user", and reached for the PROVISIONING audit path
        (org_id off the bound parameters, actor null). That was DRIFT, not
        architecture. "No logged-in user" is precisely the condition the System
        principal exists to answer -- `record_pipeline_result` in this same
        file already has the shape: it takes a `Session` and the worker mints
        it. Two precedents were available and the provisioning one was picked
        in passing, never argued. Three things were wrong as a result: the
        organisation was a caller-supplied CLAIM rather than a property of an
        authenticated principal; every detection was audited with a NULL
        ACTOR; and this was the only `requires_session=False` method in the
        file that writes a tenant-scoped row -- a category of one.

        THE ROLE GATE IS `System`, NOT `Lab technician`. Detection is the
        platform observing a directory, not a member of laboratory staff
        receiving a specimen, and w129 forbids treating an internal principal
        as a normal human staff role. A human session holding Administrator,
        Interpreter, Orderer AND Lab technician is refused here.

        THE SESSION COMES FROM THE CALLER. Neither this method nor
        `clinical/ingestion.py` mints one. `_create_system_session` is an
        authentication bypass whose invariant is about WHERE, not how many:
        every call site sits in a background worker class in `geper/api/`.
        Minting one in the scanner would be a FIFTH site in a non-worker module
        and test_identity.py's
        `test_create_system_session_call_sites_are_the_four_pinned_worker_sites`
        would fail -- correctly. The not-yet-written scheduler is the thing
        that has to be explicit about which principal it runs as.

        The audit row still comes from `@auditable` and only from it: an
        earlier draft called `self._audit` by hand as well and would have
        written TWO rows per detection.
        """
        self._require_role(session, "System")

        sample = self._query_one(
            "SELECT sample_id FROM samples WHERE sample_id = %s AND org_id = %s",
            (sample_id, session.org_id),
        )
        if sample is None:
            raise NotFoundError(f"Sample {sample_id} not found")

        fastq_set_id = uuid.uuid4()
        self._execute(
            "INSERT INTO fastq_sets (fastq_set_id, org_id, sample_id, r1_path, r2_path, "
            "r1_checksum, r2_checksum, detected_at, state) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'detected')",
            (fastq_set_id, session.org_id, sample_id, r1_path, r2_path, r1_checksum, r2_checksum, detected_at),
        )
        return fastq_set_id


# A real bcrypt hash of a value nobody holds, used only to spend verification
# work when no user matched. Generated once, constant thereafter.
_DUMMY_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.6c1sVQ0S0kzSfKUL5jHkKzE1LpMOxQ2"
