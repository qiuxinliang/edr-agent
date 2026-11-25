"""Transaction witness for the isolated owner-range experiment.

Install only in an empty synthetic fixture. The unmodified native writer still
owns the primary rows, all owner checks and recovery decisions. SQLite triggers
mirror the exact accepted changes in the same transaction. Never install this
witness on an endpoint database.
"""
from probe_evidence_owner_ranges import RANGE_SCHEMA, REFERENCE_COLUMNS

COLUMNS = ",".join(REFERENCE_COLUMNS)
NEW_FIELDS = ",".join("NEW." + col for col in REFERENCE_COLUMNS)
# Locate exactly one possible containing run by its primary key. An ID gap
# belongs to no run, irrespective of timestamps, PID, or process ancestry.
PREVIOUS = "(SELECT max(first_ref_id) FROM probe_owner_ranges WHERE first_ref_id < NEW.id)"
CONTAINING = "(SELECT max(first_ref_id) FROM probe_owner_ranges WHERE first_ref_id <= NEW.id)"
CONTAINS_NEW = (
    f"first_ref_id={CONTAINING} AND NEW.id-first_ref_id < member_count"
)


def is_standard(prefix):
    return (
        f"typeof({prefix}.source_identity)='blob' AND length({prefix}.source_identity)=32 "
        f"AND {prefix}.artifact_override IS NULL AND {prefix}.candidate_json_override IS NULL "
        f"AND typeof({prefix}.created_ns)='integer' "
        f"AND {prefix}.upload_status='local_manifest' AND {prefix}.minio_key=''"
    )


def install(db):
    if db.in_transaction or db.execute("SELECT count(*) FROM compact_context_refs").fetchone() != (0,):
        raise ValueError("the witness requires an empty synthetic reference ledger")
    # These views are command ports for the three triggers. They share the
    # same append/erase implementation for inserts, updates and deletes.
    standard = is_standard("NEW")
    previous_standard = is_standard("p")
    changed = " OR ".join(
        f"typeof(OLD.{c})<>typeof(NEW.{c}) OR OLD.{c} IS NOT NEW.{c} COLLATE BINARY"
        for c in REFERENCE_COLUMNS
    )
    db.executescript(f"""
        BEGIN IMMEDIATE;
        {RANGE_SCHEMA}
        CREATE TABLE probe_literals AS SELECT {COLUMNS} FROM compact_context_refs WHERE 0;
        CREATE UNIQUE INDEX probe_literals_id ON probe_literals(id);
        CREATE VIEW probe_put AS SELECT {COLUMNS} FROM probe_literals WHERE 0;
        CREATE VIEW probe_erase AS SELECT id FROM probe_literals WHERE 0;

        CREATE TRIGGER probe_put_member INSTEAD OF INSERT ON probe_put BEGIN
            SELECT CASE WHEN EXISTS(SELECT 1 FROM probe_literals WHERE id=NEW.id)
                OR EXISTS(SELECT 1 FROM probe_owner_ranges WHERE {CONTAINS_NEW})
                THEN RAISE(ABORT,'range witness duplicate member') END;
            UPDATE probe_owner_ranges SET member_count=member_count+1
                WHERE first_ref_id={PREVIOUS} AND {standard} AND member_count<256
                AND NEW.id-first_ref_id=member_count
                AND NEW.candidate_key-first_candidate_key=member_count
                AND fact_key=NEW.fact_key AND source_identity=NEW.source_identity AND created_ns=NEW.created_ns;
            INSERT INTO probe_owner_ranges(first_ref_id,first_candidate_key,member_count,fact_key,source_identity,created_ns)
                SELECT p.id,p.candidate_key,2,p.fact_key,p.source_identity,p.created_ns
                FROM probe_literals p WHERE p.id=NEW.id-1 AND {standard} AND {previous_standard}
                AND NEW.candidate_key-p.candidate_key=1
                AND p.fact_key=NEW.fact_key AND p.source_identity=NEW.source_identity AND p.created_ns=NEW.created_ns;
            DELETE FROM probe_literals WHERE id=NEW.id-1
                AND EXISTS(SELECT 1 FROM probe_owner_ranges WHERE first_ref_id=NEW.id-1 AND member_count=2);
            INSERT INTO probe_literals({COLUMNS}) SELECT {NEW_FIELDS}
                WHERE NOT EXISTS(SELECT 1 FROM probe_owner_ranges WHERE {CONTAINS_NEW});
        END;

        CREATE TRIGGER probe_erase_member INSTEAD OF INSERT ON probe_erase BEGIN
            SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM probe_literals WHERE id=NEW.id)
                AND NOT EXISTS(SELECT 1 FROM probe_owner_ranges WHERE {CONTAINS_NEW})
                THEN RAISE(ABORT,'range witness missing member') END;
            DELETE FROM probe_literals WHERE id=NEW.id;
            -- Materialize the right fragment from the original range before
            -- shrinking its left side. Single surviving members stay literal.
            INSERT INTO probe_owner_ranges(first_ref_id,first_candidate_key,member_count,fact_key,source_identity,created_ns)
                SELECT NEW.id+1,first_candidate_key+(NEW.id-first_ref_id)+1,
                       member_count-(NEW.id-first_ref_id)-1,fact_key,source_identity,created_ns
                FROM probe_owner_ranges WHERE {CONTAINS_NEW} AND member_count-(NEW.id-first_ref_id)>2;
            INSERT INTO probe_literals({COLUMNS})
                SELECT NEW.id+1,first_candidate_key+(NEW.id-first_ref_id)+1,fact_key,source_identity,
                       NULL,NULL,created_ns,'local_manifest',''
                FROM probe_owner_ranges WHERE {CONTAINS_NEW} AND member_count-(NEW.id-first_ref_id)=2;
            INSERT INTO probe_literals({COLUMNS})
                SELECT first_ref_id,first_candidate_key,fact_key,source_identity,NULL,NULL,created_ns,'local_manifest',''
                FROM probe_owner_ranges WHERE {CONTAINS_NEW} AND NEW.id-first_ref_id=1;
            DELETE FROM probe_owner_ranges WHERE {CONTAINS_NEW} AND NEW.id-first_ref_id<2;
            UPDATE probe_owner_ranges SET member_count=NEW.id-first_ref_id
                WHERE {CONTAINS_NEW} AND NEW.id-first_ref_id>=2;
        END;

        CREATE TRIGGER probe_after_insert AFTER INSERT ON compact_context_refs BEGIN
            INSERT INTO probe_put({COLUMNS}) VALUES({NEW_FIELDS});
        END;
        CREATE TRIGGER probe_after_update AFTER UPDATE ON compact_context_refs WHEN {changed} BEGIN
            INSERT INTO probe_erase(id) VALUES(OLD.id);
            INSERT INTO probe_put({COLUMNS}) VALUES({NEW_FIELDS});
        END;
        CREATE TRIGGER probe_after_delete AFTER DELETE ON compact_context_refs BEGIN
            INSERT INTO probe_erase(id) VALUES(OLD.id);
        END;
        COMMIT;
    """)


def logical_rows(db):
    segments = db.execute(f"""
        SELECT {COLUMNS},1 FROM probe_literals
        UNION ALL
        SELECT first_ref_id,first_candidate_key,fact_key,source_identity,NULL,NULL,created_ns,
               'local_manifest','',member_count FROM probe_owner_ranges ORDER BY 1
    """)
    previous = None
    for id_, owner, *values, width in segments:
        if previous is not None and id_ <= previous:
            raise ValueError("overlapping range or duplicate literal")
        previous = id_ + width - 1
        for offset in range(width):
            yield (id_ + offset, owner + offset, *values)


def assert_matches_writer(db):
    from itertools import zip_longest
    sentinel = object()
    for n, (original, copy) in enumerate(zip_longest(
            db.execute(f"SELECT {COLUMNS} FROM compact_context_refs ORDER BY id"), logical_rows(db),
            fillvalue=sentinel)):
        if original != copy or tuple(map(type, original)) != tuple(map(type, copy)):
            raise ValueError(f"reference mismatch at ordered position {n + 1}")
