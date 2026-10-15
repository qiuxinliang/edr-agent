#!/usr/bin/env python3
"""Keep startup physical-growth costing tied to actual CREATE INDEX owners."""
import pathlib
import re

root = pathlib.Path(__file__).resolve().parents[1]
cache = (root / "src/storage/local_evidence_cache.c").read_text()
context = (root / "src/storage/evidence_context_store.c").read_text()
declarations = re.compile(
    r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(IF NOT EXISTS\s+)?(\w+)\s+ON\s+(\w+)")


def declared(source, context_owner=False):
    # Adjacent C string literals may split an index name from its ON clause.
    source = re.sub(r'"\s*"', "", source)
    return {(name, table, (1 if optional else 2) if context_owner else 0)
            for optional, name, table in declarations.findall(source)}


block = cache.split("startup_index_cost_manifest[] = {", 1)[1].split("};", 1)[0]
entries = re.findall(r'\{"(\w+)",\s*"(\w+)",\s*(\d+)\}', block)
actual = {(name, table, int(layout)) for name, table, layout in entries}
expected = declared(cache) | declared(context, True)
assert len(actual) == len(entries), "duplicate startup index cost entry"
assert actual == expected, (
    f"Startup cost manifest differs from real CREATE INDEX declarations: "
    f"uncosted={sorted(expected - actual)}, stale={sorted(actual - expected)}")
print(f"evidence startup index cost manifest: {len(actual)} real declarations covered")
