#!/usr/bin/env python3
"""Render the shared operation corpus; fixture commands are never executed."""
import argparse
import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
source=root.parent/'edr-backend/platform/config/p0_operation_vectors.json'
out=root/'src/preprocess/p0_operation_vectors.inc'
parser=argparse.ArgumentParser()
parser.add_argument("--source",type=Path,default=source)
parser.add_argument("--out",type=Path,default=out)
parser.add_argument("--retired-source",type=Path,default=source.with_name("p0_retired_purpose_vectors.json"))
parser.add_argument("--retired-out",type=Path,default=root/"src/preprocess/p0_retired_purpose_vectors.inc")
parser.add_argument("--check",action="store_true")
args=parser.parse_args();source=args.source;out=args.out
d=json.loads(source.read_text())
lines=['/* Generated from canonical p0_operation_vectors.json; matcher replay only. */']
for c in d['cases']:
 e=c['event'];strings=[c['id'],c['rule_id'],e['event_type'],e['process_name'],e['process_path'],e['cmdline'],e.get('file_path',''),e.get('dest_ip','')]
 lines.append('{'+','.join(json.dumps(x,ensure_ascii=True) for x in strings)+f',{e.get("dest_port",0)},{1 if c["expect"] else 0}'+'},')
rendered='\n'.join(lines)+'\n'
if args.check:
 if not out.is_file() or out.read_text()!=rendered:raise SystemExit("operation corpus generated output differs")
else:
 out.parent.mkdir(parents=True,exist_ok=True);out.write_text(rendered)

retired=json.loads(args.retired_source.read_text())
rows=['/* Generated from canonical p0_retired_purpose_vectors.json. */']
for c in retired['cases']:
 rule=json.dumps(c['rule'],ensure_ascii=True,separators=(',',':'))
 rows.append('{'+json.dumps(c['id'])+','+str(c['ir_schema_version'])+','+str(int(c['retired']))+','+json.dumps(rule)+'},')
rendered='\n'.join(rows)+'\n'
if args.check:
 if not args.retired_out.is_file() or args.retired_out.read_text()!=rendered:raise SystemExit("retired purpose corpus differs")
else:
 args.retired_out.parent.mkdir(parents=True,exist_ok=True);args.retired_out.write_text(rendered)
