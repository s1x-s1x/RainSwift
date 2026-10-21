#!/usr/bin/env python3
"""Replay all three complete SM3-128-24 signatures through a chosen new library.

This is correctness acceptance, not a formal signing benchmark. Each attempted
signature is reserved and finalized in a run-local ledger. The published seeded
fixture keys are experimental; this ledger does not reconcile all historical
copies. No output is overwritten, no signatures are generated merely for timing.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import time

from native import NativeSlhDsa
from signing_budget import SigningBudget
from bench_verify_optimization import source_hashes, canonical

ROOT=Path(__file__).resolve().parents[1]
INPUT=ROOT/'reference/evidence/python-sm3-128-24.jsonl'

def sha(data):return hashlib.sha256(data).hexdigest()
def file_sha(path):return sha(path.read_bytes())

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--build-manifest',type=Path,required=True,
                        help='prepared.json from a matching six-way source-bound build')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--threads',type=int,default=8)
    args=parser.parse_args()
    if not 1<=args.threads<=64:parser.error('threads must be 1..64')
    library=args.library.resolve();build_manifest=args.build_manifest.resolve()
    build_bytes=build_manifest.read_bytes();build_hash=sha(build_bytes)
    built=json.loads(build_bytes)
    lib_hash=file_sha(library)
    if built['status']!='prepared-not-timed' or built['source_sha256']!=source_hashes():
        raise ValueError('build manifest is not accepted or does not match current compilation sources')
    if built['source_manifest_sha256']!=sha(canonical(built['source_sha256']).encode()):
        raise ValueError('build source manifest digest differs')
    variants=[v for v in built['variants'] if Path(v['library']).resolve()==library and v['library_sha256']==lib_hash]
    if len(variants)!=1:raise ValueError('library path/digest does not match exactly one prepared variant')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    ledger=SigningBudget(out/'budget.sqlite')
    input_bytes=INPUT.read_bytes();input_hash=sha(input_bytes)
    inputs=[json.loads(line) for line in input_bytes.decode('utf-8').splitlines() if line.strip()]
    if len(inputs)!=3 or any(r['pid']!=3 for r in inputs):raise ValueError('expected three preserved pid3 inputs')
    names=['c/Makefile',*[p.relative_to(ROOT).as_posix() for p in (ROOT/'c/src').iterdir() if p.is_file()],
           'c/include/slhdsa_sm3.h','tools/native.py','tools/signing_budget.py',Path(__file__).relative_to(ROOT).as_posix()]
    def all_sources():return {**source_hashes(),**{n:file_sha(ROOT/n) for n in names}}
    before=all_sources()
    if any(before.get(n)!=digest for n,digest in built['source_sha256'].items()):
        raise ValueError('compilation source changed after build preflight')
    manifest={'scope':__doc__,'command':sys.argv,'started_at_utc':datetime.now(timezone.utc).isoformat(),
              'library_sha256':lib_hash,'input_sha256':input_hash,'sources_sha256':before,
              'build_manifest_sha256':build_hash,'accepted_build_variant':variants[0],
              'threads':args.threads,'backend':2,'verify_after_sign_backend':1,'rows':[]}
    try:
        with (out/'results.jsonl').open('x',encoding='utf-8') as stream:
            for source in inputs:
                mp,sk,pk,rnd,expected=(bytes.fromhex(source[n]) for n in ('mp','sk','pk','opt_rand','sig'))
                operation_id='complete-signature-replay:'+source['case_id']
                receipt=ledger.reserve('SLH-DSA-SM3-128-24',pk,mp,
                                       operation_id=operation_id,case_identity=source['case_id'])
                row={'case_id':source['case_id'],'receipt':receipt,'message_sha256':sha(mp),
                     'public_key_sha256':sha(pk),'expected_signature_sha256':sha(expected)}
                print(json.dumps({'phase':'signing','case_id':source['case_id'],'threads':args.threads}),flush=True)
                begin=time.monotonic();signature=None
                try:
                    with NativeSlhDsa(3,threads=args.threads,flags=2|0x100,library=library) as native:
                        signature=native.sign_internal(mp,sk,rnd)
                    with NativeSlhDsa(3,threads=1,flags=1,library=library) as ref:
                        accepted=ref.verify_internal(mp,signature,pk)
                    row.update({'signature_equal':signature==expected,'ref_accepted':accepted,
                                'actual_signature_sha256':sha(signature),'passed':signature==expected and accepted})
                except BaseException as error:
                    row.update({'passed':False,'error':repr(error)})
                finally:
                    ledger.finish(receipt,signature)
                row['diagnostic_duration_seconds']=time.monotonic()-begin
                row['receipt_evidence']=ledger.validate_receipt(
                    receipt,algorithm='SLH-DSA-SM3-128-24',public_key=pk,message=mp,
                    signature=signature,statuses=('committed','failed'),
                    operation_id=operation_id,case_identity=source['case_id'])
                stream.write(json.dumps(row,sort_keys=True)+'\n');stream.flush()
                manifest['rows'].append(row)
                print(json.dumps(row,sort_keys=True),flush=True)
                if not row['passed']:raise RuntimeError('complete signature replay failed')
        manifest['ledger_reconciliation']=ledger.reconcile();manifest['ledger_status']=ledger.status()
        manifest['sources_unchanged']=before==all_sources()
        manifest['library_unchanged']=lib_hash==file_sha(library);manifest['input_unchanged']=input_hash==file_sha(INPUT)
        manifest['build_manifest_unchanged']=build_hash==file_sha(build_manifest)
        manifest['passed']=len(manifest['rows'])==3 and all(r['passed'] for r in manifest['rows']) and all(
            manifest[n] for n in ('sources_unchanged','library_unchanged','input_unchanged','build_manifest_unchanged'))
    except BaseException as error:
        manifest['passed']=False;manifest['error']=repr(error);raise
    finally:
        manifest['finished_at_utc']=datetime.now(timezone.utc).isoformat()
        (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if not manifest['passed']:raise RuntimeError('source or input changed')

if __name__=='__main__':main()
