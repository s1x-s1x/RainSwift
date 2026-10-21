#!/usr/bin/env python3
"""Fresh-directory reproduction of the verification optimizations.

All generated files stay under --output. Timing, when requested, follows the
native and sanitizer gates and six independent release builds. Historical
evidence is never overwritten. Requires Linux/WSL, GCC, make and Python 3.12.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from bench_verify_optimization import source_hashes

ROOT=Path(__file__).resolve().parents[1]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timing', action='store_true')
    parser.add_argument('--rounds', type=int, default=100)
    parser.add_argument('--batch', type=int, default=8)
    parser.add_argument('--cpu', type=int)
    args=parser.parse_args()
    if not sys.platform.startswith('linux'):
        parser.error('use Linux or WSL')
    if args.rounds<2 or args.batch<1:
        parser.error('rounds >= 2, batch >= 1 required')
    out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    scratch=out/'scratch';scratch.mkdir()
    env={**os.environ,'TMPDIR':str(scratch),'PYTHONPYCACHEPREFIX':str(out/'python-cache')}
    paths=[ROOT/'c/Makefile',*sorted((ROOT/'c/src').glob('*')),
           *sorted((ROOT/'c/include').glob('*')),*sorted((ROOT/'c/tests').glob('*.c')),
           ROOT/'tools/native.py',ROOT/'tools/check_native_guards.py',
           ROOT/'tools/bench_verify_optimization.py',Path(__file__).resolve()]
    paths=[p for p in paths if p.is_file()]
    def all_sources():
        return {**source_hashes(),**{p.relative_to(ROOT).as_posix():digest(p) for p in paths}}
    before=all_sources()
    record={'scope':'CPU verify optimization reproduction; no production signing',
            'started_at_utc':datetime.now(timezone.utc).isoformat(),
            'command':sys.argv,'source_sha256':before,'steps':[]}
    def save():
        (out/'reproduction.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    def run(name, argv, timeout=1800):
        begin=time.monotonic()
        with (out/(name+'.log')).open('x',encoding='utf-8') as log:
            result=subprocess.run(argv,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        row={'name':name,'command':argv,'cwd':str(ROOT),'returncode':result.returncode,
             'diagnostic_duration_seconds':time.monotonic()-begin,'log_sha256':digest(out/(name+'.log'))}
        record['steps'].append(row);save();print(json.dumps(row),flush=True)
        if result.returncode:raise RuntimeError(name+' failed; inspect preserved log')
    save()
    try:
        run('native',['make','-C','c',f'OUT={out}/native-build','COUNTERS=1','-j2',
                      'all','test','review-test','repair-test','avx2-test','wots-test',
                      'verify-scheduling-test','prehash-test','fault-test','guard-test'])
        run('sanitizer',['make','-C','c',f'OUT={out}/sanitizer-build',
                        'CFLAGS=-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer',
                        'COUNTERS=1','verify-scheduling-test'])
        run('prepare',[sys.executable,'tools/bench_verify_optimization.py','--prepare-only',
                       '--output',str(out/'ablation'),'--build-root',str(out/'ablation-builds')])
        if args.timing:
            argv=[sys.executable,'tools/bench_verify_optimization.py','--run-only','--output',
                  str(out/'ablation'),'--rounds',str(args.rounds),'--batch',str(args.batch)]
            if args.cpu is not None:argv+=['--cpu',str(args.cpu)]
            run('timing',argv,timeout=7200)
        record['sources_unchanged']=before==all_sources()
        if not record['sources_unchanged']:raise RuntimeError('source changed during reproduction')
        record['status']='passed-with-local-timing' if args.timing else 'passed-prepared-not-timed'
    except BaseException as error:
        record['status']='failed';record['error']=repr(error);save();raise
    finally:
        record['finished_at_utc']=datetime.now(timezone.utc).isoformat();save()

if __name__=='__main__':
    main()
