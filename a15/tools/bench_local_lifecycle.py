#!/usr/bin/env python3
"""Paired local SM3-128-24 lifecycle measurements on accepted release builds.

This is a new limited local plan, not the canonical R3/R4/R5/GPU campaign.
Each phase runs in its own process; both variants use the same fixture and
physical-core affinity. Only preallocated native calls are timed. Every signing
attempt is charged before computation; REF/oracle checking occurs after timing.
No old output is overwritten. Requires Linux/WSL; production keys are not used.
"""
from __future__ import annotations
import argparse
import ctypes as ct
from datetime import datetime,timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import statistics
import subprocess
import sys
import time
import uuid

from native import NativeSlhDsa,_buffer,_erase
from signing_budget import SigningBudget
from bench_verify_optimization import source_hashes,canonical
from bench_cpu import topology,physical_cpus,openmp_environment,environment,sample_environment
from workload_guard import fully_stopped,performance_exclusive

ROOT=Path(__file__).resolve().parents[1]
PHASES=[('keygen',5,1,0),('cache_build',5,1,0),('cache_load',100,1,3),
        ('sign_uncached',5,1,0),('sign_cached',30,1,0),
        ('sign_cached_selfcheck',5,1,0),('verify',100,100,3)]
VARIANTS=['wots0-fors0','wots2-fors1']

def sha(data):return hashlib.sha256(data).hexdigest()
def digest(path):return sha(path.read_bytes())
def utc():return datetime.now(timezone.utc).isoformat()
def write(path,data):path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def read(path):return json.loads(path.read_bytes())
def sources():
    names=['tools/bench_local_lifecycle.py','tools/bench_cpu.py','tools/signing_budget.py','tools/workload_guard.py']
    return {**source_hashes(),**{name:digest(ROOT/name) for name in names}}
def memory():
    status={}
    for line in Path('/proc/self/status').read_text().splitlines():
        name,_,value=line.partition(':')
        if name in ('VmRSS','VmHWM'):status[name]=value.strip()
    return {'process_ru_maxrss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,**status}
def stats(values):
    q1,_,q3=statistics.quantiles(values,n=4,method='inclusive')
    return {'n':len(values),'median':statistics.median(values),'q1':q1,'q3':q3,'iqr':q3-q1,'min':min(values),'max':max(values)}

def competitors(output):
    """Known native campaigns; no processes are signalled or reconfigured."""
    matches=[]
    scripts={'check_optimization.py','bench_cpu.py','bench_cuda.py','bench_local_lifecycle.py',
             'check_kernel_network.py','bootstrap_local_env.py','measure_cache_storage.py',
             'run_native_stage2.py','check_verify_optimization_signing.py','bench_verify_optimization.py',
             'reproduce_verify_optimization.py','run_stage1.py','reproduce_project.py',
             'generate_reference_vectors.py','run_acceptance.py','check_digest_native.py'}
    for directory in Path('/proc').iterdir():
        if not directory.name.isdecimal():continue
        if fully_stopped(directory):continue
        try:parts=(directory/'cmdline').read_bytes().split(b'\0')
        except (OSError,PermissionError):continue
        text_parts=[part.decode('utf-8',errors='replace') for part in parts if part]
        names={Path(part).name for part in text_parts}
        script=sorted(names&scripts)
        if script and str(output) not in text_parts:
            matches.append({'pid':int(directory.name),'scripts':script})
        elif names and next(iter(text_parts),'').split('/')[-1].startswith('test_'):
            matches.append({'pid':int(directory.name),'program':Path(text_parts[0]).name})
    return matches

def require_quiet(output):
    active=competitors(output)
    if active:raise RuntimeError('overlapping native campaign: '+json.dumps(active))

def settle_signing_attempt(ledger,receipt,signature,pk,mp,operation_id,case_identity,row,operation_error):
    """Keep candidate output separate from the actual durable receipt state."""
    row['candidate_signature_sha256']=sha(signature) if signature is not None else None
    try:
        ledger.finish(receipt,signature)
    except BaseException as error:
        row['finalization_error']=repr(error);row['passed']=False
        if operation_error is not None:operation_error.add_note('budget finalization: '+repr(error))
        else:operation_error=error
    try:
        evidence=ledger.validate_receipt(receipt,public_key=pk,message=mp,
            statuses=('committed','failed','reserved'),operation_id=operation_id,case_identity=case_identity)
        row['receipt_evidence']=evidence
        row['receipt_persisted_signature_sha256']=evidence['signature_sha256']
        candidate=row['candidate_signature_sha256']
        if evidence['status']=='committed' and evidence['signature_sha256']!=candidate:
            raise ValueError('committed receipt differs from candidate output')
        if row['passed'] and (evidence['status']!='committed' or candidate is None):
            raise ValueError('successful signing lacks committed output receipt')
        if evidence['status']=='reserved' and not row.get('finalization_error'):
            raise ValueError('unfinished receipt lacks a finalization failure')
    except BaseException as error:
        row['receipt_validation_error']=repr(error);row['passed']=False
        if operation_error is not None:operation_error.add_note('receipt validation: '+repr(error))
        else:operation_error=error
    if operation_error is not None:
        row['error']=repr(operation_error);row['passed']=False
        row['timed']=False;row['timing_accepted']=False
    return operation_error

def preflight(build_manifest):
    data=build_manifest.read_bytes();built=json.loads(data);current=source_hashes()
    if built['status']!='prepared-not-timed' or built['source_sha256']!=current:
        raise ValueError('accepted preparation sources do not match this workspace')
    if built['source_manifest_sha256']!=sha(canonical(current).encode()):raise ValueError('build source digest differs')
    variants=[]
    for name in VARIANTS:
        candidates=[v for v in built['variants'] if v['name']==name]
        if len(candidates)!=1:raise ValueError('missing/duplicate prepared variant')
        variant=candidates[0];expected=(0,0) if name==VARIANTS[0] else (2,1)
        if (variant['wots_schedule'],variant['fors_verify_x8'])!=expected or variant['counters']!=0:
            raise ValueError('unexpected variant/instrumentation')
        if digest(Path(variant['library']))!=variant['library_sha256']:raise ValueError('accepted library changed')
        variants.append(variant)
    inputs=ROOT/'reference/evidence/python-sm3-128-24.jsonl';input_bytes=inputs.read_bytes()
    if sha(input_bytes)!=built['input_files_sha256'][inputs.relative_to(ROOT).as_posix()]:raise ValueError('accepted fixture input changed')
    fixture=json.loads(input_bytes.decode().splitlines()[0])
    return built,variants,fixture,sha(data),sha(input_bytes)

def worker(args):
    out=args.output.resolve();plan_bytes=(out/'plan.json').read_bytes();plan=json.loads(plan_bytes)
    if sha(plan_bytes)!=args.plan_sha256:raise ValueError('planned bytes changed')
    if plan['source_sha256']!=sources():raise ValueError('planned sources changed')
    built,variants,fixture,build_hash,input_hash=preflight(args.build_manifest.resolve())
    if build_hash!=plan['build_manifest_sha256'] or input_hash!=plan['input_sha256']:raise ValueError('plan preflight differs')
    phase=next(p for p in plan['phases'] if p['name']==args.worker)
    affinity=phase['affinity'];threads=phase['threads']
    cpus=affinity['cpus'];os.sched_setaffinity(0,set(cpus))
    if sorted(os.sched_getaffinity(0))!=sorted(cpus):raise ValueError('affinity differs')
    for name in list(os.environ):
        if name.startswith(('OMP_','GOMP_','KMP_')):os.environ.pop(name)
    os.environ.update(openmp_environment(threads,cpus));require_quiet(out)
    directory=out/args.worker;directory.mkdir(exist_ok=False)
    mp,sk,pk,rnd,expected=(bytes.fromhex(fixture[n]) for n in ('mp','sk','pk','opt_rand','sig'))
    message,secret,public,randomizer=_buffer(mp),_buffer(sk),_buffer(pk),_buffer(rnd)
    sk_seed,sk_prf,pk_seed=(_buffer(bytes.fromhex(fixture[n])) for n in ('sk_seed','sk_prf','pk_seed'))
    output_sig=(ct.c_uint8*len(expected))();output_pk=(ct.c_uint8*32)();output_sk=(ct.c_uint8*64)()
    buffers=[secret,randomizer,sk_seed,sk_prf,output_sig,output_sk]
    ledger=SigningBudget(out/'budget.sqlite')
    rows=[];contexts={};refs={};cache_paths={};setup=[]
    cache_hashes={};start_memory=memory();flags=2|(0x100 if args.worker=='sign_cached_selfcheck' else 0)
    record={'phase':phase,'plan_sha256':args.plan_sha256,'source_sha256':plan['source_sha256'],'build_manifest_sha256':build_hash,
            'input_sha256':input_hash,'fixture_case_id':fixture['case_id'],'variants':variants,
            'self_verify_after_sign':bool(flags&0x100),'started_at_utc':utc(),'status':'running',
            'memory_scope':'paired worker high-water mark through the recorded observation, before final cleanup; includes Python/two libraries/setup/checks/OpenMP',
            'memory_at_start':start_memory,'setup':setup,'rows':0}
    write(directory/'manifest.json',record)
    try:
        for variant in variants:
            name=variant['name'];contexts[name]=NativeSlhDsa(3,threads,flags,variant['library'])
            refs[name]=NativeSlhDsa(3,1,1,variant['library'])
            contexts[name].set_cache_level(12)
            if contexts[name].backend!=2:raise ValueError('backend did not select AVX2')
            if args.worker in ('cache_load','sign_cached','sign_cached_selfcheck'):
                setup_start=time.monotonic();path=directory/(name+'.cache');cache_paths[name]=path
                with NativeSlhDsa(3,threads,2,variant['library']) as builder:
                    builder.cache_build(sk,12);builder.cache_save(path)
                if path.stat().st_size!=16480:raise ValueError('t12 cache file size differs')
                if args.worker.startswith('sign_'):contexts[name].cache_load(path,pk)
                cache_hashes[name]=digest(path)
                setup.append({'variant':name,'cache_sha256':digest(path),'cache_file_bytes':path.stat().st_size,
                              'cache_payload_bytes':16384,'cache_nodes_ram_bytes':32752,
                              'diagnostic_setup_seconds_excluded':time.monotonic()-setup_start})
        record['environment_before']=environment(affinity);record['memory_after_setup']=memory()
        rng=random.Random(plan['seed']);gc.disable()
        with (directory/'timing.jsonl').open('x',encoding='utf-8') as stream:
            for index in range(-phase['warmup_batches'],phase['samples']):
                order=list(variants);rng.shuffle(order)
                for variant in order:
                    require_quiet(out)
                    name=variant['name'];native=contexts[name];receipt=None;signature=None
                    operation_id=f"{plan['campaign_id']}:{args.worker}:{index}:{name}"
                    if args.worker.startswith('sign_'):
                        receipt=ledger.reserve('SLH-DSA-SM3-128-24',pk,mp,
                             operation_id=operation_id,case_identity=args.worker+':'+name)
                    observation=None;rc=None;elapsed=None;operation_error=None;row={}
                    try:
                        observation=sample_environment(cpus);rc=0
                        if args.worker=='keygen':
                            function=native.lib.slh_keygen_internal;arguments=(native.ctx,output_pk,output_sk,sk_seed,sk_prf,pk_seed)
                        elif args.worker=='cache_build':
                            function=native.lib.slh_cache_build;arguments=(native.ctx,secret,12)
                        elif args.worker=='cache_load':
                            function=native.lib.slh_cache_load;arguments=(native.ctx,os.fsencode(cache_paths[name]),public)
                        elif args.worker.startswith('sign_'):
                            function=native.lib.slh_sign_internal_checked;arguments=(native.ctx,output_sig,len(expected),message,len(mp),secret,randomizer)
                        else:
                            function=native.lib.slh_verify_internal;arguments=(native.ctx,output_sig,len(expected),message,len(mp),public)
                            ct.memmove(output_sig,expected,len(expected))
                        begin=time.perf_counter_ns()
                        for _ in range(phase['batch']):rc|=function(*arguments)
                        elapsed=time.perf_counter_ns()-begin
                        if args.worker.startswith('sign_') and rc==0:signature=bytes(output_sig)
                        require_quiet(out)
                        if rc!=0:raise RuntimeError('native call returned '+str(rc))
                        if args.worker=='keygen' and (bytes(output_pk)!=pk or bytes(output_sk)!=sk):raise ValueError('keygen differs from Python oracle')
                        if args.worker.startswith('sign_'):
                            if signature!=expected or not refs[name].verify_internal(mp,signature,pk):raise ValueError('sign/oracle/REF differs')
                        if args.worker=='cache_build':
                            path=directory/(name+f'-sample-{index}.cache');native.cache_save(path)
                            if path.stat().st_size!=16480:raise ValueError('cache bytes differ')
                            with NativeSlhDsa(3,1,1,variant['library']) as check:check.cache_load(path,pk)
                        row={'index':index,'timed':index>=0,'phase':args.worker,'variant':name,'batch':phase['batch'],
                             'elapsed_ns':elapsed,'ns_per_call':elapsed/phase['batch'],'native_returncode':rc,
                             'library_sha256':variant['library_sha256'],'operation_id':operation_id,
                             'result_signature_sha256':sha(signature) if signature is not None else None,
                             'receipt':receipt,'environment_observation':observation,'memory_after_call':memory(),'passed':True}
                    except BaseException as error:
                        operation_error=error
                        row={'index':index,'phase':args.worker,'variant':name,'operation_id':operation_id,
                             'batch':phase['batch'],'library_sha256':variant['library_sha256'],
                             'elapsed_ns':elapsed,'ns_per_call':None,'native_returncode':rc,
                             'environment_observation':observation,
                             'receipt':receipt,'passed':False,'error':repr(error),
                             'candidate_signature_sha256':sha(signature) if signature is not None else None}
                    finally:
                        if receipt is not None:
                            operation_error=settle_signing_attempt(ledger,receipt,signature,pk,mp,
                                operation_id,args.worker+':'+name,row,operation_error)
                    if operation_error is not None:
                        row['timed']=False;row['timing_accepted']=False
                    stream.write(json.dumps(row,sort_keys=True)+'\n');stream.flush();os.fsync(stream.fileno())
                    rows.append(row)
                    if operation_error is not None:raise operation_error
                print(json.dumps({'phase':args.worker,'completed_pairs':index+1,'planned_pairs':phase['samples']}),flush=True)
        record['latency_ns_per_call']={name:stats([r['ns_per_call'] for r in rows if r['timed'] and r['variant']==name]) for name in VARIANTS}
        by_index={(r['index'],r['variant']):r['ns_per_call'] for r in rows if r['timed']}
        record['paired_ratio']=stats([by_index[i,VARIANTS[0]]/by_index[i,VARIANTS[1]] for i in range(phase['samples'])])
        if args.worker=='cache_load':
            for name,native in contexts.items():
                roundtrip=directory/(name+'-roundtrip.cache');native.cache_save(roundtrip)
                if digest(roundtrip)!=cache_hashes[name]:raise ValueError('loaded cache roundtrip differs')
                refs[name].cache_load(roundtrip,pk)
        record['cache_inputs_unchanged']=all(digest(cache_paths[n])==h for n,h in cache_hashes.items())
        record['plan_unchanged']=digest(out/'plan.json')==args.plan_sha256
        record['memory_peak_end']=memory();record['environment_after']=environment(affinity)
        record['sources_unchanged']=plan['source_sha256']==sources()
        record['build_unchanged']=digest(args.build_manifest.resolve())==build_hash
        record['input_unchanged']=digest(ROOT/'reference/evidence/python-sm3-128-24.jsonl')==input_hash
        record['libraries_unchanged']=all(digest(Path(v['library']))==v['library_sha256'] for v in variants)
        if not all(record[n] for n in ('sources_unchanged','build_unchanged','input_unchanged','libraries_unchanged','cache_inputs_unchanged','plan_unchanged')):
            raise ValueError('measurement identity changed')
        record['raw_sha256']=digest(directory/'timing.jsonl');record['rows']=len(rows);record['status']='passed-local-subset'
    except BaseException as error:record['status']='failed';record['error']=repr(error);raise
    finally:
        for context in [*contexts.values(),*refs.values()]:context.close()
        for buffer in buffers:_erase(buffer)
        gc.enable();record['rows']=len(rows)
        if (directory/'timing.jsonl').exists():record['raw_sha256']=digest(directory/'timing.jsonl')
        record['finished_at_utc']=utc();write(directory/'manifest.json',record)

def _campaign(args):
    out=args.output.resolve()
    if not args.prepare_only:require_quiet(out)
    if not args.run_prepared:out.mkdir(parents=True,exist_ok=False)
    built,variants,fixture,build_hash,input_hash=preflight(args.build_manifest.resolve())
    topo,raw=topology();selected=physical_cpus(topo,args.threads)
    affinity={'verified_physical':True,'cpus':[r['cpu'] for r in selected],'physical_cores':selected,
              'nodes':sorted({r['node'] for r in selected if r['node'] is not None}),
              'cross_numa':len({r['node'] for r in selected})>1,'lscpu':raw,'memory_policy':'first touch under affinity; kernel default'}
    plan={'schema':'a15-local-lifecycle-v1','campaign_id':uuid.uuid4().hex,'started_at_utc':utc(),'pid':3,
          'threads':args.threads,'affinity':affinity,'seed':20261004,'source_sha256':sources(),
          'build_manifest_sha256':build_hash,'input_sha256':input_hash,'fixture_case_id':fixture['case_id'],
          'phases':[{'name':name,'samples':n,'batch':batch,'warmup_batches':warmups,
                     'threads':1 if name=='verify' else args.threads,
                     'affinity':{**affinity,'cpus':[selected[0]['cpu']],'physical_cores':[selected[0]]} if name=='verify' else affinity}
                    for name,n,batch,warmups in PHASES],
          'timing_scope':'preencoded internal native ABI call + ctypes loop; explicit phase includes C REF selfcheck; message encoding/allocation/budget/checks/writes/setup excluded',
          'cache_load_scope':'warm OS page cache; repeated transactional loads, no drop_caches or cold-load claim',
          'classification':'limited local lifecycle plan; canonical formal competition matrix incomplete',
          'verify_meaning':'100 measured batches x 100 calls, 100 statistics observations, not 10000 independent messages',
          'signatures_planned':80,'variants':variants,'counters':0,'peak_ram_scope':'paired worker high-water mark at the recorded observation before cleanup, inclusive of Python/setup/checks',
          'clock_policy':'frequency/boost observed, never changed; no hardware core-cycle inference'}
    if args.run_prepared:
        previous=read(out/'prepare.json');plan_bytes=(out/'plan.json').read_bytes();plan=json.loads(plan_bytes)
        if previous['plan_sha256']!=sha(plan_bytes) or plan['source_sha256']!=sources():raise ValueError('prepared source/plan changed')
        if previous['status']!='prepared-no-native-execution' or (out/'campaign.json').exists():raise ValueError('prepared campaign was already started')
        if plan['build_manifest_sha256']!=build_hash or plan['input_sha256']!=input_hash:raise ValueError('prepared build/fixture changed')
    else:write(out/'plan.json',plan)
    record={'status':'running','plan_sha256':digest(out/'plan.json'),'steps':[],
            'workload_guard':getattr(args,'workload_guard',None)}
    if args.prepare_only:
        write(out/'prepare.json',{'status':'prepared-no-native-execution','plan_sha256':record['plan_sha256'],
                                 'known_competing_campaigns':competitors(out),'native_calls':0})
        print(json.dumps({'status':'prepared-no-native-execution','output':str(out)}));return
    write(out/'campaign.json',record)
    env={**os.environ,'PYTHONPYCACHEPREFIX':str(out/'python-cache'),'TMPDIR':str(out/'scratch')}
    (out/'scratch').mkdir()
    try:
        for phase in plan['phases']:
            require_quiet(out)
            if digest(out/'plan.json')!=record['plan_sha256']:raise ValueError('plan changed before phase')
            argv=[sys.executable,str(Path(__file__).resolve()),'--output',str(out),'--build-manifest',str(args.build_manifest.resolve()),
                  '--worker',phase['name'],'--plan-sha256',record['plan_sha256']]
            print(json.dumps({'starting_phase':phase['name'],'samples':phase['samples']}),flush=True)
            with (out/(phase['name']+'.log')).open('x',encoding='utf-8') as log:
                try:result=subprocess.run(argv,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=7200)
                except subprocess.TimeoutExpired as error:
                    record['steps'].append({'phase':phase['name'],'command':argv,'status':'timeout',
                                           'returncode':None,'killed_on_timeout':True,
                                           'error':repr(error),'log_sha256':digest(out/(phase['name']+'.log'))})
                    write(out/'campaign.json',record);raise
            record['steps'].append({'phase':phase['name'],'command':argv,'returncode':result.returncode,
                                    'log_sha256':digest(out/(phase['name']+'.log'))})
            write(out/'campaign.json',record)
            if result.returncode:raise RuntimeError(phase['name']+' failed; no phase restarted')
        record['summary']={p['name']:read(out/p['name']/'manifest.json') for p in plan['phases']}
        ledger=SigningBudget(out/'budget.sqlite');record['ledger_reconciled']=ledger.reconcile();record['key_usage']=ledger.status()
        record['sources_unchanged']=plan['source_sha256']==sources()
        record['plan_unchanged']=digest(out/'plan.json')==record['plan_sha256']
        if not record['sources_unchanged'] or not record['plan_unchanged']:raise ValueError('source/plan changed during campaign')
        record['status']='passed-local-lifecycle-subset'
    except BaseException as error:record['status']='failed';record['error']=repr(error);raise
    finally:record['finished_at_utc']=utc();write(out/'campaign.json',record)

def campaign(args):
    if args.prepare_only:return _campaign(args)
    with performance_exclusive(ROOT,'local-lifecycle') as guard:
        args.workload_guard=guard
        return _campaign(args)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--build-manifest',type=Path,required=True)
    parser.add_argument('--threads',type=int,default=8);parser.add_argument('--worker',choices=[p[0] for p in PHASES])
    parser.add_argument('--plan-sha256',help=argparse.SUPPRESS)
    phase=parser.add_mutually_exclusive_group();phase.add_argument('--prepare-only',action='store_true');phase.add_argument('--run-prepared',action='store_true')
    args=parser.parse_args()
    if not sys.platform.startswith('linux'):parser.error('requires Linux/WSL')
    if args.worker and not args.plan_sha256:parser.error('worker requires frozen plan digest')
    worker(args) if args.worker else campaign(args)

if __name__=='__main__':main()
