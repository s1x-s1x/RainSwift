#!/usr/bin/env python3
"""Read-only audit of local lifecycle evidence; no native loading.

SQLite immutable is for the closed/checkpointed evidence snapshot only. The
live ledger must not have WAL/SHM/journal files when this audit starts.
--allow-incomplete audits only a completed phase prefix of a failed campaign.
It preserves failed-phase accounting, without accepting its timings as results.
"""
from __future__ import annotations
import argparse
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import sqlite3
import statistics

VARIANTS=['wots0-fors0','wots2-fors1']
EXPECTED={'keygen':(5,1,0),'cache_build':(5,1,0),'cache_load':(100,1,3),
          'sign_uncached':(5,1,0),'sign_cached':(30,1,0),
          'sign_cached_selfcheck':(5,1,0),'verify':(100,100,3)}

def sha(data):return hashlib.sha256(data).hexdigest()
def digest(path):return sha(path.read_bytes())
def read(path):return json.loads(path.read_bytes())
def require(value,message):
    if not value:raise ValueError(message)
def statistics_record(values):
    q1,_,q3=statistics.quantiles(values,n=4,method='inclusive')
    return {'n':len(values),'median':statistics.median(values),'q1':q1,'q3':q3,'iqr':q3-q1,'min':min(values),'max':max(values)}
def same_stats(actual,expected):
    return set(actual)==set(expected) and all(math.isclose(actual[k],expected[k],rel_tol=1e-12,abs_tol=1e-12) for k in expected)

def require_closed(database):
    require(all(not Path(str(database)+suffix).exists() for suffix in ('-wal','-shm','-journal')),
            'ledger not checkpointed/closed')

def check_environment(record,phase,completed):
    stages=('environment_before','environment_after') if completed else ('environment_before',)
    for stage in stages:
        require(record[stage]['affinity']==phase['affinity'],'environment affinity differs')
        omp=record[stage]['openmp']
        require(omp['OMP_NUM_THREADS']==str(phase['threads']) and omp['OMP_DYNAMIC']=='FALSE','OpenMP policy differs')
        require('OMP_THREAD_LIMIT' not in omp and 'GOMP_CPU_AFFINITY' not in omp,'inherited OpenMP constraint')
    if completed:
        for field in ('host','platform','python','governor','turbo','clocksource','clock','openmp','affinity'):
            require(record['environment_before'][field]==record['environment_after'][field],
                    'environment policy changed: '+field)

def audit_ledger(database,signed,pk,mp,expected_signature):
    """Reconcile every charge, including committed outputs from failed rows."""
    require_closed(database);before=digest(database)
    require(len({r['operation_id'] for r in signed})==len(signed) and
            len({r['receipt'] for r in signed})==len(signed),'signing reuse/count differs')
    db=sqlite3.connect(database.as_uri()+'?mode=ro&immutable=1',uri=True)
    statuses=Counter()
    try:
        uuid=db.execute("SELECT value FROM ledger_metadata WHERE name='ledger_uuid'").fetchone()[0]
        require(db.execute('SELECT COUNT(*) FROM reservations').fetchone()[0]==len(signed),
                'ledger reservation count differs; charge has no raw row')
        keys=db.execute('SELECT key_id,algorithm,public_key,limit_text,used_text FROM keys').fetchall()
        require(len(keys)==(1 if signed else 0),'unexpected benchmark keys')
        if signed:
            key_id,algorithm,public,limit_text,used_text=keys[0]
            require(key_id==sha(b'a15:slh:pid:3\0'+pk) and algorithm=='slh-dsa-sm3-128-24' and
                    public==pk and int(limit_text)==1<<24 and int(used_text)==len(signed),'key accounting differs')
            reservations=db.execute('SELECT ordinal_text,receipt FROM reservations WHERE key_id=?',(key_id,)).fetchall()
            require(sorted(int(r[0]) for r in reservations)==list(range(1,len(signed)+1)),'signing ordinal gap')
            accounting=db.execute('SELECT used_text,last_receipt FROM accounting WHERE key_id=?',(key_id,)).fetchone()
            require(int(accounting[0])==len(signed) and accounting[1]==max(reservations,key=lambda r:int(r[0]))[1],
                    'ledger accounting differs')
            require(db.execute('SELECT COUNT(*) FROM accounting').fetchone()[0]==1,'extra ledger accounting')
        else:
            require(db.execute('SELECT COUNT(*) FROM accounting').fetchone()[0]==0,'unexpected ledger accounting')
        for row in signed:
            receipt=row['receipt_evidence']
            candidate=row.get('candidate_signature_sha256',row.get('result_signature_sha256'))
            persisted=receipt['signature_sha256']
            actual=db.execute('SELECT status,signature_sha256,message_sha256,operation_id,case_identity FROM reservations WHERE receipt=?',
                              (row['receipt'],)).fetchone()
            require(actual is not None,'receipt absent from ledger')
            status=actual[0];statuses[status]+=1
            require(status in ('committed','failed','reserved'),'unknown receipt status')
            require(actual[1:]==(persisted,sha(mp),row['operation_id'],row['phase']+':'+row['variant']),
                    'raw row/receipt differs')
            require((status=='committed')==(persisted is not None),'receipt output/status differs')
            require(row.get('receipt_persisted_signature_sha256',persisted)==persisted,'persisted receipt digest differs')
            if status=='committed':require(persisted==candidate,'committed output differs from candidate')
            if status=='reserved':require(bool(row.get('finalization_error')),'reserved receipt lacks recorded finalization error')
            if row['passed']:
                require(status=='committed' and candidate==sha(expected_signature),'successful sign/oracle receipt differs')
            require(receipt['ledger_uuid']==uuid and receipt['key_id']==key_id and
                    receipt['algorithm']==algorithm and receipt['public_key_sha256']==sha(pk) and
                    receipt['message_sha256']==sha(mp) and receipt['operation_id']==row['operation_id'] and
                    receipt['case_identity']==row['phase']+':'+row['variant'] and receipt['receipt']==row['receipt'] and
                    receipt['status']==status and receipt['signature_sha256']==persisted,'receipt identity differs')
    finally:db.close()
    require_closed(database);require(digest(database)==before,'read-only audit changed ledger')
    return {'database_sha256':before,'signatures_charged':len(signed),'receipt_status_counts':dict(statuses),
            'ledger_unchanged':True,'sqlite_mode':'ro&immutable=1'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign',type=Path,required=True);parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--build-manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--allow-incomplete',action='store_true',
                        help='accept only the audited completed prefix of a failed campaign, never full completion')
    parser.add_argument('--library-root',type=Path,
                        help='resolve preserved libraries at ROOT/VARIANT/libslhdsa_sm3.so without rewriting manifests')
    args=parser.parse_args();root=args.campaign.resolve();source=args.source_root.resolve()
    watched={}
    def checked_digest(path):
        path=path.resolve();value=digest(path)
        require(watched.get(path,value)==value,'input changed during audit: '+str(path))
        watched[path]=value;return value
    def checked_read(path):
        path=path.resolve();data=path.read_bytes();value=sha(data)
        require(watched.get(path,value)==value,'input changed during audit: '+str(path))
        watched[path]=value;return json.loads(data)
    campaign=checked_read(root/'campaign.json');plan=checked_read(root/'plan.json');build=checked_read(args.build_manifest)
    completed_campaign=campaign['status']=='passed-local-lifecycle-subset'
    require(completed_campaign or (args.allow_incomplete and campaign['status']=='failed'),'campaign incomplete/failed')
    require(campaign['plan_sha256']==checked_digest(root/'plan.json'),'plan hash drift')
    if completed_campaign:
        require(campaign['plan_unchanged'],'campaign plan drift')
        require(campaign['sources_unchanged'],'campaign source drift')
    else:
        require(bool(campaign.get('error')),'failed campaign has no recorded error')
    require(plan['build_manifest_sha256']==checked_digest(args.build_manifest),'build manifest hash drift')
    require(plan['pid']==3 and plan['signatures_planned']==80 and plan['counters']==0 and plan['seed']==20261004,'campaign scope differs')
    for name,value in plan['source_sha256'].items():require(checked_digest(source/name)==value,'frozen source differs: '+name)
    require(all(plan['source_sha256'].get(n)==v for n,v in build['source_sha256'].items()),'accepted compilation sources differ')
    input_bytes=(source/'reference/evidence/python-sm3-128-24.jsonl').read_bytes()
    watched[(source/'reference/evidence/python-sm3-128-24.jsonl').resolve()]=sha(input_bytes)
    require(sha(input_bytes)==plan['input_sha256'],'input hash drift')
    oracle=next(json.loads(row) for row in input_bytes.decode().splitlines() if json.loads(row)['case_id']==plan['fixture_case_id'])
    pk=bytes.fromhex(oracle['pk']);mp=bytes.fromhex(oracle['mp']);expected_signature=bytes.fromhex(oracle['sig'])
    variants={v['name']:v for v in plan['variants']}
    require(set(variants)==set(VARIANTS) and len(plan['variants'])==len(VARIANTS),'variant selection differs')
    library_resolution=[]
    for variant in variants.values():
        library=(args.library_root/variant['name']/'libslhdsa_sm3.so') if args.library_root else Path(variant['library'])
        require(variant in build['variants'] and checked_digest(library)==variant['library_sha256'],'accepted library differs')
        library_resolution.append({'variant':variant['name'],'manifest_path':variant['library'],
                                   'audited_path':str(library.resolve()),'sha256':variant['library_sha256']})
    all_rows=[];completed_rows=[];table=[];case_results=[];failed_phase=None
    require([p['name'] for p in plan['phases']]==list(EXPECTED),'phase set/order differs')
    steps=campaign['steps'];attempted=[s['phase'] for s in steps]
    require(attempted==list(EXPECTED)[:len(steps)] and len(set(attempted))==len(steps),'campaign execution is not a phase prefix')
    require(len(steps)==len(EXPECTED) if completed_campaign else 1<=len(steps)<=len(EXPECTED),'campaign step count differs')
    require(all(s.get('returncode')==0 for s in (steps if completed_campaign else steps[:-1])),'completed prefix contains failed step')
    if not completed_campaign:
        terminal=steps[-1]
        require((terminal.get('returncode') not in (None,0)) or
                (terminal.get('status')=='timeout' and bool(terminal.get('error'))),
                'failed campaign has no failed terminal step')
    for phase in plan['phases']:
        name=phase['name'];samples,batch,warmups=EXPECTED[name]
        require((phase['samples'],phase['batch'],phase['warmup_batches'])==(samples,batch,warmups),'phase sample plan differs')
        selected=phase['affinity']['physical_cores'];cpus=phase['affinity']['cpus']
        require(len(selected)==len(cpus)==phase['threads'] and len({(p['socket'],p['core']) for p in selected})==len(selected),'physical affinity differs')
        require(phase['threads']==(1 if name=='verify' else 8),'phase thread scope differs')
        if name not in attempted:
            require(not (root/name).exists() and not (root/(name+'.log')).exists(),'unattempted phase has evidence')
            continue
        completed=completed_campaign or name!=attempted[-1]
        record=checked_read(root/name/'manifest.json')
        require(record['status']==('passed-local-subset' if completed else 'failed') and record['phase']==phase,'phase status/scope differs')
        require(record['self_verify_after_sign']==(name=='sign_cached_selfcheck'),'selfverify scope differs')
        require(record['plan_sha256']==campaign['plan_sha256'] and record['source_sha256']==plan['source_sha256'],'phase source/plan differs')
        require(record['build_manifest_sha256']==plan['build_manifest_sha256'] and record['input_sha256']==plan['input_sha256'],'phase build/input differs')
        require(record['fixture_case_id']==plan['fixture_case_id'] and record['variants']==plan['variants'],'phase fixture/variants differ')
        closing_fields=('sources_unchanged','build_unchanged','input_unchanged','libraries_unchanged','cache_inputs_unchanged','plan_unchanged')
        for field in closing_fields:
            if completed or field in record:require(record[field],name+': '+field+' failed')
        raw=root/name/'timing.jsonl';require(checked_digest(raw)==record['raw_sha256'],'phase raw hash differs')
        rows=[json.loads(line) for line in raw.read_text().splitlines()]
        require(len(rows)==record['rows'] and len(rows)<=2*(samples+warmups),'phase row count differs')
        if completed:require(len(rows)==2*(samples+warmups),'completed phase row count differs')
        keyed={(r['index'],r['variant']):r for r in rows}
        order=[];rng=random.Random(plan['seed'])
        for index in range(-warmups,samples):
            shuffled=list(VARIANTS);rng.shuffle(shuffled);order.extend((index,v) for v in shuffled)
        require(len(keyed)==len(rows) and [(r['index'],r['variant']) for r in rows]==order[:len(rows)],'missing/repeated/reordered phase sample')
        for row in rows:
            require(row['phase']==name and row['operation_id']==f"{plan['campaign_id']}:{name}:{row['index']}:{row['variant']}",'row operation identity differs')
            require((row['receipt'] is not None)==name.startswith('sign_'),'receipt scope differs')
            if row['passed'] is True:
                require(row['native_returncode']==0 and row['timed']==(row['index']>=0),'timing scope differs')
                require(row['batch']==batch and row['ns_per_call']==row['elapsed_ns']/batch and row['elapsed_ns']>0,'call duration scope differs')
                require(row['library_sha256']==variants[row['variant']]['library_sha256'],'row library differs')
                if row['receipt'] is not None:require(row['result_signature_sha256']==sha(expected_signature),'sign/oracle hash differs')
            else:
                require(not completed and row['passed'] is False and row is rows[-1] and
                        bool(row.get('error') or row.get('finalization_error') or row.get('receipt_validation_error')),
                        'invalid nonterminal/completed failure row')
        require([s['variant'] for s in record['setup']]==(VARIANTS if name in ('cache_load','sign_cached','sign_cached_selfcheck') else []),
                'cache setup variants differ')
        for setup in record['setup']:
            require(setup['variant'] in VARIANTS,'cache variant differs')
            cache=root/name/(setup['variant']+'.cache')
            require(cache.stat().st_size==setup['cache_file_bytes']==16480 and checked_digest(cache)==setup['cache_sha256'],'cache input changed')
            if name=='cache_load':require(checked_digest(root/name/(setup['variant']+'-roundtrip.cache'))==setup['cache_sha256'],'cache roundtrip differs')
        check_environment(record,phase,completed)
        step=next(s for s in steps if s['phase']==name)
        require(checked_digest(root/(name+'.log'))==step['log_sha256'],'phase execution log differs')
        command=step['command']
        require(command[command.index('--worker')+1]==name and
                command[command.index('--plan-sha256')+1]==campaign['plan_sha256'],'phase execution command differs')
        all_rows.extend(rows)
        if not completed:
            require(bool(record.get('error')),'failed phase has no recorded error')
            failed_phase={'phase':name,'status':record['status'],'error':record['error'],'returncode':step.get('returncode'),
                          'execution_timeout':step.get('status')=='timeout',
                          'raw_sha256':checked_digest(raw),'manifest_sha256':checked_digest(root/name/'manifest.json'),
                          'log_sha256':step['log_sha256'],'raw_rows':len(rows),
                          'passed_rows_excluded_from_performance':sum(r['passed'] is True for r in rows),
                          'failed_rows':[r for r in rows if r['passed'] is False],
                          'failed_row_candidate_hash_matches_oracle':[r.get('candidate_signature_sha256',r.get('result_signature_sha256'))==sha(expected_signature)
                                                                     for r in rows if r['passed'] is False],
                          'signatures_charged':sum(r['receipt'] is not None for r in rows),
                          'missing_closing_observations':[f for f in (*closing_fields,'environment_after','memory_peak_end') if f not in record],
                          'performance_accepted':False}
            continue
        completed_rows.extend(rows)
        for variant in VARIANTS:
            computed=statistics_record([keyed[i,variant]['ns_per_call'] for i in range(samples)])
            require(same_stats(record['latency_ns_per_call'][variant],computed),'latency summary differs')
            table.append({'phase':name,'variant':variant,'observations':samples,'calls_per_observation':batch,
                          'median_ms':computed['median']/1e6,'q1_ms':computed['q1']/1e6,'q3_ms':computed['q3']/1e6,
                          'peak_paired_process_kib':record['memory_peak_end']['process_ru_maxrss_kib']})
        computed=statistics_record([keyed[i,VARIANTS[0]]['ns_per_call']/keyed[i,VARIANTS[1]]['ns_per_call'] for i in range(samples)])
        require(same_stats(record['paired_ratio'],computed),'paired ratio summary differs')
        case_results.append({'phase':name,'statistics_recomputed':True,'paired_ratio':computed,
                     'rows':len(rows),'measured_calls':sum(r['batch'] for r in rows if r['timed'])})
    signed=[r for r in all_rows if r['receipt'] is not None]
    if completed_campaign:require(len(signed)==80,'completed signing count differs')
    else:require(len(signed)<=80 and failed_phase is not None and bool(case_results),'no completed prefix to audit')
    ledger=audit_ledger(root/'budget.sqlite',signed,pk,mp,expected_signature)
    watched[(root/'budget.sqlite').resolve()]=ledger['database_sha256']
    for path,value in watched.items():require(digest(path)==value,'input changed during audit: '+str(path))
    require_closed(root/'budget.sqlite')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    with (out/'lifecycle.csv').open('x',encoding='utf-8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(table[0]));writer.writeheader();writer.writerows(table)
    result={'status':'PASS' if completed_campaign else 'PASS_COMPLETED_PREFIX_ONLY',
            'overall_campaign_status':campaign['status'],'complete_lifecycle':completed_campaign,
            'native_code_executed':False,'measured_calls':sum(r['batch'] for r in completed_rows if r['timed']),
            'raw_rows':len(all_rows),'completed_prefix_raw_rows':len(completed_rows),'signatures_charged':len(signed),
            'plan_sha256':watched[(root/'plan.json').resolve()],'campaign_sha256':watched[(root/'campaign.json').resolve()],
            'build_manifest_sha256':watched[args.build_manifest.resolve()],'ledger':ledger,
            'input_files_rechecked_at_end':len(watched),'inputs_unchanged_during_audit':True,
            'library_resolution_route':'explicit preserved library root' if args.library_root else 'original manifest paths',
            'library_resolution':library_resolution,'phases':case_results,'failed_phase':failed_phase,
            'unattempted_phases':list(EXPECTED)[len(steps):],
            'campaign_missing_closing_observations':[f for f in ('sources_unchanged','plan_unchanged') if f not in campaign],
            'scope':'limited local internal ABI lifecycle; one fixed fixture; inclusive paired-process peak memory'
                    if completed_campaign else 'completed phase prefix only; failed phase timings excluded; all observed signing charges reconciled; lifecycle incomplete'}
    (out/'audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
