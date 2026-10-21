#!/usr/bin/env python3
"""Read-only hash, provenance, statistics and receipt audit; no native loading."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import zipfile
from plot_verify_optimization import checked_data

def sha(data):return hashlib.sha256(data).hexdigest()
def file_sha(path):return sha(path.read_bytes())
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def require(condition,message):
    if not condition:raise ValueError(message)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bundle',type=Path,required=True)
    args=parser.parse_args();root=args.bundle.resolve();manifest=read(root/'manifest.json')
    for name,record in manifest['files'].items():
        path=(root/name).resolve()
        require(root in path.parents,'artifact path escapes bundle')
        require(path.stat().st_size==record['bytes'] and file_sha(path)==record['sha256'],'artifact changed: '+name)
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    require(actual==set(manifest['files'])|{'manifest.json'},'unmanifested/missing bundle files')
    source_manifest=read(root/'source-manifest.json')
    with zipfile.ZipFile(root/manifest['source_archive']) as archive:
        zip_hashes={name:sha(archive.read(name)) for name in archive.namelist()}
        expected={**source_manifest['files_sha256'],**source_manifest['executed_snapshots_sha256']}
        require(zip_hashes==expected,'source archive differs from member manifest')
    def source_present(name,digest):
        return any(value==digest and (member==name or member.endswith('/'+name)) for member,value in zip_hashes.items())
    def check_sources(mapping):
        for name,digest in mapping.items():require(source_present(name,digest),'executed source missing: '+name)
    with zipfile.ZipFile(root/manifest['source_archive']) as archive:
        oracle_bytes=archive.read('reference/evidence/python-sm3-128-24.jsonl')
    for encoded in oracle_bytes.decode('utf-8').splitlines():
        row=json.loads(encoded);check_sources(row['sources_sha256'])
        original=dict(row);expected_hash=original.pop('record_sha256')
        require(sha(json.dumps(original,sort_keys=True,separators=(',',':')).encode())==expected_hash,'oracle record hash differs')
        for field,digest in row['content_sha256'].items():
            require(sha(bytes.fromhex(row[field]))==digest,'oracle content digest differs')
    call_total=0;correctness_total=0;library_total=0
    for directory,builds in [('verify-ablation-r1','ablation-builds-r1'),
                             ('reproduction-r2/ablation','reproduction-r2/ablation-builds'),
                             ('reproduction-r3-final-gates/ablation','reproduction-r3-final-gates/ablation-builds')]:
        phase=root/directory;p=read(phase/'prepared.json');check_sources(p['source_sha256'])
        canonical=json.dumps(p['source_sha256'],sort_keys=True,separators=(',',':'),ensure_ascii=False)
        require(sha(canonical.encode())==p['source_manifest_sha256'],'build source mapping digest differs')
        require(file_sha(phase/'fixtures.json')==p['fixtures_sha256'],'fixtures changed')
        require(file_sha(phase/'correctness.jsonl')==p['correctness_sha256'],'correctness changed')
        checks=[json.loads(x) for x in (phase/'correctness.jsonl').read_text().splitlines()]
        require(len(checks)==p['correctness_rows'],'correctness row count differs')
        require(all(row['pass'] and row['accepted']==row['expected'] for row in checks),'correctness failure')
        correctness_total+=len(checks)
        for name,digest in p['input_files_sha256'].items():require(source_present(name,digest),'input source missing')
        for variant in p['variants']:
            library=root/builds/variant['name']/'libslhdsa_sm3.so'
            require(file_sha(library)==variant['library_sha256'],'built library differs')
            library_total+=1
        if (phase/'summary.json').exists():
            _,record=checked_data(phase)
            require(file_sha(phase/'prepared.json')==read(phase/'summary.json')['prepared_sha256'],'timing prepared record differs')
            call_total+=record['verification_calls']
    for directory in ('reproduction-r2','reproduction-r3-final-gates'):
        record=read(root/directory/'reproduction.json');check_sources(record['source_sha256'])
        require(record['sources_unchanged'] and record['status'].startswith('passed'),'reproduction failed')
        for step in record['steps']:
            log=root/directory/(step['name']+'.log')
            require(step['returncode']==0 and file_sha(log)==step['log_sha256'],'gate/log mismatch')
            if step['name']=='sanitizer':
                require(not re.search(r'runtime error:|ERROR: AddressSanitizer|LeakSanitizer',log.read_text()),'sanitizer diagnostic')
                if directory=='reproduction-r3-final-gates':
                    require(any('-fno-sanitize-recover=undefined' in value for value in step['command']),'fail-fast flag missing')
    signed=0
    for directory in ('full-pid3-replay','full-pid3-replay-r2','full-pid3-replay-r3-bound'):
        record=read(root/directory/'manifest.json')
        if directory=='full-pid3-replay':require(not record['passed'] and len(record['rows'])==1,'preserved failure scope changed')
        else:
            require(record['passed'] and len(record['rows'])==3,'complete signing acceptance failed')
            check_sources(record['sources_sha256'])
            require(record['sources_unchanged'] and record['library_unchanged'] and record['input_unchanged'],'signing drift')
        # The package is a frozen, checkpointed snapshot. Ordinary mode=ro on
        # a WAL database can create -wal/-shm sidecars and mutate its file set.
        connection=sqlite3.connect((root/directory/'budget.sqlite').as_uri()+'?mode=ro&immutable=1',uri=True)
        try:
            uuid=connection.execute("SELECT value FROM ledger_metadata WHERE name='ledger_uuid'").fetchone()[0]
            used=sum(int(row[0]) for row in connection.execute('SELECT used_text FROM keys'))
            require(used==connection.execute('SELECT COUNT(*) FROM reservations').fetchone()[0]==len(record['rows']),'ledger charge/count differs')
            for key_id,algorithm,public_key,limit_text,used_text in connection.execute('SELECT key_id,algorithm,public_key,limit_text,used_text FROM keys'):
                count=int(used_text)
                require(algorithm=='slh-dsa-sm3-128-24' and int(limit_text)==1<<24,'replay key parameter/limit differs')
                require(key_id==sha(b'a15:slh:pid:3\0'+public_key),'canonical key identity differs')
                reservations=connection.execute('SELECT ordinal_text,receipt FROM reservations WHERE key_id=?',(key_id,)).fetchall()
                require(len(reservations)==count and sorted(int(x[0]) for x in reservations)==list(range(1,count+1)),'key ordinal/charge differs')
                accounting=connection.execute('SELECT used_text,last_receipt FROM accounting WHERE key_id=?',(key_id,)).fetchone()
                require(accounting is not None and int(accounting[0])==count and accounting[1]==max(reservations,key=lambda x:int(x[0]))[1],'accounting differs')
            for row in record['rows']:
                receipt=row['receipt_evidence']
                key=connection.execute('SELECT k.key_id,k.public_key FROM keys k JOIN reservations r ON r.key_id=k.key_id WHERE r.receipt=?',(row['receipt'],)).fetchone()
                require(key is not None and key[0]==receipt['key_id'] and sha(key[1])==row['public_key_sha256']==receipt['public_key_sha256'],'receipt/public key differs')
                require(receipt['ledger_uuid']==uuid and receipt['receipt']==row['receipt'],'receipt UUID differs')
                require(row['passed'] and row['signature_equal'] and row['ref_accepted'] and
                        row['actual_signature_sha256']==row['expected_signature_sha256'],'signature oracle mismatch')
                sql=connection.execute('SELECT status,signature_sha256,message_sha256,operation_id,case_identity FROM reservations WHERE receipt=?',(row['receipt'],)).fetchone()
                require(sql==('committed',row['actual_signature_sha256'],row['message_sha256'],receipt['operation_id'],row['case_id']),'receipt mismatch')
                signed+=1
        finally:connection.close()
        if directory=='full-pid3-replay-r3-bound':
            prepared=root/'reproduction-r3-final-gates/ablation/prepared.json'
            require(file_sha(prepared)==record['build_manifest_sha256'] and record['build_manifest_unchanged'],'signing build binding differs')
            variant=record['accepted_build_variant']
            require(variant in read(prepared)['variants'] and variant['library_sha256']==record['library_sha256'],'accepted library differs')
            require(variant['wots_schedule']==2 and variant['fors_verify_x8']==1,'signing did not accept optimized variant')
    require(call_total==412800 and signed==7 and library_total==18 and correctness_total==5418,'campaign totals differ')
    print(json.dumps({'status':'PASS','artifact_files':len(manifest['files']),'source_archive_members':len(zip_hashes),
          'prepared_libraries_checked':library_total,'real_fixture_checks':correctness_total,
          'measured_verification_calls':call_total,'charged_replay_signatures':signed,
          'native_code_executed_by_this_audit':False,'scope':'internal evidence integrity and consistency; no award/security certification'},indent=2))

if __name__=='__main__':main()
