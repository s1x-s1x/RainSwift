#!/usr/bin/env python3
"""Read-only V5 evidence audit. No project/native imports or execution."""
import argparse,difflib,hashlib,json,re,zipfile
from pathlib import Path

def sha(data):return hashlib.sha256(data).hexdigest()
def read(path):return json.loads(path.read_bytes())
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def require(value,message):
    if not value:raise ValueError(message)
def flip(data,offset=0):
    output=bytearray(data or b'\0');output[offset]^=1;return bytes(output)
def mutations(case):
    m,s,p,c=(bytes.fromhex(case[k]) for k in ('message','sig','pk','context'))
    return {'valid':(m,s,p,c),'fors-secret-bit':(m,flip(s,16),p,c),
            'fors-auth-bit':(m,flip(s,32),p,c),'message-bit':(flip(m),s,p,c),
            'truncated':(m,s[:-1],p,c),'extra-byte':(m,s+b'\0',p,c)}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bundle',type=Path,required=True)
    args=parser.parse_args();root=args.bundle.resolve();manifest=read(root/'manifest.json');before=sha((root/'manifest.json').read_bytes())
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p!=root/'manifest.json'}
    require(actual==set(manifest['files']),'bundle file set differs')
    for name,entry in manifest['files'].items():
        path=(root/name).resolve();require(root in path.parents,'artifact path escapes bundle')
        require(path.stat().st_size==entry['bytes'] and sha(path.read_bytes())==entry['sha256'],'artifact differs: '+name)
    require(manifest['status']=='correctness-accepted-performance-pending' and manifest['timing_samples']==0 and
            manifest['new_128_24_signatures']==0 and manifest['main_core_modified'] is False,'candidate scope relabelled')
    sources=read(root/'source-manifest.json')['source_files_sha256']
    with zipfile.ZipFile(root/'candidate-source.zip') as archive:
        require(len(archive.namelist())==len(set(archive.namelist())) and set(archive.namelist())==set(sources),'source member set differs')
        candidate={name:archive.read(name) for name in sources}
        require(all(sha(data)==sources[name] for name,data in candidate.items()),'source member hash differs')
    with zipfile.ZipFile(root/'baseline-source.zip') as archive:baseline={name:archive.read(name) for name in archive.namelist()}
    changed=sorted(n for n in candidate if candidate[n]!=baseline[n])
    expected_changes=sorted(['c/Makefile','c/src/engine.c','c/src/sm3x8.c','c/src/sm3x8.h','c/tests/test_verify_scheduling.c'])
    require(changed==expected_changes,'unexpected source changes')
    patch=''.join(''.join(difflib.unified_diff(baseline[name].decode().splitlines(keepends=True),candidate[name].decode().splitlines(keepends=True),
                  fromfile='a/'+name,tofile='b/'+name)) for name in ['c/src/engine.c','c/src/sm3x8.c','c/src/sm3x8.h','c/Makefile','c/tests/test_verify_scheduling.c'])
    require(patch==(root/'candidate.patch').read_text(),'patch does not recreate candidate source difference')
    checks=0
    for name,builddir in [('prepared','builds'),('prepared-r2','builds-r2')]:
        directory=root/'evidence'/name;prepared=read(directory/'prepared.json')
        require(prepared['status']=='prepared-not-timed' and prepared['signing_calls']==0,'preparation scope differs')
        for source,digest in prepared['source_sha256'].items():
            data=candidate[source]
            if name=='prepared' and source=='c/src/engine.c':data=(root/'evidence/history/integration-v1/engine.c').read_bytes()
            require(sha(data)==digest,'prepared source differs: '+name+'/'+source)
        digest=sha(canonical(prepared['source_sha256']).encode());require(digest==prepared['source_manifest_sha256'],'source manifest differs')
        variants={v['name']:v for v in prepared['variants']};require(len(variants)==6,'variant matrix differs')
        for v in variants.values():
            lib=root/'evidence'/builddir/v['name']/'libslhdsa_sm3.so'
            require(sha(lib.read_bytes())==v['library_sha256'] and v['counters']==0,'accepted library differs')
        fixtures=read(directory/'fixtures.json');require(isinstance(fixtures,list) and len(fixtures)==43,'fixture set differs')
        cases={c['case_id']:c for c in fixtures};require(len(cases)==43,'duplicate fixtures')
        for c in fixtures:
            fields={k:c[k] for k in ('message','context','pk','sig')}
            require(c['input_sha256']==sha(canonical({'pid':c['pid'],**fields}).encode()),'fixture identity differs')
            require(all(c['content_sha256'][k]==sha(bytes.fromhex(v)) for k,v in fields.items()),'fixture field differs')
        raw=(directory/'correctness.jsonl').read_bytes();require(sha(raw)==prepared['correctness_sha256'],'correctness raw differs')
        rows=[json.loads(line) for line in raw.splitlines()];require(len(rows)==prepared['correctness_rows']==1806,'row count differs')
        keys={(r['variant'],r['backend'],r['case_id'],r['mutation']) for r in rows}
        groups=[('wots0-fors0',1),*((v,2) for v in variants)]
        expected={(v,b,c,m) for v,b in groups for c in cases for m in mutations(cases[c])}
        require(len(keys)==len(rows) and keys==expected,'case/backend/mutation coverage differs')
        for r in rows:
            values=mutations(cases[r['case_id']])[r['mutation']];valid=r['mutation']=='valid'
            require(r['pass'] is True and r['accepted'] is valid and r['expected'] is valid,'incorrect acceptance result')
            require(r['pid']==cases[r['case_id']]['pid'] and r['fixture_sha256']==cases[r['case_id']]['input_sha256'],'fixture row differs')
            require(r['library_sha256']==variants[r['variant']]['library_sha256'] and r['source_manifest_sha256']==digest,'row build differs')
            require(r['mutation_sha256']==sha(canonical([v.hex() for v in values]).encode()),'actual negative input differs')
        checks+=len(rows)
    primitives=read(root/'evidence/correctness-r3/result.json');require(primitives['status']=='PASS_CORRECTNESS_ONLY','primitive tests incomplete')
    for record in primitives['variants']:
        result=record['result'];require(result['passed'] is True and result['lane_differential_checks']==16400,'primitive coverage differs')
        require(result['full_schedule_zero_after']==(4098 if result['avx2'] else 0),'full schedule cleanup missing')
        require(result['invalid_lengths']==6 and result['input_tail_guard_page_calls']==2,'boundary coverage differs')
        require(sha((root/'evidence/correctness-r3'/record['name']).read_bytes())==record['binary_sha256'],'primitive executable differs')
    rejected=read(root/'evidence/zero-rejection/result.json')
    require(rejected['status']=='PASS_EXPECTED_REJECTION' and rejected['exit_code']==1,'zeroization fault was not rejected')
    require(sha((root/'evidence/history/v1/sm3x8.c').read_bytes())==rejected['negative_source_sha256'],'negative source differs')
    for log in ('component-r2-launch.log','component-r2-sanitizer-launch.log'):
        text=(root/'evidence'/log).read_text()
        require('5272 per-invocation prediction checks PASS' in text and
                'VERIFY-SCHED PASS: FORS=1664 WOTS=1280 CPU-dispatch=384 length-rejections=24' in text,'component coverage incomplete')
    codegen=read(root/'evidence/codegen-r2/result.json')
    require(codegen['public_symbols_equal'] is True and codegen['timing_samples']==0,'static inspection scope differs')
    for func,count in [('a15_sm3x8_final_blocks',16),('a15_sm3x8_final_thash',0)]:
        text=(root/'evidence/codegen-r2'/(func+'.asm')).read_text()
        require(len(re.findall(r'\bvpgather\w+',text))==count==codegen['functions'][func]['static_gather_instruction_sites'],'static gather sites differ')
    require(sha((root/'manifest.json').read_bytes())==before,'manifest changed during read')
    print(json.dumps({'status':'PASS_CANDIDATE_CORRECTNESS_EVIDENCE','artifacts':len(actual),'source_files':len(candidate),
        'real_fixture_checks':checks,'primitive_lane_checks_per_configuration':16400,'native_calls':0,
        'timing_samples':0,'performance_accepted':False,'main_core_promoted':False,'manifest_sha256':before},indent=2))

if __name__=='__main__':main()
