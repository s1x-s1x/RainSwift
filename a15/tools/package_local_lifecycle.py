#!/usr/bin/env python3
"""Freeze existing local lifecycle evidence; no native imports or execution.

The failed campaign remains failed. Only independently accepted complete
prefix phases may be summarized. Original manifests and absolute paths are
preserved, with a separate library relocation map for read-only verification.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'__pycache__', 'python-cache', 'python-cache-win', 'scratch', '.git'}

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return json.loads(path.read_bytes())
def write(path, value): path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
def copy_tree(source, target):
    target.mkdir(parents=True, exist_ok=False)
    for path in sorted(source.rglob('*')):
        relative = path.relative_to(source)
        if path.is_file() and not any(part in EXCLUDED for part in relative.parts):
            destination = target/relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)

def audit_bindings(campaign,build,prefix_audit,independent_audit):
    """Reject an accepted audit belonging to a different campaign or ledger."""
    prefix=read(prefix_audit/'audit.json');independent=read(independent_audit/'audit.json')
    identities={'plan_sha256':sha(campaign/'plan.json'),
                'campaign_sha256':sha(campaign/'campaign.json'),
                'build_manifest_sha256':sha(build)}
    if any(prefix.get(key)!=value for key,value in identities.items()):
        raise ValueError('prefix audit belongs to another plan/campaign/build')
    database=sha(campaign/'budget.sqlite')
    if prefix.get('ledger',{}).get('database_sha256')!=database:
        raise ValueError('prefix audit ledger differs')
    if independent.get('plan_sha256')!=identities['plan_sha256'] or \
       independent.get('build_manifest_sha256')!=identities['build_manifest_sha256'] or \
       independent.get('database_sha256')!=database:
        raise ValueError('independent audit belongs to another plan/build/ledger')
    original=str(independent.get('run_root','')).replace('\\','/').rstrip('/')
    if not original:raise ValueError('independent audit lacks its campaign root')
    checked=set()
    for name,value in independent.get('audited_files_sha256',{}).items():
        normal=name.replace('\\','/')
        if not normal.startswith(original+'/'):continue
        relative=normal[len(original)+1:]
        target=(campaign/relative).resolve()
        if not target.is_relative_to(campaign.resolve()) or not target.is_file() or sha(target)!=value:
            raise ValueError('independent audited campaign input differs: '+relative)
        checked.add(relative)
    required={'plan.json','campaign.json','budget.sqlite'}
    required.update(step['phase']+'/timing.jsonl' for step in read(campaign/'campaign.json')['steps']
                    if (campaign/step['phase']/'timing.jsonl').is_file())
    if not required<=checked:raise ValueError('independent audit lacks campaign/raw bindings')
    return {**identities,'database_sha256':database,'independent_campaign_files_checked':len(checked)}

def check(out):
    manifest = read(out/'manifest.json')
    actual = {p.relative_to(out).as_posix() for p in out.rglob('*') if p.is_file() and p != out/'manifest.json'}
    if actual != set(manifest['files']): raise ValueError('bundle file set differs')
    for name, entry in manifest['files'].items():
        path = out/name
        if path.stat().st_size != entry['bytes'] or sha(path) != entry['sha256']:
            raise ValueError('bundle artifact changed: '+name)
    members = read(out/'source-manifest.json')['actual_source_files_sha256']
    with zipfile.ZipFile(out/'actual-source.zip') as archive:
        if len(archive.namelist()) != len(set(archive.namelist())) or set(archive.namelist()) != set(members):
            raise ValueError('source archive member set differs')
        for name, digest in members.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != digest: raise ValueError('source member changed: '+name)
    if read(out/'campaign/campaign.json')['status'] != 'failed': raise ValueError('campaign status relabelled')
    if read(out/'prefix-audit/audit.json')['status'] != 'PASS_COMPLETED_PREFIX_ONLY': raise ValueError('prefix acceptance differs')
    audit_bindings(out/'campaign',out/'accepted-build.json',out/'prefix-audit',out/'independent-audit')
    return {'status':'PASS_FROZEN_PREFIX_BUNDLE', 'files':len(actual), 'native_calls':0,
            'overall_lifecycle_completed':False, 'manifest_sha256':sha(out/'manifest.json')}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--evidence-root', type=Path)
    parser.add_argument('--prefix-audit', type=Path)
    parser.add_argument('--independent-audit', type=Path)
    parser.add_argument('--harness-review', type=Path)
    args = parser.parse_args(); out = args.output.resolve()
    if args.check_only: print(json.dumps(check(out))); return
    if any(v is None for v in (args.evidence_root, args.prefix_audit, args.independent_audit, args.harness_review)):
        parser.error('freezing requires evidence root and both audits and harness review')
    origin = args.evidence_root.resolve(); campaign = origin/'lifecycle-r3-prepared'
    build_path = origin/'reproduction-r3-final-gates/ablation/prepared.json'
    if out == origin or origin in out.parents: raise ValueError('output must be outside evidence root')
    if read(campaign/'campaign.json')['status'] != 'failed': raise ValueError('this package expects the preserved failed R3')
    for name in ('lifecycle-r1', 'lifecycle-r3-prepared'):
        for suffix in ('-wal', '-shm', '-journal'):
            if (origin/name/('budget.sqlite'+suffix)).exists(): raise ValueError('ledger must be closed/checkpointed: '+name)
    if read(args.prefix_audit/'audit.json')['status'] != 'PASS_COMPLETED_PREFIX_ONLY': raise ValueError('prefix audit not accepted')
    independent = read(args.independent_audit/'audit.json')
    if independent.get('passed') is not True or independent.get('whole_campaign_complete') is not False:
        raise ValueError('independent prefix audit not accepted')
    audit_bindings(campaign,build_path,args.prefix_audit,args.independent_audit)
    out.mkdir(parents=True, exist_ok=False)
    copy_tree(campaign, out/'campaign')
    copy_tree(args.prefix_audit, out/'prefix-audit')
    copy_tree(args.independent_audit, out/'independent-audit')
    copy_tree(args.harness_review, out/'harness-review')
    copy_tree(origin/'lifecycle-mock-review-v3', out/'original-runner-mock-review')
    copy_tree(origin/'lifecycle-ledger-checkpoint', out/'ledger-checkpoint-observation')
    shutil.copyfile(origin/'checkpoint_lifecycle_ledger.py', out/'ledger-checkpoint-observation/driver.py')
    for name in ('lifecycle-r1', 'lifecycle-r2'):
        copy_tree(origin/name, out/'history'/name)
    copy_tree(origin/'lifecycle-prefix-independent', out/'history/independent-audit-first')
    copy_tree(origin/'lifecycle-prefix-audit-probes', out/'history/audit-probes-first')
    copy_tree(origin/'lifecycle-prefix-audit-probes-r2', out/'audit-probes')
    shutil.copyfile(origin/'lifecycle-prefix-audit-probes.py', out/'audit-probes/driver.py')
    shutil.copyfile(origin/'lifecycle-prefix-audit-probes-r1-driver.py', out/'history/audit-probes-first-driver.py')
    for name in ('lifecycle-r1-interruption.json','lifecycle-r1.log','lifecycle-r2-busy-gate.log',
                 'lifecycle-r3-busy-gate.log','lifecycle-r3-prepared.log'):
        shutil.copyfile(origin/name, out/'history'/name)
    snapshots = out/'history/driver-snapshots'; snapshots.mkdir()
    for source, name in [(origin/'lifecycle-source/tools/bench_local_lifecycle.py','r1.py'),
                         (origin/'lifecycle-source-r2/tools/bench_local_lifecycle.py','r2.py')]:
        shutil.copyfile(source, snapshots/name)
    build_path = origin/'reproduction-r3-final-gates/ablation/prepared.json'
    shutil.copyfile(build_path, out/'accepted-build.json')
    libraries = []
    for variant in read(campaign/'plan.json')['variants']:
        source = Path(variant['library']); destination = out/'libraries'/variant['name']/'libslhdsa_sm3.so'
        if sha(source) != variant['library_sha256']: raise ValueError('accepted library changed')
        destination.parent.mkdir(parents=True); shutil.copyfile(source, destination)
        libraries.append({'variant':variant['name'],'original_path':str(source),
                          'bundle_path':destination.relative_to(out).as_posix(),'sha256':sha(destination)})
    write(out/'library-location-map.json', {'libraries':libraries, 'original_manifests_modified':False})
    original_sources = read(ROOT/'report-data/verify-optimization-20261004/source-manifest.json')['files_sha256']
    names = sorted({*original_sources, 'tools/bench_local_lifecycle.py'})
    frozen = origin/'lifecycle-source-r3'; hashes = {name:sha(frozen/name) for name in names}
    for name, value in read(campaign/'plan.json')['source_sha256'].items():
        if hashes.get(name) != value: raise ValueError('executed source differs: '+name)
    with zipfile.ZipFile(out/'actual-source.zip', 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names: archive.write(frozen/name, name)
    if hashes != {name:sha(frozen/name) for name in names}: raise ValueError('source changed during archive')
    final_names = ['tools/bench_local_lifecycle.py','tools/audit_local_lifecycle.py',
                   'tools/plot_local_lifecycle.py','tools/package_local_lifecycle.py',
                   'tools/workload_guard.py','tools/test_workload_guard.py',
                   'tools/test_lifecycle_settlement.py','tools/test_lifecycle_package_bindings.py',
                   'docs/LOCAL_LIFECYCLE_20261004.md']
    current = {}
    for name in final_names:
        destination = out/'final-tools'/name; destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/name, destination); current[name] = sha(destination)
    write(out/'source-manifest.json', {'actual_source_files_sha256':hashes,'final_tools_files_sha256':current,
          'policy':'actual-source.zip contains the executed R3 runner; later tool fixes are separate and have no new native samples'})
    (out/'README.md').write_text('''# 生命周期部分证据（2026-10-04）

原计划7阶段，R3在缓存签名阶段发现另一个check_optimization.py负载后失败。
只有keygen/cache_build/cache_load/sign_uncached四个完整阶段接受统计；全生命周期未完成。
未完成缓存签名的全部原始行及36次累计签名收费保留；失败候选输出也计费。
内部ABI、单公开fixture、8物理核；内存是含Python/两库/检查的worker峰值。
known-process quiet gate不保证宿主或未知进程无干扰；本包不是正式竞赛矩阵。
actual-source.zip为实际执行版本；final-tools为后续工具修复，无追加原生测试。

冻结哈希校验（不执行native）：
python3 final-tools/tools/package_local_lifecycle.py --check-only --output .

解压actual-source.zip至新目录source后，重算完整前缀与全部预算：
python3 final-tools/tools/audit_local_lifecycle.py --allow-incomplete \\
  --campaign campaign --source-root source --build-manifest accepted-build.json \\
  --library-root libraries --output /path/to/new-read-only-audit

历史R1受干扰数据不纳入统计，R2是busy gate拒绝；旧目录和驱动均保留。
本包含公开实验密钥、本机路径与账号，只作内部审查，不可直接作为匿名提交包。
''', encoding='utf-8')
    artifacts = {p.relative_to(out).as_posix():{'sha256':sha(p),'bytes':p.stat().st_size}
                 for p in sorted(out.rglob('*')) if p.is_file()}
    write(out/'manifest.json', {'schema':'a15-local-lifecycle-prefix-v1',
          'created_at_utc':datetime.now(timezone.utc).isoformat(), 'files':artifacts,
          'campaign_status':'failed', 'overall_lifecycle_completed':False})
    print(json.dumps(check(out)))

if __name__ == '__main__': main()
