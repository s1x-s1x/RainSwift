"""Exact, finite parameter/local-bound comparison. Not a strength certificate.

Source-derived dimensions and conditional local lemmas are kept distinct from
the author's inapplicable/incorrect full-protocol instantiation. No crypto runs.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import importlib.util
import io
import json
import math
import os
import re
import sys
import time
from datetime import datetime, timezone
from fractions import Fraction as F
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[1]
Q4 = BASE.parent
ORIG = Q4.parent / '源码/rain-voleith'
UP = Path('<工作区>/迭代/迭代028_P0基线与求解器/资料/sources/rfaest/rFAEST')
M = 1 << 128
CID = 'C030-RFAEST128-EQUIV'

def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

def sha(path):
    if '粘贴的' in str(path):
        raise ValueError('excluded input')
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write_new(path, text):
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(text, encoding='utf-8')
    os.replace(tmp, path)

def jwrite(path, obj):
    write_new(path, json.dumps(obj, ensure_ascii=False, indent=2) + '\n')

def frac(x):
    x = F(x)
    return dict(numerator=str(x.numerator), denominator=str(x.denominator))

def log2frac(x):
    # Display only; every ordering/threshold comparison below is exact.
    x = F(x)
    return math.log2(x.numerator) - math.log2(x.denominator)

def exact_record(x):
    return dict(**frac(x), log2_display=log2frac(x))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]+', args.run_id):
        raise ValueError('run-id must be a simple fresh directory name')
    out = BASE / '原始数据' / args.run_id
    if out.exists():
        raise FileExistsError(out)
    t0, c0 = time.perf_counter(), time.process_time()
    started = datetime.now(timezone.utc).isoformat()
    gate = json.loads((BASE/'原始数据/当前实验门控.json').read_text('utf-8'))
    reg = json.loads((BASE/'候选登记表.json').read_text('utf-8'))
    gm = load_module(BASE/'管理工具/候选门控.py', '_equality_gate')
    candidate = next(c for c in reg['candidates'] if c['id'] == CID)
    allowed, reason = gm.evaluate(candidate, 'bounded-check', gate)
    if not allowed:
        raise RuntimeError(reason)
    if gate['remaining_compute_wall_seconds'] < 60:
        raise RuntimeError('less than one finite-check allowance remains')
    old = load_module(Q4/'脚本/重做05/run_ledger.py', '_old_guard_only')
    guard = old.ResourceGuard(60)
    # Enforce one logical processor where this Windows API is available.
    affinity = 'not available on this OS'
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.GetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
        k32.GetProcessAffinityMask.restype = wintypes.BOOL
        k32.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
        k32.SetProcessAffinityMask.restype = wintypes.BOOL
        a, b = ctypes.c_size_t(), ctypes.c_size_t()
        if not k32.GetProcessAffinityMask(k32.GetCurrentProcess(), ctypes.byref(a), ctypes.byref(b)):
            raise OSError('GetProcessAffinityMask')
        mask = a.value & -a.value
        if not k32.SetProcessAffinityMask(k32.GetCurrentProcess(), mask):
            raise OSError('SetProcessAffinityMask')
        affinity = hex(mask)

    checks = []
    def ck(label, condition):
        checks.append(dict(label=label, pass_=bool(condition)))
        if not condition:
            raise AssertionError(label)
        guard.check()

    # Reuse the historical frozen input identity, not its old experiment budget.
    frozen_path = Q4/'类别1核验_20261015/原始数据/输入快照.json'
    frozen = json.loads(frozen_path.read_text('utf-8'))
    inputs = {}
    for e in frozen['files']:
        p = Path(e['path'])
        h = sha(p)
        ck('frozen:' + str(p), h == e['sha256'])
        inputs[str(p)] = h
    independent_path = BASE/'独立核对/组件与参数_证据.json'
    independent = json.loads(independent_path.read_text('utf-8'))
    for e in independent['components']:
        if e.get('missing'):
            continue
        for root, key in [(UP,'up_sha256'), (ORIG,'orig030_sha256')]:
            p = root/e['file']
            h = sha(p)
            ck('component:' + str(p), h == e[key])
            inputs[str(p)] = h
    paper = Q4/'资料/rFAEST_2025-1077_作者版.pdf'
    ck('paper identity', sha(paper) == '515cd5949e714df7cadab994528462f3f0dba6e559914c77a1d766aab2ea5646')
    for p in [paper, frozen_path, independent_path, Q4/'Q4_重做_02_P01_坏事件与自适应分析.md',
              Q4/'P0-3_Lemma3.6_反例严格核验.md',
              Q4/'类别1核验_20261015/Rain分析/Rain128_类别1核验.md']:
        inputs[str(p)] = sha(p)

    # Read actual aliases (the v2 segment avoids similarly named v1 aliases).
    uptext = (UP/'parameters.hpp').read_text('utf-8').split('namespace v2', 1)[1]
    raintext = (ORIG/'parameters.hpp').read_text('utf-8').split('namespace rain_sets', 1)[1]
    regex = re.compile(r'using\s+(\w+)\s*=\s*parameter_set<secpar::s128,\s*(\d+),\s*owf::(\w+),\s*prg::aes_ctr,\s*prg::aes_ctr,\s*leaf_hash::aes_ctr,\s*(\d+),\s*\{bavc::ggm_forest,\s*0\}>;', re.S)
    aliases = {m[0]: (int(m[1]),m[2],int(m[3])) for m in regex.findall(uptext)}
    aliases.update({m[0]: (int(m[1]),m[2],int(m[3])) for m in regex.findall(raintext)})
    wanted = [('ref_f','faest_em_128_f'),('ref_s','faest_em_128_s')] + [(x,x) for x in
              ['rain3_fast','rain3_bal','rain3_short','rain4_fast','rain4_bal','rain4_short']]
    records, local, paper_sensitivity, prg_refutation = [], {}, [], []
    u = 128
    for name, alias in wanted:
        tau, owf, g = aliases[alias]
        rain = name.startswith('rain')
        R = int(owf[-1]) if rain else None
        degree = 2 if rain else 3
        witness = 128*R if rain else 128 + 8*(16*10*3//4 - 16)
        constraints = R if rain else 3*16*10//2 + 1
        B = 6 if rain or tau == 11 else 5
        D = 128-g
        kl, nh = divmod(D,tau)
        nl = tau-nh
        nmax = 1 << (kl + bool(nh))
        N = nl*(1<<kl) + nh*(1<<(kl+1))
        lqs = witness+(degree-1)*128
        L = lqs+128+8*B
        m = (L+127)//128
        n = (lqs+127)//128
        sig = (L//8)*(tau-1) + 16+B + witness//8 + (degree-1)*16 + (D+tau)*16 + 16+16+4
        row = dict(name=name,tau=tau,g=g,D=D,B_bytes=B,k_low=kl,n_low=nl,k_high=kl+1,n_high=nh,
                   N_total=N,N_max=nmax,witness_bits=witness,QS_degree=degree,constraints=constraints,
                   LQS=lqs,VHash_bits=128+8*B,L_bits=L,tape_AES_blocks=m,signature_bytes=sig,
                   sign_AES=(m+3)*N-tau,verify_AES=(m+3)*(N-tau)-2*D+tau,
                   h1_input_bytes=81+(L//8)*(tau-1),
                   h2_input_bytes=88+(16+B)*129+witness//8+1,
                   h3_input_bytes=56+16+(degree-1)*16+4+1,hybrid_path=D+2*tau)
        refrow = next(e for e in independent['parameters'] if e['name'] == name)
        for key, value in row.items():
            ck(name + ':' + key, value == refrow[key])
        ck(name+': challenge dimension', nl*kl+nh*(kl+1)+g == 128)
        ck(name+': source API bytes integral', L % 8 == 0 and witness % 8 == 0)
        ev = F(1,1<<(128+8*B)) + F((n-1)*(2*n-1),1<<192)
        ez = F(1,M) + F((constraints-1)**2,1<<192)
        local[name] = dict(V_single=ev, V_pair_list=math.comb(tau,2)*ev,
                           Z_single=ez, fixed_target=F(1,M), qs_roots=F(degree,M),
                           conservative_challenge=F(degree+1,M))
        row['V_padded_blocks_128'] = n
        row['V_root_product'] = (n-1)*(2*n-1)
        row['Z_root_product'] = (constraints-1)**2
        row['secret_domain_log2_display'] = 128.0 if rain else 128+math.log2(3/4)
        row['secret_domain_scope'] = 'unshrunk K; joint (P,K) rejection TV<=R/2^128' if rain else 'exactly 3*2^126 accepted secrets'
        row['local_coefficients'] = {k:exact_record(v) for k,v in local[name].items()}
        records.append(row)

        # PURE SENSITIVITY of printed paper formulas, not established bounds
        # for either source implementation. Nmax use is hypothetical padding.
        vcoef = F(nmax*nmax*(tau*tau*u**4+8*tau*u*u),8)*ev
        coll2coef = F(64*nmax*nmax,1<<256)
        exponent4 = 6+2*(nmax.bit_length()-1)-127*(L//128-2)
        fourcoef = F(2**exponent4) if exponent4>=0 else F(1,1<<(-exponent4))
        paper_sensitivity.append(dict(name=name,status='UNESTABLISHED_FOR_SOURCE__FORMULA_SENSITIVITY_ONLY',
            Q_times_V=exact_record(vcoef), QP_squared_times_coll2=exact_record(coll2coef),
            Qsum_times_fourxor=exact_record(fourcoef),
            hiding_path_count=D+2*tau, printed_PRG_first_coefficient=(D+2*tau)*(m+3)**2))

        # Rigorous lower bound on the EXISTING component distinguisher:
        # p*(1-1/M)^Q >= p*(1-p), Q=2^100. Never exponentiate huge integers.
        q = 1 << 100
        p = F(q,M)
        lower, upper = p*(1-p), p
        c = m+3
        printed = F(c*c,M) + F(c*c,M*M) + F(2*q*c,M*M)
        ck(name+': lemma premise at QI=1, QP=2^100', nmax+q <= M//2)
        ck(name+': PRG printed bound contradicted', lower > printed)
        prg_refutation.append(dict(name=name,QI='1',QP=str(q),
            rigorous_lower=exact_record(lower),rigorous_upper=exact_record(upper),
            printed_upper=exact_record(printed),ratio_lower_to_printed=exact_record(lower/printed),
            scope='component PRG distinguishing only; not signature forgery; prior counterexample reused'))

    pair_results = []
    for name in local:
        if not name.startswith('rain'):
            continue
        ref = 'ref_s' if name.endswith('short') else 'ref_f'
        ratios = {}
        for key in local[name]:
            ratio = local[name][key]/local[ref][key]
            ck(name+': local coefficient <= '+ref+':'+key, ratio <= 1)
            ratios[key] = exact_record(ratio)
        pair_results.append(dict(name=name,comparator=ref,ratios=ratios,
                                 implication='local fixed-difference/residual lemmas only; extraction/OWF/hiding not included'))

    # Freeze all checked files again after the finite arithmetic.
    for p, h in inputs.items():
        ck('unchanged at exit:' + p, sha(Path(p)) == h)
    guard.check()
    body_wall, body_cpu = time.perf_counter()-t0, time.process_time()-c0
    result = dict(schema='rfaest128_comparison_v1',candidate=CID,started_utc=started,
        script_sha256=sha(Path(__file__)),input_sha256=inputs,
        scope='classical single-parameter single-public-key; exact parameter counts and local conditional bound comparison',
        parameters=records,local_comparisons=pair_results,paper_sensitivity=paper_sensitivity,
        component_PRG_refutation=prg_refutation,checks=checks,
        check_count=len(checks),all_checks_passed=True,
        full_signature_equivalence='OPEN',full_forgery_below_nominal128='NOT_ESTABLISHED',
        Rain_concrete_OWF_advantage=None,
        resources=dict(workload_wall_seconds=body_wall,process_cpu_seconds=body_cpu,
                       process_limit=1,processor_affinity=affinity,**guard.snapshot(),
                       accounting_scope='script body up to snapshot; excludes final output writing/process startup/exit; no native protocol execution'))
    out.mkdir(parents=True)
    jwrite(out/'comparison.json',result)
    buf=io.StringIO(newline='')
    writer=csv.writer(buf)
    writer.writerow(['name','comparator','tau','g','N_total','N_max','b_bits','QS_degree','witness_bits','constraints','V_pair_log2','Z_log2','QS_roots_log2','signature_bytes'])
    for r in records:
        name=r['name']
        writer.writerow([name,('ref_s' if name.endswith('short') else 'ref_f') if name.startswith('rain') else '',r['tau'],r['g'],r['N_total'],r['N_max'],r['B_bytes']*8,r['QS_degree'],r['witness_bits'],r['constraints'],log2frac(local[name]['V_pair_list']),log2frac(local[name]['Z_single']),log2frac(local[name]['qs_roots']),r['signature_bytes']])
    write_new(out/'comparison.csv',buf.getvalue())
    jwrite(out/'run_finished.json',dict(status='PASS',checks=len(checks),result_sha256=sha(out/'comparison.json'),
          workload_wall_seconds=body_wall,process_cpu_seconds=body_cpu,resources=result['resources'],
          finished_utc=datetime.now(timezone.utc).isoformat(),full_signature_equivalence='OPEN'))
    print(json.dumps(dict(status='PASS',checks=len(checks),parameters=len(records),
                          comparisons=len(pair_results),out=str(out),wall_seconds=body_wall,
                          full_signature_equivalence='OPEN'),ensure_ascii=False))

if __name__ == '__main__':
    main()
