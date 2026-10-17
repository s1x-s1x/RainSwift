"""Finite conditional-distribution checks and exact substitution in new lemmas.

No native implementation, attack search, benchmark, or protocol parameter scan.
The Rain advantage and complete security strength deliberately remain unknown.
"""
from pathlib import Path
from datetime import datetime, timezone
from fractions import Fraction
from itertools import combinations, permutations, product
from collections import defaultdict
import argparse
import hashlib
import importlib.util
import json
import math
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.set_int_max_str_digits(30000)
BASE = Path(__file__).resolve().parents[1]
OLD = BASE.parent / '具体界推进_20261015'
AU = BASE / '误差收紧/01_全桶AU的前缀桶矩界.md'
CMA = BASE / '误差收紧/02_CMA端点去重与诚实重构细化.md'
R1_SCRIPT = BASE / '脚本/核验误差瓶颈与固定阈值.py'
R1 = BASE / '原始数据/R1_thresholds/result.json'
PARAM = BASE.parent / '等强核验_rFAEST128_20261015/原始数据/R1/comparison.json'
LEDGER = OLD / '原始数据/R3_witness_ledger/result.json'
HELPER = OLD / '脚本/验证仿射引理与地址缓存.py'
M, U = 1 << 128, 80
EXPECTED_PROOFS = {
    AU: '71d383e2552ed87aae9c845565ab284bd3ae03e024272caf481b323f7156f21e',
    CMA: '09bbf27a19db81ee84840044a039cfd392d05853120d4f06d4ef4d1f22a1c29d',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def moments(v, lam):
    mu2 = v*v + 2*v*lam + lam*lam + lam
    mu4 = (v**4 + 4*v**3*lam + 6*v*v*(lam*lam+lam)
           + 4*v*(lam**3+3*lam*lam+lam)
           + lam**4+6*lam**3+7*lam*lam+lam)
    return {2: mu2, 4: mu4}


def stirling(n, k):
    if n == 0:
        return int(k == 0)
    if k <= 0 or k > n:
        return 0
    return k*stirling(n-1, k) + stirling(n-1, k-1)


def finite_prefix_checks(require, tick, counts):
    # Exact Bernoulli laws independently check the moment domination, including
    # deterministic indicators, unequal probabilities and repeated target use.
    for probabilities in ((Fraction(1, 2), Fraction(1, 3), Fraction(1, 4)),
                          (Fraction(0), Fraction(1), Fraction(1, 7)),
                          (Fraction(2, 3),)*4):
        lam = sum(probabilities, Fraction(0))
        for v in (2, 4):
            bounds = moments(v, lam)
            for power in (2, 4):
                exact = Fraction(0)
                for bits in product((0, 1), repeat=len(probabilities)):
                    mass = math.prod(p if b else 1-p for p, b in zip(probabilities, bits))
                    exact += mass * (v+sum(bits))**power
                expanded = sum(Fraction(math.comb(power, j)*v**(power-j))
                               * sum(stirling(j, k)*lam**k for k in range(j+1))
                               for j in range(power+1))
                require(expanded == bounds[power], 'independent Stirling expansion')
                require(exact <= bounds[power], 'Bernoulli versus Poisson moment')
                counts['finite_moment_cases'] += 1
    require(moments(2, Fraction(1)) == {2: 10, 4: 151}, 'v2 integer identities')
    require(moments(4, Fraction(1)) == {2: 26, 4: 799}, 'v4 integer identities')

    # All 6^3 independent three-point permutations. The second operation is
    # adaptive; one strategy uses a forward call, the other an inverse call.
    small = 3
    perms = tuple(permutations(range(small)))
    families = tuple(product(perms, repeat=small))
    for mode in ('second_forward', 'adaptive_inverse'):
        groups = defaultdict(list)
        for oracle in families:
            y = oracle[0][0]
            first = (0, 0, y)
            if mode == 'second_forward':
                second = (1, 0, oracle[1][0])
            else:
                key, target = 1+(y % 2), (y+1) % small
                second = (key, oracle[key].index(target), target)
            for prefix in ((), (first,), (first, second)):
                groups[prefix].append(oracle)
        for prefix, completions in groups.items():
            q = len(set(prefix))
            lam = Fraction(1) + Fraction(q, small*(small-q))
            for x, y in product(range(small), repeat=2):
                observed = len({key for key, xx, yy in prefix if (xx, yy) == (x, y)})
                buckets = [sum(oracle[key][x] == y for key in range(small)) for oracle in completions]
                unknown_mean = Fraction(sum(buckets), len(buckets)) - observed
                require(unknown_mean <= lam, 'adaptive residual unknown mean')
                for left, right in combinations(range(small), 2):
                    pleft = Fraction(sum(o[left][x] == y for o in completions), len(completions))
                    pright = Fraction(sum(o[right][x] == y for o in completions), len(completions))
                    both = Fraction(sum(o[left][x] == y and o[right][x] == y for o in completions), len(completions))
                    require(both == pleft*pright, 'conditional different-key independence')
                for v in (1, 2):
                    if observed > v:
                        continue
                    bound = moments(v, lam)
                    for power in (2, 4):
                        actual = Fraction(sum(max(1, b)**power for b in buckets), len(buckets))
                        require(actual <= bound[power], 'current-prefix selected bucket moment')
                counts['finite_prefix_bucket_cases'] += 1
            tick()

    # K is chosen as the publicly known F-output. Forward response still costs
    # an output match; inverse explicitly targets it and must keep its linear term.
    fwd_hits = inv_hits = trials = 0
    for oracle in families:
        for output, label in product(range(small), repeat=2):
            key = output
            fwd_hits += int(oracle[key][0] == output and label == key)
            _ = oracle[key].index(output)
            inv_hits += int(label == key)
            trials += 1
    require(Fraction(fwd_hits, trials) == Fraction(1, small*small), 'fresh forward two matches')
    require(Fraction(inv_hits, trials) == Fraction(1, small), 'inverse retains one match')
    counts['finite_endpoint_trials'] = trials


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run-id', required=True)
    ap.add_argument('--extractor-proof', required=True)
    ap.add_argument('--extractor-sha256', required=True)
    args = ap.parse_args()
    if not args.run_id.isascii() or not args.run_id.replace('_', '').isalnum():
        raise ValueError('simple fresh run id required')
    extractor = Path(args.extractor_proof).resolve()
    if not extractor.is_relative_to((BASE/'提取收紧').resolve()) or '粘贴的' in extractor.name:
        raise ValueError('expected a new-stage extractor proof')
    expected_proofs = dict(EXPECTED_PROOFS)
    expected_proofs[extractor] = args.extractor_sha256.lower()
    for path, expected in expected_proofs.items():
        if sha(path) != expected:
            raise ValueError('proof hash mismatch: ' + str(path))
    out = BASE / '原始数据' / args.run_id
    if out.exists():
        raise FileExistsError(out)
    gate_path = BASE / '原始数据/当前实验门控.json'
    gate = json.loads(gate_path.read_text('utf-8'))
    if len(gate['consumption']) >= gate['max_runs']:
        raise RuntimeError('run quota exhausted')
    pre = subprocess.run([sys.executable, '-X', 'utf8', str(BASE/'管理工具/候选门控.py'),
                          gate['candidate'], 'bounded-check'], capture_output=True, text=True, encoding='utf-8')
    if pre.returncode:
        raise RuntimeError(pre.stdout+pre.stderr)
    snap_path = BASE / '原始数据/输入快照.json'
    snapshot = json.loads(snap_path.read_text('utf-8'))
    for name, expected in snapshot['protected_sha256'].items():
        path = Path(name)
        if '粘贴的' in path.name or sha(path) != expected:
            raise ValueError('protected input mismatch: ' + name)
    helper = load_module('limits_only', HELPER)
    affinity, peak = helper.process_limits()
    started, cpu = time.perf_counter(), time.process_time()
    r1 = load_module('r1_formulas_only', R1_SCRIPT)
    encode, fraction = r1.encode, r1.fraction
    counts = {'assertions': 0, 'finite_moment_cases': 0, 'finite_prefix_bucket_cases': 0,
              'finite_endpoint_trials': 0, 'budget_rows': 0}
    result = {
        'candidate': gate['candidate'], 'started_utc': datetime.now(timezone.utc).isoformat(),
        'script_sha256': sha(Path(__file__)),
        'input_sha256': {str(p): sha(p) for p in (R1_SCRIPT, R1, PARAM, LEDGER, HELPER, snap_path, gate_path)},
        'proof_sha256': {str(p): expected for p, expected in expected_proofs.items()},
        'protected_inputs_verified': len(snapshot['protected_sha256']),
        'scope': 'finite lemma checks and exact bounds; no whole-scheme strength certificate',
        'fixed_analysis_choices': {'u': U, 'kappa': 2, 'u_x': 2, 'u_y': 2, 'prefix_v': [2, 4]},
        'ordinary_costs_and_all_other_ST_terms_retained': True,
        'budgets_are_examples_not_user_selected_key_lifetimes': True,
        'Rain_OWF_advantage': None, 'complete_signature_security_bits': None,
        'all_checks_passed': False,
    }
    def require(ok, label):
        counts['assertions'] += 1
        if not ok:
            raise AssertionError(label)
    def tick():
        if time.perf_counter()-started > min(gate['per_check_seconds'], gate['remaining_compute_wall_seconds']):
            raise TimeoutError('wall-time budget')
        if peak() > gate['per_process_memory_bytes']:
            raise MemoryError('memory budget')
        if datetime.now(timezone.utc) > datetime.fromisoformat(gate['valid_until_utc']):
            raise TimeoutError('phase deadline')
    out.mkdir(parents=True)
    try:
        finite_prefix_checks(require, tick, counts)
        old = json.loads(LEDGER.read_text('utf-8'))
        previous = json.loads(R1.read_text('utf-8'))
        require(old['all_checks_passed'] and previous['all_checks_passed'], 'both input ledgers passed')
        params = {p['name']: p for p in json.loads(PARAM.read_text('utf-8'))['parameters']}
        old_rows = {(x['name'], x['case']): x for x in old['budget_rows']}
        rows = []
        table = ['# 完整新界：固定预算与归约IC资源', '',
                 'log₂ε表示ST附加误差；Rain优势仍待另行代入。P为归约IC调用上界，不是CPU时间。',
                 '新P属于仅重放最终伪造的B_final；不同归约的OWF项分别计费。', '',
                 '| 参数 | 预算 | 旧 log₂ε | 新 log₂ε | 误差改善倍数 | 旧P / 新P | 新主导项 |',
                 '| --- | --- | ---: | ---: | ---: | ---: | --- |']
        expected_linear = {'rain3_fast': 3126, 'rain3_bal': 5340, 'rain3_short': 35091,
                           'rain4_fast': 4735, 'rain4_bal': 4479, 'rain4_short': 35168}
        for prior in previous['budget_rows']:
            name, case = prior['name'], prior['case']
            p, oldrow = params[name], old_rows[(name, case)]
            a = prior['budgets']['attacker_forward_plus_inverse_IC']
            Q, G = prior['budgets']['signing_queries'], prior['budgets']['G']
            tau, n, r, av = p['tau'], p['N_total'], p['tape_AES_blocks'], p['verify_AES']
            sizes = [1 << p['k_low']]*p['n_low'] + [1 << p['k_high']]*p['n_high']
            require(sum(sizes) == n and len(sizes) == tau, 'forest shape')
            internal_groups = sum(sum((1 << depth)-1 for depth in range(nt.bit_length()-1)) for nt in sizes)
            leaf_groups = n-tau
            hself = internal_groups+leaf_groups+tau
            require(hself == 2*n-tau-p['D'], 'honest input groups')
            require(2*internal_groups+(r+1)*leaf_groups+tau == av, 'same honest IC cost')
            sim = r1.sim_bound(p, a, Q, G, 2)
            q0, anchor = sim['q0'], a+Q*av
            require(0 <= q0 <= M-3, 'structural domain')
            J, E, F, v0 = (sim[k] for k in ('J', 'E', 'F', 'v0'))
            require(hself+v0 == expected_linear[name], 'independently recorded linear coefficient')
            sub = sim['subterms']
            if Q:
                linear = Fraction(2*(a+av)+2*a+Q*(hself+v0), M)
                cross_input = Fraction(3*Q*(Q-1)*av*J, M*M)
                forward_output = Fraction(q0*Q*F, M*(M-q0))
                unchanged_quadratic = Fraction(q0*Q*E+3*r1.choose2(Q)*J*J+r1.choose2(Q*J), M*M)
                tails = sub['delta4']+sub['deltax']+sub['deltay']
                refined = linear+cross_input+forward_output+unchanged_quadratic+tails
                hide = min(Fraction(1), refined, sub['hide'])
            else:
                linear = cross_input = forward_output = unchanged_quadratic = tails = refined = hide = Fraction(0)
            simulation = min(Fraction(1), hide+sub['program']+sub['tail_dyadic_upper'])
            require(simulation <= sim['total'], 'same simulation event improved')
            coeff = sum(r1.choose2(nt*U) for nt in sizes) + r1.choose2(tau+n*U*U//2)
            epsv = fraction(p['local_coefficients']['V_single'])
            terms = {k: fraction(v) for k, v in prior['terms_new'].items()}
            require(terms['full_affine'] == a*epsv*coeff, 'same old AU coefficient')
            lam = Fraction(1)+Fraction(q0, M*(M-q0))
            options = []
            for v in (2, 4):
                mu = moments(v, lam)
                delta = min(Fraction(1), Fraction(math.comb(q0, v+1), (M-q0)**v))
                cmom = (mu[2]*sum(nt*nt for nt in sizes)/2+Fraction(tau*tau, 2)
                        +Fraction(tau*n, 2)*mu[2]+Fraction(n*n, 8)*mu[4])
                bare = delta+a*epsv*cmom
                weighted = a*epsv*(cmom+coeff*delta)
                au = min(Fraction(1), terms['full_affine'], bare, weighted)
                options.append({'v': v, 'lambda': encode(lam), 'mu2': encode(mu[2]), 'mu4': encode(mu[4]),
                                'delta_src': encode(delta), 'C_mom': encode(cmom),
                                'bare_tail_bound': encode(bare), 'weighted_tail_bound': encode(weighted),
                                'AU_bound': encode(au)})
            chosen = min(options, key=lambda x: (fraction(x['AU_bound']), x['v']))
            terms_new = dict(terms)
            terms_new['simulation'] = simulation
            terms_new['full_affine'] = fraction(chosen['AU_bound'])
            total = min(Fraction(1), sum(terms_new.values(), Fraction(0)))
            before = fraction(oldrow['additive_error_bound'])
            threshold_only = fraction(prior['new_additive_error_bound'])
            require(total <= threshold_only <= before, 'all-event total improves')
            for k in terms:
                if k not in ('simulation', 'full_affine'):
                    require(terms_new[k] == fraction(oldrow['terms'][k]), 'retained term: '+k)
            svis = min(n*U, 2*anchor)
            private_ic = 3*anchor+r*svis
            pfinal = q0+private_ic
            pold = oldrow['resources']['P_full_role_bound']
            require(pfinal <= q0+(2*r+3)*anchor <= pold, 'same filtered-final algorithm bounds')
            dominant = max(terms_new, key=terms_new.get)
            rows.append({
                'name': name, 'case': case, 'budgets': prior['budgets'],
                'old_additive_error_bound': encode(before),
                'threshold_only_additive_error_bound': encode(threshold_only),
                'new_additive_error_bound': encode(total), 'improvement_factor': encode(before/total),
                'terms_new': {k: encode(v) for k, v in terms_new.items()},
                'dominant_term': dominant,
                'CMA': {'H_self': hself, 'Q_linear_coefficient': hself+v0,
                        'C_cross_upper': av*J, 'q_inverse_upper': a, 'q_forward_upper': q0,
                        'new_linear': encode(linear), 'cross_input': encode(cross_input),
                        'fresh_forward_output': encode(forward_output),
                        'unchanged_quadratic': encode(unchanged_quadratic),
                        'multiplicity_tails': encode(tails), 'unclipped_refined_hide': encode(refined),
                        'selected_hide': encode(hide),
                        'program': encode(sub['program']), 'grinding_tail_upper': encode(sub['tail_dyadic_upper'])},
                'AU_options': options, 'chosen_prefix_v': chosen['v'],
                'B_final_resources': {'q0': q0, 'q_anchor': anchor, 'visible_seed_cap': svis,
                                      'additional_private_IC_bound': private_ic, 'P_full_bound': pfinal,
                                      'old_eager_P_full_bound': pold, 'old_over_new_P_ratio': encode(Fraction(pold, pfinal)),
                                      'selected_forest_materializations_upper': 1, 'H2_relation_checks_upper': 1,
                                      'Hs_distinct_key_checks_upper': a,
                                      'H2_VH_seed_iteration_upper': n*U,
                                      'CPU_and_memory_are_additional_not_replaced_by_P': True},
                'Rain_OWF_advantage': None, 'complete_signature_security_bits': None,
            })
            table.append(f"| {name} | {case} | {encode(before)['log2_display']:.6f} | "
                         f"{encode(total)['log2_display']:.6f} | {float(before/total):.6f} | "
                         f"{pold} / {pfinal} | {dominant} |")
            counts['budget_rows'] += 1
            tick()
        require(len(rows) == 24, 'six sets by four fixed budgets')
        result['budget_rows'] = rows
        result['all_checks_passed'] = True
        with (out/'完整新界表.md').open('x', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(table)+'\n')
    except Exception as exc:
        result['error'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        result['counts'] = counts
        result['body_wall_seconds'] = time.perf_counter()-started
        result['process_cpu_seconds'] = time.process_time()-cpu
        result['peak_working_set_bytes'] = peak()
        result['processor_affinity_mask'] = affinity
        result['finished_utc'] = datetime.now(timezone.utc).isoformat()
        with (out/'result.json').open('x', encoding='utf-8', newline='\n') as f:
            f.write(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'run': str(out), 'passed': True, 'counts': counts,
                      'body_wall_seconds': result['body_wall_seconds'],
                      'peak_working_set_bytes': result['peak_working_set_bytes']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
