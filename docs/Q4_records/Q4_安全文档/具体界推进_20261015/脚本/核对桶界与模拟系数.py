"""Fixed finite arithmetic/coupling checks; not a protocol parameter search.

This script checks a universal bucket union bound, the conditional affine
coefficient, IC-cell counts, and small probability identities used in coupling.
It does not certify signature security and never searches the real key space.
"""
from pathlib import Path
from datetime import datetime, timezone
from fractions import Fraction
from itertools import combinations, product
import argparse
import hashlib
import importlib.util
import json
import math
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[1]
PRIOR = BASE.parent / '等强核验_rFAEST128_20261015/原始数据/R1/comparison.json'
HELPER = BASE / '脚本/验证仿射引理与地址缓存.py'
M = 1 << 128
# Exact union-bound fractions have at most about 5,000 decimal digits here.
sys.set_int_max_str_digits(10000)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fraction_record(value):
    return {'numerator': str(value.numerator),
            'denominator': str(value.denominator),
            'log2_display': (math.log2(value.numerator) - math.log2(value.denominator))
            if value else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run-id', required=True)
    args = ap.parse_args()
    if not args.run_id.isascii() or not args.run_id.replace('_', '').isalnum():
        raise ValueError('new simple run id required')
    output = BASE / '原始数据' / args.run_id
    if output.exists():
        raise FileExistsError(output)
    gate_path = BASE / '原始数据/当前实验门控.json'
    gate = json.loads(gate_path.read_text('utf-8'))
    preflight = subprocess.run(
        [sys.executable, '-X', 'utf8', str(BASE / '管理工具/候选门控.py'),
         gate['candidate'], 'bounded-check'], capture_output=True,
        text=True, encoding='utf-8')
    if preflight.returncode:
        raise RuntimeError(preflight.stdout + preflight.stderr)
    spec = importlib.util.spec_from_file_location('affine_check_helper', HELPER)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)  # Only process_limits is used; no R1 rerun.
    affinity, peak = helper.process_limits()
    start, cpu_start = time.perf_counter(), time.process_time()
    cap = min(gate['per_check_seconds'], gate['remaining_compute_wall_seconds'])
    memory_cap = gate['per_process_memory_bytes']
    checks = 0
    counts = {'bucket_examples': 0, 'affine_coefficients': 0,
              'IC_count_sets': 0, 'same_key_coupling_states': 0,
              'ordinary_coupling_states': 0, 'symbolic_cell_pairs': 0,
              'direct_label_assignments': 0}
    result = {'scope': 'fixed arithmetic and small coupling identities; not a security certificate',
              'candidate': gate['candidate'], 'script_sha256': sha(Path(__file__)),
              'helper_sha256': sha(HELPER), 'parameter_source': str(PRIOR),
              'prior_sha256': sha(PRIOR), 'gate_sha256': sha(gate_path),
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'all_checks_passed': False}

    def tick():
        if time.perf_counter() - start > cap:
            raise TimeoutError('bounded-check wall limit')
        if datetime.now(timezone.utc) > datetime.fromisoformat(gate['valid_until_utc']):
            raise TimeoutError('UTC deadline')
        if peak() > memory_cap:
            raise MemoryError('bounded-check memory limit')

    def require(condition, explanation):
        nonlocal checks
        checks += 1
        if not condition:
            raise AssertionError(explanation)

    output.mkdir(parents=True)
    try:
        parameters = json.loads(PRIOR.read_text('utf-8'))['parameters']
        # Fixed analytic thresholds, not an optimization or a protocol scan.
        thresholds = (2, 64, 80, 128)
        bucket = []
        for u in thresholds:
            exact_union = Fraction(M * M * math.comb(M, u + 1), M ** (u + 1))
            factorial_bound = Fraction(M * M, math.factorial(u + 1))
            require(exact_union <= factorial_bound, ('factorial upper', u))
            bucket.append({'u': u, 'union_bound_unclipped': fraction_record(exact_union),
                           'factorial_bound_unclipped': fraction_record(factorial_bound),
                           'probability_bound': fraction_record(min(Fraction(1), factorial_bound))})
            counts['bucket_examples'] += 1
            tick()
        result['bucket_bounds'] = bucket

        affine = []
        cell_counts = []
        expected = {'ref_f': (137, 448, 136, 312, 1296),
                    'ref_s': (130, 379, 129, 250, 899),
                    'rain3_fast': (145, 414, 144, 270, 774),
                    'rain3_bal': (139, 378, 138, 240, 614),
                    'rain3_short': (128, 320, 127, 193, 402),
                    'rain4_fast': (141, 406, 140, 266, 779),
                    'rain4_bal': (139, 402, 138, 264, 777),
                    'rain4_short': (128, 331, 127, 204, 479)}
        for p in parameters:
            tau, D, r = p['tau'], p['D'], p['tape_AES_blocks']
            sizes = [1 << p['k_low']] * p['n_low'] + [1 << p['k_high']] * p['n_high']
            require(len(sizes) == tau and sum(sizes) == p['N_total'], ('forest', p['name']))
            vh = p['local_coefficients']['V_single']
            epsilon = Fraction(int(vh['numerator']), int(vh['denominator']))
            for u in thresholds:
                e_sizes = [nt * u for nt in sizes]
                f_sizes = [1 + nt * u * u // 2 for nt in sizes]
                within = sum(math.comb(n, 2) for n in e_sizes)
                cross = sum(x * y for x, y in combinations(f_sizes, 2))
                cross_alt = (sum(f_sizes) ** 2 - sum(x * x for x in f_sizes)) // 2
                require(cross == cross_alt, ('cross-tree identity', p['name'], u))
                coeff = within + cross
                term = coeff * epsilon
                affine.append({'name': p['name'], 'u': u,
                               'within_error_pairs': within, 'cross_u_pairs': cross,
                               'coefficient': coeff, 'AU_per_H1': fraction_record(term),
                               'comparison_scope': 'same conditional G and bucket cap; excludes structural and other losses'})
                counts['affine_coefficients'] += 1
            S = 1 + D + tau
            J = 2 * D + (r + 2) * tau
            E = D + tau
            F = D + (r + 1) * tau
            v0 = math.comb(tau, 2) + D + tau * math.comb(r + 1, 2)
            require((S, J, E, F, v0) == expected[p['name']], ('CMA counts', p['name']))
            require(J == E + F, ('cell partition', p['name']))
            require((r + 3) * (sum(sizes) - tau) - 2 * D + tau == p['verify_AES'],
                    ('verify accounting', p['name']))
            cell_counts.append({'name': p['name'], 'S': S, 'J': J, 'E': E, 'F': F,
                                'v0': v0, 'verify_AES': p['verify_AES'],
                                'role_completion_per_anchor_bound': 2 * r * r + 10 * r + 6,
                                'reference_scope': 'combinatorial structure only; no EM OWF transfer asserted'})
            counts['IC_count_sets'] += 1
            tick()
        result['conditional_affine'] = affine
        result['cell_counts'] = cell_counts

        # Four-point exact rejection coupling, covering every set of used outputs.
        small = tuple(range(4))
        subsets = [frozenset(c) for size in range(5) for c in combinations(small, size)]
        for used in subsets:
            remaining = set(small) - used
            if not remaining:
                continue
            for z in remaining:
                mass = sum(Fraction(1, 4) *
                           (Fraction(1, len(remaining)) if proposal in used else int(proposal == z))
                           for proposal in small)
                require(mass == Fraction(1, len(remaining)), ('protected marginal', used, z))
            counts['same_key_coupling_states'] += 1
            for ordinary_used in subsets:
                if not ordinary_used <= used:
                    continue
                virtual_remaining = set(small) - ordinary_used
                for z in remaining:
                    mass = sum(Fraction(1, len(virtual_remaining)) *
                               (Fraction(1, len(remaining)) if proposal in used else int(proposal == z))
                               for proposal in virtual_remaining)
                    require(mass == Fraction(1, len(remaining)),
                            ('ordinary marginal; symmetric for inverse', ordinary_used, used, z))
                counts['ordinary_coupling_states'] += 1

        # Two symbolic trees, with unique child-label producers and unique raw outputs.
        # Exhaust all values of the variables used by each pair, over a three-element set.
        cells = []
        for obj in range(2):
            prefix = f'o{obj}_'
            edges = ((0, 1), (0, 2), (1, 3), (1, 4), (2, 5))
            for source, child in edges:
                cells.append((prefix + 'L' + str(source), prefix + 'L' + str(child)))
            for source in range(6):
                for output_index in range(2):
                    cells.append((prefix + 'L' + str(source),
                                  prefix + 'Y' + str(source) + '_' + str(output_index)))
        for (ki, yi), (kj, yj) in combinations(cells, 2):
            symbols = sorted({ki, yi, kj, yj})
            index = {s: i for i, s in enumerate(symbols)}
            hits = 0
            total = 3 ** len(symbols)
            for values in product(range(3), repeat=len(symbols)):
                hits += (values[index[ki]] == values[index[kj]] and
                         values[index[yi]] == values[index[yj]])
            target = Fraction(1, 3 if ki == kj else 9)
            require(Fraction(hits, total) == target, ('two-equality rank', (ki, yi), (kj, yj)))
            counts['symbolic_cell_pairs'] += 1
            counts['direct_label_assignments'] += total
            tick()

        result['small_coupling_scope'] = ('exact identities on four-point output sets and '
            'two acyclic symbolic trees; not a test of full adaptive CMA or role coverage')
        result['all_checks_passed'] = True
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        result['assertions'] = checks
        result['counts'] = counts
        result['resources'] = {'body_wall_seconds': time.perf_counter() - start,
                               'process_cpu_seconds': time.process_time() - cpu_start,
                               'peak_working_set_bytes': peak(), 'affinity_mask': affinity,
                               'per_check_wall_cap_seconds': cap,
                               'memory_cap_bytes': memory_cap,
                               'measure_scope': 'body after preflight/affinity; wrapper overhead excluded'}
        result['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (output / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
        print(json.dumps({'output': str(output / 'result.json'),
                          'all_checks_passed': result['all_checks_passed'],
                          'assertions': checks, 'counts': counts,
                          'resources': result['resources']}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
