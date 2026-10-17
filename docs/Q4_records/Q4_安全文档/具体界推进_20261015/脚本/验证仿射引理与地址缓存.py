"""Finite algebra checks for new conditional lemmas, not a 128-bit attack test."""
from pathlib import Path
from datetime import datetime, timezone
from itertools import product
from functools import reduce
from operator import xor
from fractions import Fraction
import argparse
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[1]
PRIOR = BASE.parent / '等强核验_rFAEST128_20261015/原始数据/R1/comparison.json'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def xor_all(values):
    return reduce(xor, values, 0)


def process_limits():
    class PMC(ctypes.Structure):
        _fields_ = [('cb', ctypes.c_ulong), ('PageFaultCount', ctypes.c_ulong)] + [
            (s, ctypes.c_size_t) for s in ('PeakWorkingSetSize', 'WorkingSetSize',
            'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage',
            'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage',
            'PagefileUsage', 'PeakPagefileUsage')]
    k = ctypes.windll.kernel32
    k.GetCurrentProcess.restype = ctypes.c_void_p
    h = k.GetCurrentProcess()
    pm, sm = ctypes.c_size_t(), ctypes.c_size_t()
    k.GetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
    k.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    assert k.GetProcessAffinityMask(h, ctypes.byref(pm), ctypes.byref(sm))
    affinity = pm.value & -pm.value
    assert k.SetProcessAffinityMask(h, affinity)
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(PMC), ctypes.c_ulong]

    def peak():
        p = PMC()
        p.cb = ctypes.sizeof(p)
        assert ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(p), p.cb)
        return p.PeakWorkingSetSize
    return affinity, peak


def open_columns(m, beta, c, error, k):
    # Build the actual opened list first, then apply the small-VOLE XOR rule.
    opened = list(m)
    opened[beta] = None
    opened[beta ^ 1] ^= error
    return tuple(xor_all(opened[j] for j in range(len(m))
                         if ((j ^ beta) >> bit) & 1)
                 ^ (c if (beta >> bit) & 1 else 0) for bit in range(k))


def affine_solution(records, k):
    if not records:
        return None
    beta0, q0, _ = records[0]
    if len(records) == 1:
        return 0, q0
    beta1, q1, _ = records[1]
    different = beta0 ^ beta1
    bit = (different & -different).bit_length() - 1
    u = q0[bit] ^ q1[bit]
    v = tuple(q0[h] ^ (u if (beta0 >> h) & 1 else 0) for h in range(k))
    if all(q[h] == v[h] ^ (u if (beta >> h) & 1 else 0)
           for beta, q, _ in records for h in range(k)):
        return u, v
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run-id', required=True)
    args = ap.parse_args()
    if not args.run_id.isascii() or not args.run_id.replace('_', '').replace('-', '').isalnum():
        raise ValueError('simple new run id required')
    out = BASE / '原始数据' / args.run_id
    if out.exists():
        raise FileExistsError(out)
    gate_path = BASE / '原始数据/当前实验门控.json'
    gate = json.loads(gate_path.read_text('utf-8'))
    preflight = subprocess.run([sys.executable, '-X', 'utf8', str(BASE / '管理工具/候选门控.py'),
                               gate['candidate'], 'bounded-check'], capture_output=True, text=True, encoding='utf-8')
    if preflight.returncode:
        raise RuntimeError(preflight.stdout + preflight.stderr)
    affinity, peak = process_limits()
    start, cpu_start = time.perf_counter(), time.process_time()
    started = datetime.now(timezone.utc).isoformat()
    cap = min(gate['per_check_seconds'], gate['remaining_compute_wall_seconds'])
    memory_cap = gate['per_process_memory_bytes']
    counts = {'affine_families': 0, 'accepted_openings': 0, 'empty_families': 0,
              'cross_pair_families': 0, 'single_pair_families': 0, 'column_identities': 0,
              'lane_address_equalities': 0, 'partial_parent_states': 0}
    checks = 0

    def tick():
        if time.perf_counter() - start > cap:
            raise TimeoutError('finite check deadline')
        if datetime.now(timezone.utc) > datetime.fromisoformat(gate['valid_until_utc']):
            raise TimeoutError('UTC deadline')
        if peak() > memory_cap:
            raise MemoryError('finite check memory limit')

    def require(ok, detail):
        nonlocal checks
        checks += 1
        if not ok:
            raise AssertionError(detail)

    out.mkdir(parents=True)
    result = {'scope': 'finite conditional algebra and address checks; no cryptographic strength certificate',
              'script_sha256': sha(Path(__file__)), 'prior_result_sha256': sha(PRIOR),
              'gate_sha256': sha(gate_path), 'started_utc': started,
              'parameter_source': str(PRIOR), 'all_checks_passed': False}
    try:
        # Every injective subset of this projection extends to one representative per image.
        # It suffices to check the maximal passing family: any subset inherits its affine pair.
        for k, width in ((1, 3), (2, 3), (3, 4)):
            n, mask = 1 << k, (1 << width) - 1
            for map_id, upper in enumerate(product(range(1 << (width - 2)), repeat=4)):
                representatives = tuple(h | (upper[h] << 2) for h in range(4))
                m = tuple(((j + 1) * (map_id + 3) ^ (j * j + 5 * map_id)) & mask for j in range(n))
                c = (11 * map_id + 7) & mask
                a = xor_all(m) ^ c
                v = tuple(xor_all(m[j] for j in range(n) if (j >> h) & 1) for h in range(k))
                for b in range(4):
                    for ehash in product(range(4), repeat=k):
                        if counts['affine_families'] % 256 == 0:
                            tick()
                        records = []
                        uhat = (a & 3) ^ b
                        vhat = tuple((v[h] & 3) ^ ehash[h] for h in range(k))
                        for beta in range(n):
                            if any(ehash[h] != (b if (beta >> h) & 1 else 0) for h in range(1, k)):
                                continue
                            error = representatives[ehash[0] ^ (b if beta & 1 else 0)]
                            q = open_columns(m, beta, c, error, k)
                            for h in range(k):
                                expected = v[h] ^ (a if (beta >> h) & 1 else 0) ^ (error if h == 0 else 0)
                                require(q[h] == expected, ('column identity', k, map_id, beta, h))
                                require((q[h] & 3) == (vhat[h] ^ (uhat if (beta >> h) & 1 else 0)), 'VH')
                                counts['column_identities'] += 1
                            records.append((beta, q, error))
                        answer = affine_solution(records, k)
                        require(answer is not False, ('missing affine pair', k, map_id, b, ehash, records))
                        counts['affine_families'] += 1
                        counts['accepted_openings'] += len(records)
                        if not records:
                            counts['empty_families'] += 1
                        elif len({r[0] >> 1 for r in records}) > 1:
                            counts['cross_pair_families'] += 1
                            require(answer[0] == a, 'cross-pair common u')
                        else:
                            counts['single_pair_families'] += 1
                            if len(records) == 2:
                                require(answer[0] == a ^ records[0][2] ^ records[1][2], 'single-pair common u')

        # Negative example: zero and a nonzero kernel error have the same VHash.
        m, c, k, z = (3, 5, 6, 1), 7, 2, 4
        a = xor_all(m) ^ c
        v = tuple(xor_all(m[j] for j in range(4) if (j >> h) & 1) for h in range(k))
        bad_records = [(beta, open_columns(m, beta, c, err, k), err)
                       for beta, err in ((0, 0), (1, 0), (2, z))]
        require(all((q[h] & 3) == ((v[h] ^ (a if (beta >> h) & 1 else 0)) & 3)
                    for beta, q, _ in bad_records for h in range(k)), 'negative VH accepted')
        require(affine_solution(bad_records, k) is False, 'negative example must be nonaffine')
        result['three_hole_counterexample'] = {'m': m, 'c': c, 'kernel_error': z, 'records': bad_records,
            'all_VH_checks_pass': True, 'common_affine_pair_exists': False,
            'scope': 'conditional legal-copath tape model, not a sampled AES attack or complete signature forgery'}

        partial_examples = []
        for size in (4, 8, 16, 32):
            for first in range(size):
                remaining = tuple(x for x in range(size) if x != first)
                for target in remaining:
                    require(sum(x == target for x in remaining) == 1, 'partial parent target')
                    counts['partial_parent_states'] += 1
            exact = Fraction(1, size - 1)
            partial_examples.append({'M': size, 'probability': str(exact), 'larger_than_M_inverse_squared': exact > Fraction(1, size * size)})
        result['partial_parent'] = partial_examples

        wordmask = (1 << 32) - 1
        def add4(x, y):
            return tuple((a + b) & wordmask for a, b in zip(x, y))
        ivs = ((0, 0, 0, 0), (wordmask, wordmask, wordmask, wordmask),
               (wordmask - 3, 17, 31, wordmask - 13), (123, 456, 789, 0x80000000))
        params = json.loads(PRIOR.read_text('utf-8'))['parameters']
        table = []
        for p in params:
            tau, r = p['tau'], p['tape_AES_blocks']
            heights = sorted({p['k_low'] for _ in range(bool(p['n_low']))} |
                             {p['k_high'] for _ in range(bool(p['n_high']))})
            for height, iv, t, counter in product(heights, ivs, range(tau), range(r)):
                xcom = add4(iv, (0, 0, 0, (height + 1) * tau + t))
                derived = add4(xcom, (counter, 0, 0, (1 << 31) - (height + 1) * tau))
                direct = add4(iv, (counter, 0, 0, (1 << 31) + t))
                require(derived == direct, ('tape address cache identity', p['name'], height, t, counter))
                counts['lane_address_equalities'] += 1
            table.append({'name': p['name'], 'r': r, 'distinct_heights': len(heights),
                          'old_extra_IC_per_H1_upper': r * p['N_total'],
                          'new_extra_IC_per_source_anchor_upper': r * len(heights),
                          'scope': 'coefficients multiply different query counts; not a runtime ratio'})
        result['cache_coefficients'] = table
        tick()
        result['all_checks_passed'] = True
    except Exception as e:
        result['error'] = {'type': type(e).__name__, 'message': str(e)}
        raise
    finally:
        result['counts'] = counts
        result['assertions'] = checks
        result['resources'] = {'body_wall_seconds': time.perf_counter() - start,
            'process_cpu_seconds': time.process_time() - cpu_start,
            'peak_working_set_bytes': peak(), 'affinity_mask': affinity,
            'per_check_wall_cap_seconds': cap, 'memory_cap_bytes': memory_cap,
            'measure_scope': 'body after preflight and affinity; excludes launcher/serialization'}
        result['finished_utc'] = datetime.now(timezone.utc).isoformat()
        temp = out / 'result.json.tmp'
        temp.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        os.replace(temp, out / 'result.json')
    print(json.dumps({'status': 'PASS', 'result': str(out / 'result.json'), 'counts': counts,
                      'assertions': checks, 'resources': result['resources']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
