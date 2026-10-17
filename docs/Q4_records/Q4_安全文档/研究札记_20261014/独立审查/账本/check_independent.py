"""Independent bounded audit of stage-05 R1. Does not import or run its author code."""
import ctypes
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from fractions import Fraction as F
from pathlib import Path

sys.dont_write_bytecode = True
from independent_formula import SETS, calculate, ceiling_log_two, grinding_limit

HERE = Path(__file__).resolve().parent
Q4 = HERE.parents[2]
MAIN = Q4 / '原始数据/重做05/R1_精确账本/ledger.json'
PRODUCER = Q4 / '脚本/重做05/run_ledger.py'
GATE = Q4 / '原始数据/重做04/review_gate.json'
R6 = Q4 / '原始数据/重做00b/R6_六组AES调用计数/run_metadata.json'
OUTPUT = HERE / 'independent_check.json'
EXPECTED = {
    'main_script': 'e7323c2751660f329deadd6c737522d716e9fc3ec0ac0b14496d71d9340efef3',
    'main_ledger': 'ffe907b341f641a0812d1b14ed988dc72d32f26809013febde502a0b7f4fd92f',
    'review_gate': '6199acf5f4d6b35b2279c4ddff84aa85f2047860fdde40f9b5b9c016d5b7ac88',
    'independent_formula_before_main_read': '71cab2bd9c7686b89fb244718768c6a72b3970ab61b092e9e5c096c39316f268',
}
PROFILES = {'KO20': (20, 0), 'CMA20': (20, 1 << 10),
            'CMA32': (32, 1 << 20), 'CMA48': (48, 1 << 32)}
NAMES = {'hide': 'hide', 'program': 'program', 'tail': 'tail_dyadic_upper',
         'chain': 'chain', 'pair': 'pair', 'late': 'late', 'AU': 'vhash_au',
         'ZHash': 'zhash', 'challenge': 'challenge'}
START = time.perf_counter()
CHECKS = {}
FAILURES = []
PEAK = 0


class PMC(ctypes.Structure):
    _fields_ = [('cb', ctypes.c_ulong), ('PageFaultCount', ctypes.c_ulong),
        ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
        ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t),
        ('PrivateUsage', ctypes.c_size_t)]


def bounded():
    global PEAK
    if time.perf_counter() - START > 120:
        raise TimeoutError('120-second review budget reached')
    if os.name == 'nt':
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
        memory = PMC()
        memory.cb = ctypes.sizeof(memory)
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(memory), memory.cb):
            raise OSError(ctypes.get_last_error())
        PEAK = max(PEAK, memory.PeakWorkingSetSize, memory.PeakPagefileUsage, memory.PrivateUsage)
        if PEAK > 512 * 1024 * 1024:
            raise MemoryError('512-MiB review budget reached')


def require(condition, label, group):
    CHECKS[group] = CHECKS.get(group, 0) + 1
    if not condition:
        FAILURES.append({'group': group, 'label': label})


def equal(left, right, label, group):
    require(left == right, label, group)


def sha(path):
    if '粘贴的' in path.name:
        raise ValueError('excluded filename')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
            bounded()
    return h.hexdigest()


def read_json(path):
    assert '粘贴的' not in path.name
    assert path.stat().st_size < 16 * 1024 * 1024
    return json.loads(path.read_text(encoding='utf-8-sig'))


def f(record):
    return None if record is None else F(int(record['numerator']), int(record['denominator']))


def encode(value):
    if isinstance(value, F):
        return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}
    if isinstance(value, dict):
        return {k: encode(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [encode(v) for v in value]
    return value


def inspect_fraction_records(node, trail='ledger'):
    if isinstance(node, dict):
        if 'numerator' in node and 'denominator' in node:
            value = f(node)
            equal(str(value.numerator), node['numerator'], trail + '.normalized_numerator', 'fraction_encoding')
            equal(str(value.denominator), node['denominator'], trail + '.normalized_denominator', 'fraction_encoding')
            k = node['floor_minus_log2_exact']
            if value == 0:
                equal(k, None, trail + '.zero_floor', 'exact_exponent_floor')
            else:
                require(isinstance(k, int) and F(2) ** k <= 1 / value < F(2) ** (k + 1),
                        trail + '.exact_binary_bracket', 'exact_exponent_floor')
            return
        for key, value in node.items():
            inspect_fraction_records(value, trail + '.' + key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            inspect_fraction_records(value, trail + f'[{index}]')


def base_budget():
    return dict(ac=0, amu=0, a1=0, a2=0, adelta=0, a4=0, as_=0, aic=0, qsig=0)


def main():
    if OUTPUT.exists():
        raise FileExistsError('Evidence exists; use a new version instead of overwriting')
    paths = {'main_script': PRODUCER, 'main_ledger': MAIN, 'review_gate': GATE,
             'independent_formula_before_main_read': HERE / 'independent_formula.py',
             'independent_check_script': Path(__file__).resolve(), 'r6': R6}
    before = {key: sha(path) for key, path in paths.items()}
    for key, expected in EXPECTED.items():
        equal(before[key], expected, key, 'identity')
    gate = read_json(GATE)
    equal(gate['status'], 'PASS', 'gate.status', 'identity')
    equal(gate['unresolved_critical_proof_findings'], 0, 'gate.critical_findings', 'identity')
    equal(gate['review_kind'], 'internal_ai', 'gate.review_kind', 'identity')
    for stage in ('00b', '01', '02', '03', '04'):
        equal(gate['stages'][stage], 'PASS', 'gate.' + stage, 'identity')
    gate_input_hashes = []
    for item in gate['files']:
        path = Q4 / item['path']
        actual = sha(path)
        equal(actual, item['sha256'], item['id'], 'reviewed_files')
        gate_input_hashes.append({'id': item['id'], 'path': str(path), 'sha256': actual})

    ledger = read_json(MAIN)
    equal(ledger['cases_count'], 24, 'case count', 'coverage')
    equal(len(ledger['cases']), 24, 'actual case count', 'coverage')
    equal(set(ledger['profiles']), set(PROFILES), 'profile names', 'coverage')
    seen = {(c['parameter'], c['profile']) for c in ledger['cases']}
    equal(seen, {(s, p) for s in SETS for p in PROFILES}, 'cartesian product', 'coverage')
    equal(ledger['security_target_approved'], False, 'no invented security target', 'interpretation')
    equal(ledger['OWF_default'], 'unknown; no zero assumption', 'OWF default', 'interpretation')
    equal(ledger['qrom_status'], 'OPEN; outside this classical theorem', 'QROM open', 'interpretation')
    equal(ledger['review_gate']['gate_sha256'], before['review_gate'], 'ledger gate identity', 'identity')
    results = []
    params = {p['name']: p for p in ledger['parameters']}
    signature_bytes = dict(zip(SETS, (4146, 3706, 3014, 4112, 4080, 3190)))
    for case in ledger['cases']:
        group = case['parameter'] + '/' + case['profile']
        query_exp, qs = PROFILES[case['profile']]
        bounds = {k: int(v) for k, v in case['adversary_budgets_by_domain'].items()}
        equal(bounds, {k: 1 << query_exp for k in ('c','mu','s','4','1','2','delta','IC')}, group+'.budgets', 'budgets')
        equal(int(case['Q_sig']), qs, group+'.Q_sig', 'budgets')
        own = calculate(case['parameter'], ac=bounds['c'], amu=bounds['mu'], a1=bounds['1'],
                        a2=bounds['2'], adelta=bounds['delta'], a4=bounds['4'], as_=bounds['s'],
                        aic=bounds['IC'], qsig=qs)
        pc, count, sub = own['parameter'], own['counts'], own['subterms']
        aliases = {'R':'R','tau':'tau','g':'g','D':'D','N':'N','r_blk':'r','lambda':'lambda_bits',
                   'b':'b_bits','L1':'L1_bits','L2':'L2_bits','ell':'ell_bits','L':'L_bits'}
        param = params[case['parameter']]
        for k, main_name in aliases.items():
            equal(param[main_name], pc[k], group + '.parameter.' + k, 'parameters')
        equal(sum(param['leaves_per_tree']), pc['N'], group+'.N_total', 'parameters')
        equal(max(param['leaves_per_tree']), pc['N_max'], group+'.N_max', 'parameters')
        equal(sum(param['heights_in_source_order']), pc['D'], group+'.D_height_sum', 'parameters')
        equal(param['signature_bytes'], signature_bytes[case['parameter']], group+'.signature_bytes', 'parameters')
        resources = case['resources']
        for key in ('A_S','A_V_effective','A_V','S0','J0','P','P_H','T'):
            equal(int(resources[key]), count[key], group+'.'+key, 'resource_queries')
        equal(int(resources['M']), pc['M'], group+'.M', 'resource_queries')
        equal(int(resources['rN_a1_extra_tape_calls']), pc['r_blk']*pc['N']*bounds['1'], group+'.eager_tapes', 'resource_queries')
        equal(int(resources['simulator_plus_final_verify_IC_calls']), (qs+1)*count['A_V'], group+'.sim_verify', 'resource_queries')
        equal(int(resources['hiding_per_signature_dummy_calls']), qs*pc['tau'], group+'.dummy', 'resource_queries')
        equal(int(resources['Rain_public_relation_evaluations_as_plus_a2']), count['Rain_checks'], group+'.rain_checks', 'resource_queries')
        equal(int(resources['simulated_grinding_QsigG']), qs*count['G'], group+'.sim_grinding', 'resource_queries')
        h = {key: int(value) for key,value in case['total_RO_budgets_h'].items()}
        equal(h, dict(count['h'], s=bounds['s']), group+'.all_h', 'resource_queries')
        equal(int(resources['B_RO_domain_counts_sum']), sum(h.values()), group+'.RO_sum', 'resource_queries')
        equal(int(resources['B_RO_plus_IC_count_upper_sum']), sum(h.values())+count['P'], group+'.RO_IC_sum', 'resource_queries')
        sums = case['adversary_count_sums']
        rosum = sum(v for k,v in bounds.items() if k!='IC')
        equal(int(sums['seven_RO_domain_upper_bounds_sum']), rosum, group+'.aRO_sum','resource_queries')
        equal(int(sums['RO_plus_IC_query_upper_bounds_sum']), rosum+bounds['IC'], group+'.aRO_IC_sum','resource_queries')
        equal(int(sums['RO_plus_IC_plus_signature_request_upper_bounds_sum']), rosum+bounds['IC']+qs, group+'.aRO_IC_sig_sum','resource_queries')
        grinding = case['grinding']
        raw_G = (1 << pc['g']) * (128 + ceiling_log_two(max(1,qs)))
        requested = raw_G + (-raw_G % 4)
        for key,value in {'G':count['G'],'requested_before_32bit_cap':requested,
                          'ceil_log2_max1_Qsig':ceiling_log_two(max(1,qs)),
                          'tail_exponent_floor':count['tail_exponent']}.items():
            equal(int(grinding[key]), value, group+'.grinding.'+key, 'grinding')
        equal(grinding['active'], qs>0, group+'.grinding.active', 'grinding')
        equal(grinding['capped_by_32bit_capacity'], requested>1<<32, group+'.counter_cap', 'grinding')
        require(count['G']%4==0 and count['G']<=1<<32,group+'.x4_capacity','grinding')
        for own_name,main_name in NAMES.items():
            item = case['C7_terms'][main_name]
            value = own['errors'][own_name]
            raw = own['raw_before_local_clipping'].get(own_name,value)
            equal(f(item['value']),value,group+'.C7.'+main_name,'nine_errors')
            equal(f(item['raw_before_local_cap']),raw,group+'.raw.'+main_name,'nine_errors')
            guard = raw is None
            equal(item['denominator_guard_triggered'],guard,group+'.guard.'+main_name,'saturation')
            equal(item['local_cap_applied'],raw is not None and raw!=value,group+'.local_cap.'+main_name,'saturation')
            equal(item['saturated'],guard or raw>=1,group+'.saturated.'+main_name,'saturation')
        chain_alias = {'collision_c':'coll_c','collision_mu':'coll_mu','late_c':'late_hash_c',
                       'collision_1':'coll_1','late_1':'late_chall1','collision_2':'coll_2','late_2':'late_chall2'}
        for key,main_name in chain_alias.items():
            equal(f(case['subterms']['chain'][main_name]),sub['chain'][key],group+'.chain.'+key,'subterms')
        program = case['subterms']['program']
        equal(f(program['ivpre_and_iv']),sub['program']['iv_pre']+sub['program']['iv'],group+'.program.iv','subterms')
        equal(f(program['chall1_prefix']),sub['program']['h2_prefix'],group+'.program.chi1','subterms')
        equal(f(program['chall2_prefix']),sub['program']['delta_prefix'],group+'.program.chi2','subterms')
        for eps in ('epsilon_V','epsilon_Z'):
            equal(f(case['subterms'][eps]),sum(sub[eps].values(),F(0)),group+'.'+eps,'subterms')
            for k,m in {'uniform':'uniform_output','polynomial':'joint_roots'}.items():
                equal(f(case['subterms'][eps+'_parts'][m]),sub[eps][k],group+'.'+eps+'.'+k,'subterms')
        equal(f(case['unclipped_error_sum_after_required_local_caps']),own['raw_total'],group+'.sum_after_local','totals')
        raw_sum = sum((own['raw_before_local_clipping'].get(k,v) for k,v in own['errors'].items()),F(0))
        equal(f(case['sum_raw_rationals_before_local_caps']),raw_sum,group+'.sum_before_local','totals')
        equal(f(case['error_upper_bound_capped_at_one']),own['capped_total'],group+'.global_cap','totals')
        equal(case['global_error_saturated'],own['raw_total']>=1,group+'.global_saturated','saturation')
        expected_local=[NAMES[k] for k,v in own['errors'].items() if own['raw_before_local_clipping'].get(k,v)>=1]
        equal(case['saturated_components'],expected_local,group+'.saturated_components','saturation')
        equal(f(case['C7_terms'][case['largest_charged_term']]['value']),max(own['errors'].values()),group+'.largest_term','totals')
        equal(case['OWF_advantage_bound'],None,group+'.OWF_unknown','interpretation')
        equal(case['numeric_EUF_CMA_bound_if_OWF_supplied'],None,group+'.no_total_without_OWF','interpretation')
        require('not an attack cost' in case['interpretation'],group+'.error_not_attack_cost','interpretation')
        require('no user-approved' in case['budget_status'],group+'.illustrative_budgets','interpretation')
        equal(case['budget_units']['IC'],'forward and inverse calls combined',group+'.IC_both_directions','interpretation')
        require('all raw grinding' in case['budget_units']['delta'],group+'.raw_grinding','interpretation')
        equal(case['storage_accounting']['full_storage_upper_bound_bytes'],None,group+'.full_memory_unknown','interpretation')
        payload=case['storage_accounting']['payloads_exact_integer_budget_expressions']
        expected_payload = {
            'H1_snapshot_tape_core_bits_a1NL':bounds['1']*pc['N']*pc['L'],
            'H2_affine_matrix_core_bits_a2lambdaL':bounds['2']*128*pc['L'],
            'IC_table_triples_core_bits_3lambdaP':3*128*count['P'],
            'RO_reserved_protocol_output_bits':256*(h['c']+h['mu']+h['s'])+128*(h['4']+h['delta'])+704*h['1']+448*h['2'],
            'simulated_grinding_table_rows':qs*count['G'],
            'simulated_grinding_input_and_output_payload_bits':qs*count['G']*(93*8+128),
            'all_signer_programmed_rows_upper':qs*(count['G']+2),
            'cached_signature_payload_bits':qs*param['signature_bytes']*8,
            'signature_cache_entries_upper':qs,
        }
        equal({k:int(v) for k,v in payload.items()},expected_payload,group+'.storage_payloads','storage')
        results.append({'parameter':case['parameter'],'profile':case['profile'],
                        'independent':own,'strict_error_exponent_floor':case['error_upper_bound_capped_at_one']['floor_minus_log2_exact'],
                        'all_compared':True})
        bounded()
    inspect_fraction_records(ledger)

    native = read_json(R6)
    for record in native['counts']:
        name,phase=record['set'],record['phase']
        own=calculate(name,**base_budget())
        p,c=own['parameter'],own['counts']
        if phase=='Sign':
            expected={'root':p['tau'],'tree':2*(p['N']-p['tau']),'com':p['N'],'tape':p['r_blk']*p['N']}
        else:
            expected={'root':0,'tree':2*(p['N']-p['tau']-p['D']),'com':p['N'],'tape':p['r_blk']*(p['N']-p['tau'])}
        equal({k:record[k] for k in expected},expected,name+'.'+phase,'r6_counts')
        equal(sum(expected.values()),c['A_S' if phase=='Sign' else 'A_V'],name+'.'+phase+'.sum','r6_counts')

    # Independently constructed arithmetic cases, beyond the 24 reported budgets.
    boundary=[]
    for q in (0,1,2,3,4,5,15,16,17,(1<<32)-1,1<<32,(1<<32)+1):
        for g in (0,1,2,5,6,7,8,12,30,32):
            exponent=0
            while 1<<exponent < max(1,q):
                exponent+=1
            raw=(1<<g)*(128+exponent)
            expected=min(1<<32,4*((raw+3)//4))
            equal(grinding_limit(128,g,q),expected,f'q={q},g={g}','independent_cutoff_boundaries')
    for g in range(6):
        for G in (1,2,3,4,7,8,15,16,31,32,63,64):
            true=F((1<<g)-1,1<<g)**G
            upper=F(1,1<<(G//(1<<g)))
            require(true<=upper,f'g={g},G={G}','independent_tail_inequality')
    for name in SETS:
        origin=calculate(name,**base_budget())
        for q in (0,1):
            baseline=calculate(name,**dict(base_budget(),qsig=q,a1=1))
            for which in ('P','T'):
                for relative in (-1,0,1):
                    aic=(1<<128)+relative-baseline['counts'][which]
                    own=calculate(name,**dict(base_budget(),qsig=q,a1=1,aic=aic))
                    equal(own['counts'][which],(1<<128)+relative,f'{name}/{q}/{which}/{relative}','independent_saturation_boundaries')
                    if which=='P':
                        equal(own['raw_before_local_clipping']['pair'] is None,relative>=0,f'{name}/{q}/pair_guard/{relative}','independent_saturation_boundaries')
                        equal(own['raw_before_local_clipping']['late'] is None,relative>=0,f'{name}/{q}/late_guard/{relative}','independent_saturation_boundaries')
                        equal(own['errors']['pair'],F(1),f'{name}/{q}/pair_clip/{relative}','independent_saturation_boundaries')
                        equal(own['errors']['late'],F(1),f'{name}/{q}/late_clip/{relative}','independent_saturation_boundaries')
                    else:
                        equal(own['raw_before_local_clipping']['hide'] is None,q>0 and relative>=0,f'{name}/{q}/hide_guard/{relative}','independent_saturation_boundaries')
                        equal(own['errors']['hide'],F(0 if q==0 else 1),f'{name}/{q}/hide_clip/{relative}','independent_saturation_boundaries')
                    equal(own['capped_total'],F(1),f'{name}/{q}/{which}/total_clip/{relative}','independent_saturation_boundaries')
                    boundary.append({'set':name,'Qsig':q,'at':which,'M_offset':relative,'counts':own['counts'],
                                     'errors':own['errors'],'capped_total':own['capped_total']})
            zero=calculate(name,**dict(base_budget(),aic=1<<128))
            for term in ('hide','program','tail'):
                equal(zero['errors'][term],F(0),name+'.zero_sig.'+term,'independent_no_signature')
    # Higher precision encoded values, not rounded logs, settle the target comparison.
    for case in results:
        require(case['independent']['capped_total']>F(1,1<<128),
                case['parameter']+'/'+case['profile']+'.not_2^-128','interpretation')
    bounded()
    after={key:sha(path) for key,path in paths.items()}
    equal(before,after,'all direct inputs unchanged','identity')
    for item in gate_input_hashes:
        equal(sha(Path(item['path'])),item['sha256'],item['id']+'.unchanged','reviewed_files')
    report={
        'status':'FAIL' if FAILURES else 'PASS',
        'scope':'independent exact arithmetic review of 24 C7 cases; internal AI review, not a new cryptographic proof',
        'formula_source':'00b sections 2/8, formal 02 B0-B9, formal 03 C1-C7; independent_formula.py written before first main ledger inspection',
        'main_code_executed_or_imported':False,
        'checked_at_utc':datetime.now(timezone.utc).isoformat(),
        'input_hashes_before':before,'input_hashes_after':after,'reviewed_gate_files':gate_input_hashes,
        'checks_by_group':CHECKS,'checks_total':sum(CHECKS.values()),'failures':FAILURES,
        'cases':results,'saturation_boundary_cases':boundary,
        'OWF':'unknown; no numeric advantage supplied; not set to zero',
        'qrom':'OPEN; outside the classical theorem',
        'security_claim':'24 illustrative error bounds all exceed 2^-128; this alone is not an attack or a work-factor estimate',
        'resource_usage':{'processes':1,'elapsed_seconds':time.perf_counter()-START,
                          'wall_limit_seconds':120,'memory_limit_bytes':512*1024*1024,
                          'peak_memory_bytes':PEAK,'enforcement':'cooperative bounded checks between cases, hash chunks, and groups'},
    }
    temporary=OUTPUT.with_suffix('.json.tmp')
    with temporary.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(encode(report),stream,ensure_ascii=False,indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    os.replace(temporary,OUTPUT)
    print(json.dumps({'status':report['status'],'checks':report['checks_total'],
                     'failures':FAILURES,'elapsed':report['resource_usage']['elapsed_seconds'],
                     'peak_memory_bytes':PEAK,'output':str(OUTPUT),'output_sha256':sha(OUTPUT)},ensure_ascii=False))
    return 1 if FAILURES else 0


if __name__=='__main__':
    raise SystemExit(main())
