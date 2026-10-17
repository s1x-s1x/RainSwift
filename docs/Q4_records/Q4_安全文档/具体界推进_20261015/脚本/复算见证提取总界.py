"""Fixed checks for the new witness-only reduction; no security certificate.

Runs finite residual-permutation and linear-lookup checks, then evaluates
specified budgets. OWF advantage stays unknown. Upstream rows are used only
for parameter-level coefficients, not for an EM total-security theorem.
"""
from pathlib import Path
from datetime import datetime, timezone
from fractions import Fraction
from itertools import combinations, permutations, product
from collections import Counter
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
U = 80
KAPPA = UX = UY = 4
BUDGETS = [('KO20',20,0),('CMA20',20,1 << 10),
           ('CMA32',32,1 << 20),('CMA48',48,1 << 32)]
sys.set_int_max_str_digits(30000)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fr(value):
    value = Fraction(value)
    if not value:
        return {'numerator':'0','denominator':'1','log2_display':None,
                'certified_negative_log2_floor':None}
    # Integer proof of floor(log2(denominator/numerator)); handles values > 1.
    k = value.denominator.bit_length() - value.numerator.bit_length()
    def ratio_ge_power(exp):
        return ((value.denominator >= (value.numerator << exp)) if exp >= 0
                else ((value.denominator << -exp) >= value.numerator))
    if not ratio_ge_power(k):
        k -= 1
    assert ratio_ge_power(k) and not ratio_ge_power(k + 1)
    return {'numerator':str(value.numerator),'denominator':str(value.denominator),
            'log2_display': math.log2(value.numerator)-math.log2(value.denominator),
            'certified_negative_log2_floor':k}


def choose2(n):
    return n * (n - 1) // 2


def clipped(x):
    return min(Fraction(1), x)


def canon(p):
    return clipped(Fraction(p * (p - 1) * U * U,
                            (M - p - 1) * (M - p - 2))) if 0 <= p <= M - 3 else Fraction(1)


def late_parent(a1,n,q):
    return clipped(Fraction(a1*n*q*U*U,2*(M-q-1)*(M-q-2))) if 0 <= q <= M-3 else Fraction(1)


def tape(q,tau,r,b):
    d = q + 3*tau + r*(tau-1)
    if d + r - 1 >= M:
        return Fraction(1)
    return clipped(Fraction(M >> b, math.prod(M-d-j for j in range(r))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run-id', required=True)
    args = ap.parse_args()
    if not args.run_id.isascii() or not args.run_id.replace('_','').isalnum():
        raise ValueError('new simple run id required')
    output = BASE / '原始数据' / args.run_id
    if output.exists():
        raise FileExistsError(output)
    gate_path = BASE / '原始数据/当前实验门控.json'
    gate = json.loads(gate_path.read_text('utf-8'))
    preflight = subprocess.run([sys.executable,'-X','utf8',
        str(BASE/'管理工具/候选门控.py'),gate['candidate'],'bounded-check'],
        capture_output=True,text=True,encoding='utf-8')
    if preflight.returncode:
        raise RuntimeError(preflight.stdout+preflight.stderr)
    spec = importlib.util.spec_from_file_location('limits_only',HELPER)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)  # No earlier checks or main functions run.
    affinity,peak = helper.process_limits()
    start,cpu = time.perf_counter(),time.process_time()
    counts={'assertions':0,'residual_sets':0,'ordered_outputs':0,'lookup_cases':0,
            'coefficient_rows':0,'budget_rows':0}
    proofs = [
      BASE/'共享地址/05_全桶语义仿射与见证提取候选.md',
      BASE/'共享地址/04_迟到父节点的整列Genie界.md',
      BASE/'提取资源/03_底层双承诺绑定探索.md',
      BASE/'签名模拟/01_按IC单元耦合的原030无私钥模拟.md',
      BASE/'01_已闭合的保守总界.md',
      BASE/'02_碰撞容忍见证提取与完整总界.md',
      BASE/'签名模拟/04_全桶语义提取的挑战接口审查.md']
    result={'candidate':gate['candidate'],'started_utc':datetime.now(timezone.utc).isoformat(),
            'script_sha256':sha(Path(__file__)),'helper_sha256':sha(HELPER),
            'parameter_source':str(PRIOR),'parameter_sha256':sha(PRIOR),
            'proof_inputs':{str(p):sha(p) for p in proofs},'gate_sha256':sha(gate_path),
            'all_checks_passed':False,
            'scope':'finite identities and exact bound substitution; no attack or security-bit certificate',
            'thresholds':{'bucket_u':U,'kappa':KAPPA,'u_x':UX,'u_y':UY},
            'budgets_are_examples_not_user_selected_key_lifetimes':True}
    def require(ok,label):
        counts['assertions']+=1
        if not ok:
            raise AssertionError(label)
    def tick():
        if time.perf_counter()-start > min(gate['per_check_seconds'],gate['remaining_compute_wall_seconds']):
            raise TimeoutError('bounded-check wall limit')
        if peak() > gate['per_process_memory_bytes']:
            raise MemoryError('bounded-check memory limit')
        if datetime.now(timezone.utc) > datetime.fromisoformat(gate['valid_until_utc']):
            raise TimeoutError('UTC deadline')
    output.mkdir(parents=True)
    try:
        # Conditional on any residual output set, count every ordered fresh r-tuple.
        # Only the last block prefix is constrained, exactly as the tape lemma.
        for lam in (2,3):
            msmall=1 << lam
            for b in range(1,lam):
                for r in (2,3):
                    for mask in range(1 << msmall):
                        remaining=[z for z in range(msmall) if mask >> z & 1]
                        if len(remaining)<r:
                            continue
                        hist=Counter()
                        for seq in permutations(remaining,r):
                            hist[seq[:-1]+(seq[-1] >> (lam-b),)] += 1
                            counts['ordered_outputs']+=1
                        denom=math.prod(len(remaining)-j for j in range(r))
                        require(sum(hist.values())==denom,('residual cardinality',lam,b,r,mask))
                        require(max(hist.values()) <= (1 << (lam-b)),('partial block multiplicity',lam,b,r,mask))
                        require(Fraction(max(hist.values()),denom) <=
                                Fraction(1 << (lam-b),denom), 'tape bound')
                        counts['residual_sets']+=1
                    tick()

        # Exhaustive retrieval-versus-direct-pair comparison for a noninjective linear H.
        for ma,mb,base,target in product(range(16),range(16),range(4),range(2)):
            left=[x for x in range(4) if ma >> x & 1]
            right=[x for x in range(4) if mb >> x & 1]
            expected={base^x^y for x in left for y in right if ((base^x^y)&1)==target}
            index={}
            for y in right:
                index.setdefault(y&1,y)
            found=None
            need=target^(base&1)
            for x in left:
                y=index.get(need^(x&1))
                if y is not None:
                    found=base^x^y
                    break
            require((found is not None)==bool(expected),'linear lookup existence')
            require(found is None or found in expected,'linear lookup witness')
            counts['lookup_cases']+=1
        tick()
        for u in (1,2,80):
            for width in range(u+1):
                # Equal commitments: diagonal adds exactly one only when the bucket is empty.
                require(max(1,width*width)<=u*u,'empty-bucket diagonal bound')
        require(canon(0)==0 and canon(1)==0,'zero pair count')
        require(canon(M-2)==1 and canon(M+2)==1,'canon domain guards')
        require(late_parent(1,1,M-2)==1,'parent domain guard')
        require(tape(M,2,6,48)==1,'tape domain guard')

        parameters=json.loads(PRIOR.read_text('utf-8'))['parameters']
        eps_bucket=clipped(Fraction(M*M,math.factorial(U+1)))
        result['bucket_bound']=fr(eps_bucket)
        coefficients=[]
        coeff_by_name={}
        for p in parameters:
            sizes=[1 << p['k_low']]*p['n_low']+[1 << p['k_high']]*p['n_high']
            require(sum(sizes)==p['N_total'] and len(sizes)==p['tau'],'forest metadata')
            a_sizes=[nt*U for nt in sizes]
            f_sizes=[1+nt*U*U//2 for nt in sizes]
            ae=sum(choose2(n) for n in a_sizes)
            au=choose2(sum(f_sizes))
            require(au==sum(choose2(n) for n in f_sizes)+sum(x*y for x,y in combinations(f_sizes,2)),
                    'same-tree plus cross-tree union')
            cp=U**4*sum((x//2)*(y//2) for x,y in combinations(sizes,2))
            coeff=ae+au
            vc=p['local_coefficients']['V_single']
            eps_v=Fraction(int(vc['numerator']),int(vc['denominator']))
            row={'name':p['name'],'affine_coefficient':coeff,'error_pairs':ae,
                 'all_u_pairs':au,'cross_tape_quadruples':cp,'AU_per_H1':fr(coeff*eps_v),
                 'role_per_source_root':2*p['tape_AES_blocks']**2+10*p['tape_AES_blocks']+6,
                 'scope':'common formula coefficients only; EM source independence not asserted'}
            coefficients.append(row)
            coeff_by_name[p['name']] = (coeff,cp,eps_v)
            counts['coefficient_rows']+=1
        result['coefficients']=coefficients
        for p in parameters:
            if p['name'].startswith('rain'):
                ref='ref_s' if p['name'].endswith('short') else 'ref_f'
                require(coeff_by_name[p['name']][0]*coeff_by_name[p['name']][2]
                        <=coeff_by_name[ref][0]*coeff_by_name[ref][2],('local coefficient comparison',p['name']))

        rows=[]
        for p in parameters:
            if not p['name'].startswith('rain'):
                continue
            tau,g,D=p['tau'],p['g'],p['D']
            r,L,n=p['tape_AES_blocks'],p['L_bits'],p['N_total']
            R=p['constraints']
            av=p['verify_AES']
            role=2*r*r+10*r+6
            coeff,cp,epsv=coeff_by_name[p['name']]
            epsz=Fraction(1,M)+Fraction((R-1)**2,1 << 192)
            for case,exp,Q in BUDGETS:
                a=1 << exp
                G=min(1 << 32,4*((((1 << g)*(128+(Q-1).bit_length() if Q else 128))+3)//4))
                q0=a+(Q+1)*av
                anchor=a+Q*av
                pfull=q0+role*anchor
                e=a  # upper bound min(a1,a2); no claim that all are used
                old_cache_p=q0+min(r*n*e,2*r*anchor)
                hc=a+(Q+1)*(tau+1)
                hmu=h4=h1=h2=a+Q+1
                hd=a+Q*G+1
                chain=Fraction(choose2(hc)+choose2(hmu)+(tau+1)*a*hc,1 << 256)
                chain+=Fraction(choose2(h1)+a*h1,1 << 704)
                chain+=Fraction(choose2(h2)+a*h2,1 << 448)
                J=2*D+(r+2)*tau
                E=D+tau
                F=D+(r+1)*tau
                v0=choose2(tau)+D+tau*choose2(r+1)
                if Q:
                    delta4=Fraction(math.comb(h4,KAPPA+1),M**KAPPA)
                    deltax=Fraction(math.comb(Q,UX+1)*J**(UX+1)*(KAPPA+1)**UX,M**UX)
                    deltay=Fraction(math.comb(Q*F,UY+1),M**UY)
                    hide=clipped(Fraction((UX+UY)*q0+Q*v0,M)
                      +Fraction(q0*Q*E+(KAPPA+1)*choose2(Q)*J*J+choose2(Q*J),M*M)
                      +delta4+deltax+deltay)
                    program=Q*(Fraction(h1,1 << (L*(tau-1)))+
                               Fraction(h2,1 << 704)+Fraction(hd,1 << 448))
                    tail=Fraction(Q,1 << (G//(1 << g)))
                else:
                    delta4=deltax=deltay=hide=program=tail=Fraction(0)
                sim=clipped(hide+program+tail)
                terms={'simulation':sim,'chain':chain,'bucket':eps_bucket,
                       'canonical_binding':canon(q0),
                       'late_parent':late_parent(a,n,q0),
                       'full_affine':a*coeff*epsv,
                       'cross_unknown_tape':a*cp*tape(q0,tau,r,48),
                       'zhash':a*epsz,'challenge':Fraction(2*a+1,M)}
                total=clipped(sum(terms.values(),Fraction(0)))
                conservative=clipped(sim+chain+
                    (clipped(Fraction(q0*(q0-1),2*(M-q0))) if q0<M else Fraction(1))+
                    (clipped(Fraction(a*n*q0,M-q0)) if q0<M else Fraction(1))+
                    a*choose2(tau)*epsv+a*epsz+Fraction(2*a+1,M))
                require(pfull>=q0 and anchor<q0,'resource bounds')
                require(G>0 and G%4==0 and G<=1 << 32,'grinding range')
                require(Q==0 or tail<=Fraction(1,1 << 128),'dyadic tail')
                require(0<=total<=1,'total clipping')
                require(terms['cross_unknown_tape'] <= a*cp*Fraction(1,1 << (L-1)),
                        'tape loss in specified budgets')
                require(total<=conservative,('error comparison on fixed cases',p['name'],case))
                rows.append({'name':p['name'],'case':case,
                    'budgets':{'each_of_seven_RO_domains':a,'attacker_forward_plus_inverse_IC':a,
                               'signing_queries':Q,'G':G},
                    'resources':{'q0':q0,'q_anchor':anchor,'P_full_role_bound':pfull,
                                 'P_full_conservative_cache_bound':old_cache_p,
                                 'canonical_probability_source_bound':q0,
                                 'H2_pair_scan_seed_bound':n*U,
                                 'H1_aggregate_bit_xor_bound':e*n*p['k_high']*L,
                                 'H2_VH_lookup_work_is_additional':True},
                    'terms':{k:fr(v) for k,v in terms.items()},
                    'simulation_subterms':{k:fr(v) for k,v in
                       {'hide':hide,'program':program,'tail_dyadic_upper':tail,
                        'delta4':delta4,'deltax':deltax,'deltay':deltay}.items()},
                    'additive_error_bound':fr(total),'conservative_error_bound':fr(conservative),
                    'wider_Full_supported_canonical_bound_not_an_extra_term':fr(canon(pfull)),
                    'Rain_OWF_advantage':None,
                    'complete_forgery_probability_or_security_bits':None})
                counts['budget_rows']+=1
                tick()
        result['budget_rows']=rows
        result['all_checks_passed']=True
    except Exception as exc:
        result['error']={'type':type(exc).__name__,'message':str(exc)}
        raise
    finally:
        result['counts']=counts
        result['body_wall_seconds']=time.perf_counter()-start
        result['process_cpu_seconds']=time.process_time()-cpu
        result['peak_working_set_bytes']=peak()
        result['processor_affinity_mask']=affinity
        result['finished_utc']=datetime.now(timezone.utc).isoformat()
        (output/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'run':str(output),'passed':True,'counts':counts,
       'body_wall_seconds':result['body_wall_seconds'],
       'peak_working_set_bytes':result['peak_working_set_bytes']},ensure_ascii=False))


if __name__=='__main__':
    main()

