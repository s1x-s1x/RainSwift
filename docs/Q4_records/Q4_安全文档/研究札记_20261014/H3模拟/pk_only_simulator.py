#!/usr/bin/env python3
"""Executable pk-only ROM simulator for the frozen six Rain parameter sets.

All algebra/VOLE reconstruction/QuickSilver verification is performed by the
read-only native adapter. The only simulated primitive here is the programmable
classical random oracle. AES stays the frozen implementation in executable tests;
the proof separately uses the ideal-cipher model. No private key or witness enters
this program. Simulated signatures are valid with the returned programmed RO,
not with ordinary unprogrammed SHAKE.
"""
from __future__ import annotations
import argparse,ctypes,hashlib,json,math,secrets,time
from pathlib import Path

HERE=Path(__file__).resolve().parent
SETS=('rain3_fast','rain3_bal','rain3_short','rain4_fast','rain4_bal','rain4_short')
CALLBACK=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t)

class SimulationAbort(Exception):pass

class ReproRNG:
    """Evidence-only deterministic coins, never a deployment RNG."""
    def __init__(self,seed:bytes):self.seed=seed;self.counter=0
    def __call__(self,n):
        self.counter+=1
        return hashlib.shake_256(self.seed+self.counter.to_bytes(8,'little')).digest(n)

class ROM:
    def __init__(self,rng=secrets.token_bytes):
        self.rng=rng;self.table={};self.origin={};self.calls=0;self.programs=0
    def query(self,x:bytes,n:int):
        self.calls+=1
        if x not in self.table:
            self.table[x]=self.rng(n);self.origin[x]='ordinary'
        elif len(self.table[x])<n:
            # A single XOF random tape, including repeated requests at a prefix.
            self.table[x]+=self.rng(n-len(self.table[x]))
        return self.table[x][:n]
    def program_fresh(self,x:bytes,y:bytes,kind:str):
        if x in self.table:raise SimulationAbort('RO programming point already present: '+kind)
        self.table[x]=y;self.origin[x]=kind;self.programs+=1

class Native:
    def __init__(self,path=HERE/'native_build'/'pk_only_native.dll'):
        self.lib=ctypes.CDLL(str(path))
        V=ctypes.c_void_p;Z=ctypes.c_size_t;I=ctypes.c_int
        self.lib.q4_sizes.argtypes=[I,V];self.lib.q4_sizes.restype=I
        self.lib.q4_evaluate.argtypes=[I,V,V,V,V,V,V,V,V,V,CALLBACK];self.lib.q4_evaluate.restype=I
        self.lib.q4_verify.argtypes=[I,V,V,Z,V,CALLBACK];self.lib.q4_verify.restype=I
    def sizes(self,index):
        a=(ctypes.c_size_t*12)();assert self.lib.q4_sizes(index,a)==1
        names=('tau','D','witness_bits','vole_rows','col_bytes','open_size','sig_size','commit_size','ut_size','a_size','c1_size','c2_size')
        return dict(zip(names,list(a)))
    @staticmethod
    def callback(ro):
        errors=[]
        @CALLBACK
        def cb(ptr,n,out,m):
            try:
                answer=ro.query(ctypes.string_at(ptr,n),m)
                ctypes.memmove(out,answer,m);return 0
            except BaseException as exc:
                errors.append(repr(exc));ctypes.memset(out,0,m);return 1
        return cb,errors
    @staticmethod
    def buf(x):return ctypes.create_string_buffer(x,max(1,len(x)))
    def evaluate(self,index,pk,sig,iv,c1,c2,ro):
        cb,errors=self.callback(ro)
        hc=ctypes.create_string_buffer(32);x2=ctypes.create_string_buffer(4096)
        n2=ctypes.c_size_t();bt=ctypes.create_string_buffer(16)
        args=[self.buf(x) for x in (pk,sig,iv,c1,c2)]
        ok=self.lib.q4_evaluate(index,*args,hc,x2,ctypes.byref(n2),bt,cb)
        if errors:raise RuntimeError(errors)
        if ok!=1:raise SimulationAbort('native reconstruction rejected')
        assert n2.value<=4096
        return hc.raw,x2.raw[:n2.value],bt.raw
    def verify(self,index,pk,msg,sig,ro):
        cb,errors=self.callback(ro)
        ok=self.lib.q4_verify(index,self.buf(pk),self.buf(msg),len(msg),self.buf(sig),cb)
        if errors:raise RuntimeError(errors)
        return ok==1

class Simulator:
    def __init__(self,native:Native,index:int,pk:bytes,ro:ROM,rng=secrets.token_bytes,query_bound=1):
        if len(pk)!=32:raise ValueError('Rain-128 public key is 32 bytes')
        self.native,self.index,self.pk,self.ro,self.rng=native,index,pk,ro,rng
        self.p=native.sizes(index);self.cache={};self.records=[]
        self.query_bound=query_bound
    def sign(self,msg:bytes,randomized=True,rho=None):
        p=self.p
        if randomized:
            rho=self.rng(16) if rho is None else rho
            if len(rho)!=16:raise ValueError('randomized API rho is 16 bytes')
        elif rho is not None:raise ValueError('deterministic mode omits rho completely')
        else:rho=b''
        mu=self.ro.query(self.pk+msg+b'\x08',32)
        cachekey=(mu,rho)
        if cachekey in self.cache:return self.cache[cachekey]
        # This draw represents the unqueried secret-prefix H3 answer. No unknown
        # H3 input is programmed. A combined reduction stops at a valid-key query.
        root=self.rng(16);ivpre=self.rng(16)
        if ivpre+b'\x04' in self.ro.table:raise SimulationAbort('H4 iv_pre previously queried')
        iv=self.ro.query(ivpre+b'\x04',16)
        delta=(int.from_bytes(self.rng(16),'little')&((1<<p['D'])-1)).to_bytes(16,'little')
        opening=self.rng(p['open_size']);c=self.rng(p['commit_size'])
        c1=self.rng(p['c1_size']);c2=self.rng(p['c2_size'])
        d=self.rng(p['witness_bits']//8);a=self.rng(p['a_size']);ut=self.rng(p['ut_size'])
        base=c+ut+d+a+opening+delta+ivpre
        provisional=base+bytes(4)
        assert len(provisional)==p['sig_size']
        hc,x2,b=self.native.evaluate(self.index,self.pk,provisional,iv,c1,c2,self.ro)
        x1=mu+hc+c+iv+b'\x09'
        self.ro.program_fresh(x1,c1,'signer-H21')
        self.ro.program_fresh(x2,c2,'signer-H22')
        prefix=c2+b+a
        grind_w=128-p['D'];prob=2.0**(-grind_w)
        # A deterministic polynomial cutoff: union tail <= 2^-128 for at most
        # query_bound fresh signatures, when the cutoff is below the API limit.
        cutoff=min(1<<32,4*((((1<<grind_w)*(128+(max(1,self.query_bound)-1).bit_length()))+3)//4))
        ctr=None
        for j in range(cutoff):
            output=self.rng(16)
            if int.from_bytes(output,'little')>>p['D']==0:
                ctr=j
                self.ro.program_fresh(prefix+j.to_bytes(4,'little')+b'\x0b',delta,'signer-H23-success')
                break
            self.ro.program_fresh(prefix+j.to_bytes(4,'little')+b'\x0b',output,'signer-H23-failed')
        if ctr is None:raise SimulationAbort('strict polynomial grinding cutoff')
        group_end=4*(ctr//4+1)
        for j in range(ctr+1,group_end):
            self.ro.program_fresh(prefix+j.to_bytes(4,'little')+b'\x0b',self.rng(16),'signer-H23-x4-extra')
        sig=base+ctr.to_bytes(4,'little')
        self.cache[cachekey]=sig
        self.records.append({'rho':rho.hex(),'deterministic':not randomized,'mu':mu.hex(),
          'latent_H3_root':root.hex(),'iv_pre':ivpre.hex(),'iv':iv.hex(),'hcom':hc.hex(),
          'chall1':c1.hex(),'chall2':c2.hex(),'btilde':b.hex(),'atilde':a.hex(),
          'delta':delta.hex(),'counter':ctr,'grinding_queries':group_end,'cutoff':cutoff,
          'signature':sig.hex(),'H21_input':x1.hex(),'H22_input':x2.hex()})
        return sig

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();out=args.output.resolve()
    if not out.is_relative_to(HERE):raise ValueError('evidence stays under this research directory')
    out.mkdir(exist_ok=False,parents=True)
    start=time.monotonic();native=Native();results=[];all_checks=[]
    for index,name in enumerate(SETS):
        rng=ReproRNG(b'Q4-pk-only-ROM-evidence-20261014/'+name.encode())
        ro=ROM(rng);pk=rng(32) # Arbitrary public input: no KeyGen or sk exists in this process.
        sim=Simulator(native,index,pk,ro,rng,query_bound=6)
        msg=b'Q4 executable public-key-only simulator / '+name.encode()
        sig=sim.sign(msg,randomized=False)
        checks={'native_frozen_verify_accepts_deterministic':native.verify(index,pk,msg,sig,ro),
          'deterministic_exact_repeat_cached':sim.sign(msg,randomized=False)==sig}
        r1=sim.sign(msg);r2=sim.sign(msg)
        checks['native_frozen_verify_accepts_two_randomized']=all(native.verify(index,pk,msg,s,ro) for s in (r1,r2))
        checks['fresh_randomized_responses_differ']=r1!=r2
        fixedrho=rng(16);f1=sim.sign(msg,True,fixedrho);f2=sim.sign(msg,True,fixedrho)
        checks['exact_mu_rho_duplicate_cached']=f1==f2
        checks['native_frozen_verify_accepts_fixed_rho']=native.verify(index,pk,msg,f1,ro)
        p=sim.p;offs=(0,p['commit_size'],p['commit_size']+p['ut_size'],p['commit_size']+p['ut_size']+p['witness_bits']//8,
          p['commit_size']+p['ut_size']+p['witness_bits']//8+p['a_size'],len(sig)-36,len(sig)-20,len(sig)-4)
        rejected=[]
        for offset in offs:
            altered=bytearray(sig);altered[offset]^=1
            rejected.append(not native.verify(index,pk,msg,bytes(altered),ro))
        checks['eight_field_bit_tampers_rejected']=all(rejected)
        checks['wrong_message_rejected']=not native.verify(index,pk,msg+b'changed',sig,ro)
        checks['all_success_counters_first_success']=all(
          all(int.from_bytes(ro.table[bytes.fromhex(r['chall2']+r['btilde']+r['atilde'])+j.to_bytes(4,'little')+b'\x0b'],'little')>>p['D']!=0 for j in range(r['counter']))
          and int.from_bytes(bytes.fromhex(r['delta']),'little')>>p['D']==0 for r in sim.records)
        checks['all_grinding_tables_include_x4_extra']=all(r['grinding_queries']==4*(r['counter']//4+1) for r in sim.records)
        checks['signature_size_matches_frozen_constants']=all(len(bytes.fromhex(r['signature']))==p['sig_size'] for r in sim.records)
        checks['source_evaluation_H22_input_length']=all(len(bytes.fromhex(r['H22_input']))==88+22+128*22+p['witness_bits']//8+1 for r in sim.records)
        result={'set':name,'pk':pk.hex(),'message':msg.hex(),'parameters':p,'checks':checks,
          'records':sim.records,'RO_rows':len(ro.table),'RO_calls':ro.calls,'RO_programs':ro.programs}
        (out/(name+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        # Save the complete programmed classical-RO state for independent replay.
        (out/(name+'.rom.json')).write_text(json.dumps([{'x':x.hex(),'y':y.hex(),'origin':ro.origin[x]} for x,y in ro.table.items()],separators=(',',':')),encoding='utf-8')
        results.append({k:result[k] for k in ('set','parameters','checks','RO_rows','RO_calls','RO_programs')})
        all_checks.extend(checks.values())
        print(name, sum(checks.values()),'/',len(checks),'checks',f'{time.monotonic()-start:.2f}s',flush=True)
        if time.monotonic()-start>120:raise TimeoutError('finite evidence budget')
    summary={'status':'PASS' if all(all_checks) else 'FAIL','checks':len(all_checks),'passed':sum(all_checks),
      'elapsed_seconds':time.monotonic()-start,'cases':results,
      'scope':'executability and source path/layout only; not statistical indistinguishability or EUF-CMA proof',
      'private_input':'none; each pk is independently sampled 32 bytes, no KeyGen/sign/private witness call'}
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    files=[p for p in out.iterdir() if p.is_file()]
    (out/'SHA256SUMS.txt').write_text('\n'.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name for p in files)+'\n',encoding='utf-8')
    print(json.dumps({k:summary[k] for k in ('status','checks','passed','elapsed_seconds')},ensure_ascii=False))
    return 0 if summary['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
