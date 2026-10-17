#!/usr/bin/env python3
"""Count actual AES block calls in a fresh instrumented copy, never frozen source.

Reuses successful R4 base objects and Zig's runtime cache. Six fixed correctness
cases only; one compile/link/run sequence with a 120-second total timeout.
"""
from __future__ import annotations
import argparse
import datetime as dt
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--base-build",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    a=ap.parse_args()
    q4=Path(__file__).resolve().parents[2]
    src=q4.parent/"源码"/"rain-voleith"
    out=a.output.resolve()
    if not out.is_relative_to(q4/"原始数据"/"重做00b"):
        raise ValueError("Output outside stage evidence directory")
    out.mkdir(parents=True,exist_ok=False)
    t0=time.monotonic()
    original_hashes={p.relative_to(src).as_posix():sha(p) for p in src.rglob("*") if p.is_file() and "粘贴的" not in p.name}
    meta=json.loads((a.base_build/"run_metadata.json").read_text(encoding="utf-8"))
    if meta["status"]!="PASS" or not meta["source_unchanged"]:
        raise ValueError("Base build must have passed")
    if json.loads((a.base_build/"source_sha256_before.json").read_text(encoding="utf-8"))!=original_hashes:
        raise ValueError("Source diverged from base object build")
    scratch=out/"instrumented_source"
    shutil.copytree(src,scratch,ignore=lambda d,names:[n for n in names if "粘贴的" in n])
    prgs=scratch/"prgs.hpp"
    original=prgs.read_text(encoding="utf-8")
    anchor="""                                const count_t* __restrict__ counters, block_t* __restrict__ ecb_blocks)
    {
"""
    if original.count(anchor)!=1:
        raise ValueError("Instrumentation anchor is not unique")
    changed=original.replace(anchor,anchor+"        q4_count_blocks(num_keys, blocks_per_key, tweaks);\n")
    prgs.write_text(changed,encoding="utf-8")
    (out/"instrumentation.diff").write_text("".join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile="frozen/prgs.hpp",tofile="instrumented/prgs.hpp")),encoding="utf-8")
    hook=out/"counter_hook.hpp"
    hook.write_text(r'''#pragma once
#include <cstddef>
#include <cstdint>
inline std::uint64_t q4_counts[4] = {};
inline std::size_t q4_tau, q4_mink, q4_maxk, q4_nmax;
inline void q4_count_blocks(std::size_t n, std::size_t blocks, const std::uint32_t* tweaks)
{
    for (std::size_t i=0;i<n;i++) {
        const auto tw=tweaks[i];
        if (!tw) q4_counts[0]+=blocks;
        else if (tw >> 31) q4_counts[3]+=blocks;
        else {
            auto tree=tw%q4_tau;
            auto height=tree<q4_nmax?q4_maxk:q4_mink;
            q4_counts[tw/q4_tau==height+1?2:1]+=blocks;
        }
    }
}
''',encoding="utf-8")
    probe=out/"count_calls.cpp"
    probe.write_text(r'''#include <cstdio>
#include <cstring>
#include <vector>
#include "all.inc"
using namespace faest;
template<class P> bool run(const char* name) {
    using CP=P::CONSTS;using VC=CP::VEC_COM;
    q4_tau=P::tau_v;q4_mink=VC::MIN_K;q4_maxk=VC::MAX_K;q4_nmax=VC::NUM_MAX_K;
    uint8_t sk[32],pk[32],rho[16],msg[3]={1,2,3};
    for(unsigned j=0;j<32;j++) sk[j]=j;
    for(unsigned j=0;j<16;j++) rho[j]=j+64;
    if(!faest_pubkey<P>(pk,sk)) return false;
    std::vector<uint8_t> sig(FAEST_SIGNATURE_BYTES<P>);
    std::memset(q4_counts,0,sizeof(q4_counts));
    bool sign=faest_sign<P>(sig.data(),msg,3,sk,rho,16);
    auto N=P::bavc_t::COMMIT_LEAVES,D=P::delta_bits_v,tau=P::tau_v,m=CP::VOLE_COL_STRIDE/16;
    bool s=sign&&q4_counts[0]==tau&&q4_counts[1]==2*(N-tau)&&q4_counts[2]==N&&q4_counts[3]==m*N;
    std::printf("{\"set\":\"%s\",\"phase\":\"Sign\",\"root\":%llu,\"tree\":%llu,\"com\":%llu,\"tape\":%llu,\"pass\":%s}\n",name,(unsigned long long)q4_counts[0],(unsigned long long)q4_counts[1],(unsigned long long)q4_counts[2],(unsigned long long)q4_counts[3],s?"true":"false");
    std::memset(q4_counts,0,sizeof(q4_counts));
    bool ver=faest_verify<P>(sig.data(),msg,3,pk);
    bool v=ver&&q4_counts[0]==0&&q4_counts[1]==2*(N-tau-D)&&q4_counts[2]==N&&q4_counts[3]==m*(N-tau);
    std::printf("{\"set\":\"%s\",\"phase\":\"Verify\",\"root\":%llu,\"tree\":%llu,\"com\":%llu,\"tape\":%llu,\"pass\":%s}\n",name,(unsigned long long)q4_counts[0],(unsigned long long)q4_counts[1],(unsigned long long)q4_counts[2],(unsigned long long)q4_counts[3],v?"true":"false");
    return s&&v;
}
int main(){bool ok=true;
ok&=run<rain_sets::rain3_fast>("rain3_fast");ok&=run<rain_sets::rain3_bal>("rain3_bal");ok&=run<rain_sets::rain3_short>("rain3_short");
ok&=run<rain_sets::rain4_fast>("rain4_fast");ok&=run<rain_sets::rain4_bal>("rain4_bal");ok&=run<rain_sets::rain4_short>("rain4_short");return !ok;}
''',encoding="utf-8")
    template=next(s["argv"] for s in meta["steps"] if s["label"]=="compile r00b_dump.cpp")
    command=[x.replace("-I"+str(src),"-I"+str(scratch)) for x in template[:template.index("-c")]]
    obj=out/"count_calls.o"
    executable=out/"count_calls.exe"
    command += ["-include",str(hook),"-c",str(probe),"-o",str(obj)]
    objects=sorted((a.base_build/"obj").glob("*.o"))
    objects=[p for p in objects if not p.name.startswith("10_")]
    if len(objects)!=10: raise ValueError("Expected ten base objects")
    link=next(s["argv"] for s in meta["steps"] if s["label"]=="link")
    prefix=link[:next(i for i,x in enumerate(link) if x.endswith(".o"))]
    os.environ["ZIG_GLOBAL_CACHE_DIR"]=str(a.base_build/"zig-global-cache")
    os.environ["ZIG_LOCAL_CACHE_DIR"]=str(out/"zig-local-cache")
    result={"start_utc":dt.datetime.now(dt.timezone.utc).isoformat(),"budget_seconds":120,"cases":6,"steps":[],"source_files":len(original_hashes),"reused_objects":{str(p):sha(p) for p in objects}}
    try:
        for label,cmd in [("compile",command),("link",prefix+[str(obj),*map(str,objects),"-o",str(executable)]),("run",[str(executable)])]:
            t=time.monotonic()
            process=subprocess.run(cmd,capture_output=True,timeout=120-(t-t0),cwd=out)
            (out/(label+".stdout.txt")).write_bytes(process.stdout)
            (out/(label+".stderr.txt")).write_bytes(process.stderr)
            result["steps"].append({"label":label,"argv":cmd,"exit_code":process.returncode,"seconds":round(time.monotonic()-t,3)})
            print(label,process.returncode,flush=True)
            if process.returncode: raise RuntimeError(label+" failed")
        counts=[json.loads(x) for x in (out/"run.stdout.txt").read_text().splitlines()]
        result["counts"]=counts
        result["status"]="PASS" if len(counts)==12 and all(x["pass"] for x in counts) else "FAIL"
    except Exception as e:
        result["status"]="FAIL"
        result["error"]=repr(e)
    result["source_unchanged"]=original_hashes=={p.relative_to(src).as_posix():sha(p) for p in src.rglob("*") if p.is_file() and "粘贴的" not in p.name}
    result["elapsed_seconds"]=round(time.monotonic()-t0,3)
    (out/"run_metadata.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("status","source_unchanged","elapsed_seconds")}))
    return int(result["status"]!="PASS" or not result["source_unchanged"])


if __name__=="__main__":raise SystemExit(main())
