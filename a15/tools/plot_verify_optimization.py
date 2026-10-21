#!/usr/bin/env python3
"""Export the two verification runs after checking raw evidence and statistics.

Requires matplotlib for rendering; the data checks use only Python's standard
library. Whiskers show IQR across rounds, not confidence intervals. Output must
be a fresh directory. No native library or signature generator is loaded.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics

VARIANTS=['wots0-fors0','wots0-fors1','wots1-fors0','wots1-fors1','wots2-fors0','wots2-fors1']
LABELS=['Original','Original + FORS x8','Fixed order','Fixed order + FORS x8','Adaptive','Adaptive + FORS x8']

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def quartiles(values):
    q1,_,q3=statistics.quantiles(values,n=4,method='inclusive')
    return {'median':statistics.median(values),'q1':q1,'q3':q3}

def checked_data(directory):
    summary=json.loads((directory/'summary.json').read_text(encoding='utf-8'))
    raw=directory/'timing.jsonl'
    if digest(raw)!=summary['raw_sha256']:raise ValueError('raw timing hash differs')
    rows=[json.loads(line) for line in raw.read_text(encoding='utf-8').splitlines()]
    if len(rows)!=summary['rows'] or sum(row['batch'] for row in rows)!=summary['total_verification_calls_measured']:
        raise ValueError('sample/call totals differ')
    indexed={};cases={1:set(),2:set(),3:set()}
    for row in rows:
        key=(row['variant'],row['case_id'],row['round'])
        if key in indexed or row['native_returncode']!=0:raise ValueError('duplicate or rejected timing row')
        if row['ns_per_verify']!=row['elapsed_ns']/row['batch']:raise ValueError('per-call time differs')
        indexed[key]=row['ns_per_verify'];cases[row['pid']].add(row['case_id'])
    rounds=sorted({r['round'] for r in rows})
    result=[]
    for pid in (1,2,3):
        ids=sorted(cases[pid])
        means={(v,r):statistics.mean(indexed[v,c,r] for c in ids) for v in VARIANTS for r in rounds}
        for variant in VARIANTS:
            latency=quartiles([means[variant,r] for r in rounds])
            ratio=quartiles([means['wots0-fors0',r]/means[variant,r] for r in rounds])
            preserved=next(x for x in summary['per_pid'] if x['pid']==pid and x['variant']==variant)
            for expected,actual in ((preserved['round_mean_latency_ns'],latency),(preserved['paired_ratio'],ratio)):
                if any(not math.isclose(expected[k],actual[k],rel_tol=1e-12,abs_tol=1e-12) for k in actual):
                    raise ValueError('recomputed summary differs')
            result.append({'pid':pid,'variant':variant,'distinct_fixture_count':len(ids),
                           **{'latency_'+k+'_us':v/1000 for k,v in latency.items()},
                           **{'paired_ratio_'+k:v for k,v in ratio.items()}})
    return result,{'summary_sha256':digest(directory/'summary.json'),'raw_sha256':digest(raw),
                   'rows':len(rows),'verification_calls':summary['total_verification_calls_measured'],
                   'configuration':summary['configuration']}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,action='append',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if len(args.run)!=2:parser.error('exactly two runs required')
    datasets=[];evidence=[]
    for index,path in enumerate(args.run,1):
        data,manifest=checked_data(path.resolve())
        datasets.append(data);evidence.append({'run':index,**manifest})
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    table=[{'run':index,**row} for index,data in enumerate(datasets,1) for row in data]
    with (out/'ablation.csv').open('x',encoding='utf-8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(table[0]));writer.writeheader();writer.writerows(table)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size':10,'svg.fonttype':'none','pdf.fonttype':42})
    fig,axes=plt.subplots(1,3,figsize=(14,5.8),sharey=True)
    colors=['#2563eb','#d97706']
    for pid,ax in enumerate(axes,1):
        for run,data in enumerate(datasets):
            rows=[x for x in data if x['pid']==pid]
            y=[i+(-.12 if run==0 else .12) for i in range(len(rows))]
            med=[x['paired_ratio_median'] for x in rows]
            err=[[x['paired_ratio_median']-x['paired_ratio_q1'] for x in rows],
                 [x['paired_ratio_q3']-x['paired_ratio_median'] for x in rows]]
            ax.errorbar(med,y,xerr=err,fmt='o' if run==0 else 's',color=colors[run],
                        markersize=5,capsize=3,label=f'Run {run+1}',linewidth=1.3)
        ax.axvline(1,color='#666666',linestyle='--',linewidth=1)
        ax.grid(axis='x',alpha=.2);ax.set_axisbelow(True)
        ax.set_title({1:'SM3-128s (20 signatures)',2:'SM3-128f (20 signatures)',3:'SM3-128-24 (3 signatures)'}[pid])
        ax.set_xlabel('Paired speedup relative to original')
        ax.set_xlim(.75,2.9);ax.set_yticks(range(6),LABELS)
        ax.spines[['top','right']].set_visible(False)
    axes[0].invert_yaxis();axes[1].legend(loc='upper right')
    fig.suptitle('SM3 SLH-DSA complete verification: six-way ablation',fontsize=15,y=.97)
    fig.text(.5,.90,'Two independent release builds; 100 rounds/run, batch 8; AVX2, one CPU, WSL',ha='center')
    fig.text(.5,.025,'Whiskers: round IQR (not confidence intervals). Fixed signatures are repeated; no outliers removed.',ha='center',fontsize=9)
    fig.subplots_adjust(left=.19,right=.98,top=.81,bottom=.14,wspace=.18)
    for extension in ('png','svg','pdf'):
        fig.savefig(out/('verify-ablation.'+extension),dpi=220,metadata={'Creator':'plot_verify_optimization.py'} if extension!='png' else None)
    plt.close(fig)
    files={p.name:digest(p) for p in out.iterdir() if p.is_file()}
    (out/'manifest.json').write_text(json.dumps({'runs':evidence,'files_sha256':files,
             'statistics_recomputed_from_raw':True,'plot_script_sha256':digest(Path(__file__))},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'raw-and-summary-checked','output':str(out),'rows':len(table)}))

if __name__=='__main__':main()
