#!/usr/bin/env python3
"""Render the independent lifecycle audit's CSV as standalone shareable plots.

Whiskers show observation IQR, not uncertainty intervals. The audit must PASS.
No cryptographic code is imported. Requires matplotlib; fresh output only.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();source=args.audit.resolve()
    checked=json.loads((source/'audit.json').read_text())
    if checked['status']!='PASS' or checked['signatures_charged']!=80:raise ValueError('completed audited lifecycle required')
    with (source/'lifecycle.csv').open(encoding='utf-8') as stream:rows=list(csv.DictReader(stream))
    if len(rows)!=14:raise ValueError('seven phases and two variants required')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size':10,'svg.fonttype':'none','pdf.fonttype':42})
    phases=['keygen','cache_build','cache_load','sign_uncached','sign_cached','sign_cached_selfcheck','verify']
    labels=['Seeded keygen (N=5)','Cache build t12 (N=5)','Cache load t12 (N=100)',
            'Sign, uncached (N=5)','Sign, t12 (N=30)','Sign, t12 + REF selfcheck (N=5)',
            'Verify (N=100 batches of 100)']
    fig,(left,right)=plt.subplots(1,2,figsize=(12.7,5.6),sharey=True,gridspec_kw={'width_ratios':[1.5,1]})
    for index,(variant,label,color) in enumerate([('wots0-fors0','Original AVX2 policy','#2563eb'),
                                               ('wots2-fors1','Adaptive + FORS x8','#d97706')]):
        selected=[next(row for row in rows if row['phase']==phase and row['variant']==variant) for phase in phases]
        y=[i+(-.1 if index==0 else .1) for i in range(7)]
        med=[float(row['median_ms']) for row in selected]
        err=[[float(row['median_ms'])-float(row['q1_ms']) for row in selected],
             [float(row['q3_ms'])-float(row['median_ms']) for row in selected]]
        left.errorbar(med,y,xerr=err,fmt='o' if index==0 else 's',capsize=3,color=color,label=label)
    left.set_xscale('log');left.set_xlabel('Median native-call latency (ms, log scale)')
    left.set_yticks(range(7),labels);left.invert_yaxis();left.grid(axis='x',alpha=.2)
    ratios=[next(row for row in checked['phases'] if row['phase']==phase)['paired_ratio'] for phase in phases]
    med=[row['median'] for row in ratios]
    right.errorbar(med,list(range(7)),xerr=[[row['median']-row['q1'] for row in ratios],
                   [row['q3']-row['median'] for row in ratios]],fmt='o',color='#15803d',capsize=3)
    right.axvline(1,color='#555555',linestyle='--',linewidth=1)
    right.set_xlabel('Paired speedup: original / new');right.set_xlim(.65,2.85);right.grid(axis='x',alpha=.2)
    for ax in (left,right):ax.spines[['top','right']].set_visible(False)
    fig.suptitle('SM3-128-24 local lifecycle: verification gains and deployment costs',fontsize=14,y=.98)
    fig.text(.5,.91,'One fixed seeded fixture; AVX2; 8 physical cores for computation, one for verification; WSL',ha='center',fontsize=9)
    left.legend(loc='lower right',fontsize=9)
    fig.text(.5,.025,'IQR whiskers are not confidence intervals. Internal ABI excludes message encoding; cache loads are warm.',ha='center',fontsize=9)
    fig.subplots_adjust(left=.28,right=.98,bottom=.14,top=.83,wspace=.15)
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    for extension in ('png','svg','pdf'):fig.savefig(out/('lifecycle.'+extension),dpi=220)
    plt.close(fig)
    manifest={'audit_sha256':sha(source/'audit.json'),'csv_sha256':sha(source/'lifecycle.csv'),
              'script_sha256':sha(Path(__file__)),'files_sha256':{path.name:sha(path) for path in out.iterdir() if path.is_file()}}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')

if __name__=='__main__':main()
