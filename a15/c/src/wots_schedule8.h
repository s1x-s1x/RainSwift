/* SPDX-License-Identifier: MIT
 * Public WOTS recovery lengths are bucketed before eight-lane evaluation.
 * This private header is included after the legacy recovery implementation.
 * See docs/VERIFY_OPTIMIZATION_20261004.md for provenance and scope. */
#ifndef A15_WOTS_SCHEDULE8_H
#define A15_WOTS_SCHEDULE8_H

/* For fixed, non-refilled groups of at most eight chains, descending lengths
 * minimize the sum of group maxima. Zero-step chains need no SIMD call.
 * The plan depends only on the public message/checksum digits. */
static unsigned wots_recovery_plan(const param *p,const uint32_t *digits,
                                  unsigned order[MAX_LEN],unsigned *old_calls,
                                  unsigned *new_calls) {
 unsigned bins[16]={0},cursor[16]={0},maximum=(1u<<p->lgw)-1,total=0;
 *old_calls=0;*new_calls=0;
 for(unsigned j=0;j<p->len;j++)bins[maximum-digits[j]]++;
 for(unsigned r=maximum;r>0;r--){cursor[r]=total;total+=bins[r];}
 for(unsigned j=0;j<p->len;j++){
  unsigned r=maximum-digits[j];if(r)order[cursor[r]++]=j;
 }
 for(unsigned first=0;first<p->len;first+=8){
  unsigned top=0,end=first+8;if(end>p->len)end=p->len;
  for(unsigned j=first;j<end;j++){unsigned r=maximum-digits[j];if(r>top)top=r;}
  *old_calls+=top;
 }
 for(unsigned first=0;first<total;first+=8)*new_calls+=maximum-digits[order[first]];
 return total;
}

static void wots_from_sig8_scheduled(work w,uint8_t node[N],const uint8_t *sig,
                                     const uint32_t *digits) {
 unsigned order[MAX_LEN],old_calls,new_calls;
 unsigned total=wots_recovery_plan(w.p,digits,order,&old_calls,&new_calls);
 /* Avoid gather/scatter when the plan cannot reduce vector hash calls. */
 if(new_calls>=old_calls){wots_from_sig8_legacy(w,node,sig,digits);return;}
 const unsigned maximum=(1u<<w.p->lgw)-1;
 uint8_t endpoints[MAX_LEN*N];
 for(unsigned j=0;j<w.p->len;j++)if(digits[j]==maximum)
  memcpy(endpoints+j*N,sig+j*N,N);
 for(unsigned first=0;first<total;first+=8){
  unsigned count=total-first;if(count>8)count=8;
  work lanes[8];uint8_t values[8][N],next[8][N];const uint8_t *inputs[8];
  for(unsigned lane=0;lane<8;lane++){
   unsigned j=order[first+(lane<count?lane:0)];lanes[lane]=w;
   put32(lanes[lane].adrs+24,j);memcpy(values[lane],sig+j*N,N);inputs[lane]=values[lane];
  }
  unsigned rounds=maximum-digits[order[first]];
  for(unsigned step=0;step<rounds;step++){
   unsigned mask=0;
   for(unsigned lane=0;lane<count;lane++){
    unsigned j=order[first+lane];
    if(step<maximum-digits[j]){mask|=1u<<lane;put32(lanes[lane].adrs+28,digits[j]+step);}
   }
   thash8_mask(lanes,next,inputs,N,C_F,mask);
   for(unsigned lane=0;lane<count;lane++)if((mask>>lane)&1u){
    memcpy(values[lane],next[lane],N);
    if(!step)TEST_FAULT(&lanes[lane],3,order[first+lane],values[lane]);
   }
  }
  for(unsigned lane=0;lane<count;lane++)memcpy(endpoints+order[first+lane]*N,values[lane],N);
  a15_secure_zero(values,sizeof values);a15_secure_zero(next,sizeof next);
 }
 /* T_len must absorb endpoints in their ORIGINAL address/chain order. */
 set_type_kp(&w,1);thash(&w,node,endpoints,w.p->len*N,C_T);
 a15_secure_zero(endpoints,sizeof endpoints);
}
#if A15_WOTS_SCHEDULE == 2
/* Longest-processing-time list scheduling predicts the exact number of SIMD
 * rounds for the following refill loop. This is a feasible schedule, not a
 * claim of globally optimal scheduling or constant-time secret-key signing. */
static unsigned wots_refill_cost(const param *p,const uint32_t *digits,
                                 const unsigned *order,unsigned total) {
 unsigned loads[8]={0},maximum=(1u<<p->lgw)-1,result=0;
 for(unsigned j=0;j<total;j++){
  unsigned lane=0;for(unsigned i=1;i<8;i++)if(loads[i]<loads[lane])lane=i;
  loads[lane]+=maximum-digits[order[j]];
 }
 for(unsigned i=0;i<8;i++)if(loads[i]>result)result=loads[i];return result;
}
static void wots_from_sig8_refill(work w,uint8_t node[N],const uint8_t *sig,
                                 const uint32_t *digits,const unsigned *order,
                                 unsigned total) {
 unsigned maximum=(1u<<w.p->lgw)-1,next_chain=0,active=0;
 unsigned ids[8]={0},position[8]={0},left[8]={0};work lanes[8];
 uint8_t values[8][N],next[8][N],endpoints[MAX_LEN*N];const uint8_t *inputs[8];
 for(unsigned j=0;j<w.p->len;j++)if(digits[j]==maximum)memcpy(endpoints+j*N,sig+j*N,N);
 for(unsigned lane=0;lane<8;lane++){lanes[lane]=w;memcpy(values[lane],sig,N);inputs[lane]=values[lane];}
 do {
  for(unsigned lane=0;lane<8;lane++)if(!left[lane]&&next_chain<total){
   unsigned j=order[next_chain++];ids[lane]=j;position[lane]=digits[j];left[lane]=maximum-digits[j];
   put32(lanes[lane].adrs+24,j);memcpy(values[lane],sig+j*N,N);
  }
  active=0;for(unsigned lane=0;lane<8;lane++)if(left[lane]){
   active|=1u<<lane;put32(lanes[lane].adrs+28,position[lane]);
  }
  if(!active)break;
  thash8_mask(lanes,next,inputs,N,C_F,active);
  for(unsigned lane=0;lane<8;lane++)if(left[lane]){
   memcpy(values[lane],next[lane],N);
   if(position[lane]==digits[ids[lane]])TEST_FAULT(&lanes[lane],3,ids[lane],values[lane]);
   position[lane]++;left[lane]--;
   if(!left[lane])memcpy(endpoints+ids[lane]*N,values[lane],N);
  }
 }while(active);
 set_type_kp(&w,1);thash(&w,node,endpoints,w.p->len*N,C_T);
 a15_secure_zero(values,sizeof values);a15_secure_zero(next,sizeof next);
 a15_secure_zero(endpoints,sizeof endpoints);
}
static void wots_from_sig8_adaptive(work w,uint8_t node[N],const uint8_t *sig,
                                   const uint32_t *digits) {
 unsigned order[MAX_LEN],old_calls,sorted_calls;
 unsigned total=wots_recovery_plan(w.p,digits,order,&old_calls,&sorted_calls);
 unsigned refill_calls=wots_refill_cost(w.p,digits,order,total);
 if(refill_calls<sorted_calls){wots_from_sig8_refill(w,node,sig,digits,order,total);return;}
 if(sorted_calls<old_calls){wots_from_sig8_scheduled(w,node,sig,digits);return;}
 wots_from_sig8_legacy(w,node,sig,digits);
}
#endif
#endif
