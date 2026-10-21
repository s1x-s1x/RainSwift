/* SPDX-License-Identifier: MIT
 * Recover independent FORS roots across trees in eight SM3 lanes.
 * Included after thash8_mask; padding lanes are defined but not counted. */
#ifndef A15_FORS_VERIFY8_H
#define A15_FORS_VERIFY8_H
static void fors_from_sig_scalar(work w,uint8_t *roots,const uint8_t *sig,
                                 const uint32_t *choices) {
 for(unsigned i=0;i<w.p->k;i++){
  uint32_t idx=(i<<w.p->a)+choices[i];const uint8_t *s=sig+i*(w.p->a+1)*N;
  put32(w.adrs+24,0);put32(w.adrs+28,idx);thash(&w,roots+i*N,s,N,C_F);s+=N;
  for(unsigned h=0;h<w.p->a;h++){
   put32(w.adrs+24,h+1);put32(w.adrs+28,idx>>(h+1));
   if((choices[i]>>h)&1)hpair(&w,roots+i*N,s,roots+i*N);
   else hpair(&w,roots+i*N,roots+i*N,s);s+=N;
  }
 }
}
static void fors_from_sig8(work w,uint8_t *roots,const uint8_t *sig,
                           const uint32_t *choices) {
 for(unsigned first=0;first<w.p->k;first+=8){
  unsigned count=w.p->k-first;if(count>8)count=8;unsigned mask=(1u<<count)-1;
  work lanes[8];uint8_t nodes[8][N],pairs[8][2*N];const uint8_t *inputs[8];
  uint32_t indices[8];
  for(unsigned lane=0;lane<8;lane++){
   unsigned i=first+(lane<count?lane:0);lanes[lane]=w;
   indices[lane]=(i<<w.p->a)+choices[i];put32(lanes[lane].adrs+24,0);
   put32(lanes[lane].adrs+28,indices[lane]);inputs[lane]=sig+i*(w.p->a+1)*N;
  }
  thash8_mask(lanes,nodes,inputs,N,C_F,mask);
  for(unsigned h=0;h<w.p->a;h++){
   for(unsigned lane=0;lane<8;lane++){
    unsigned i=first+(lane<count?lane:0);const uint8_t *auth=sig+(i*(w.p->a+1)+h+1)*N;
    unsigned right=(choices[i]>>h)&1;
    memcpy(pairs[lane]+(right?N:0),nodes[lane],N);
    memcpy(pairs[lane]+(right?0:N),auth,N);inputs[lane]=pairs[lane];
    put32(lanes[lane].adrs+24,h+1);put32(lanes[lane].adrs+28,indices[lane]>>(h+1));
   }
   thash8_mask(lanes,nodes,inputs,2*N,C_H,mask);
  }
  memcpy(roots+first*N,nodes,count*N);
 }
}
static void fors_from_sig(work w,uint8_t *roots,const uint8_t *sig,
                          const uint32_t *choices) {
#if A15_FORS_VERIFY_X8
 if(w.p->sm3&&wots_simd(w.backend)){fors_from_sig8(w,roots,sig,choices);return;}
#endif
 fors_from_sig_scalar(w,roots,sig,choices);
}
#endif
