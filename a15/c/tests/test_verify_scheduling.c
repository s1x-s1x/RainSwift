/* SPDX-License-Identifier: MIT
 * Deterministic, standalone correctness tests for verification scheduling.
 * No large FORS/XMSS trees or signatures are generated, including pid 3.
 * Compile this translation unit instead of engine.c, with A15_WOTS_SCHEDULE=2.
 * Synthetic signature fragments test recovery equivalence, not valid signing.
 */
#define SLH_TEST_BUILD 1
#ifndef SLH_COUNTERS
#define SLH_COUNTERS 1
#endif
/* Intercept only this private translation unit's calls, after preserving the
 * original declaration with its include guard. The wrapper still executes the
 * real SIMD worker; the engine and the seven logical counters are unchanged.
 * This harness invokes recovery sequentially, so this private counter need
 * not be atomic. It is not included in a production library or timing build. */
#include "../src/sm3x8.h"
static uint64_t observed_x8_calls;
static void counted_sm3x8_final_blocks(const uint32_t seed[8],
                                      const uint8_t blocks[8][64],
                                      uint8_t out[8][16]) {
 observed_x8_calls++;
 a15_sm3x8_final_blocks(seed,blocks,out);
}
#define a15_sm3x8_final_blocks counted_sm3x8_final_blocks
#include "../src/engine.c"
#undef a15_sm3x8_final_blocks
#if A15_WOTS_SCHEDULE != 2
#error This harness requires A15_WOTS_SCHEDULE=2 to test every candidate
#endif

#define CHECK(x) do {if(!(x)){fprintf(stderr,"VERIFY-SCHED FAIL line %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static uint32_t random_state=UINT32_C(0x6a09e667);
static unsigned fors_cases,wots_cases,dispatch_cases,length_cases;
static unsigned adaptive_choices[3];
static unsigned physical_call_checks;
static uint64_t wots_observed_totals[5],fors_observed_total;

static uint32_t next_random(void) {
 random_state^=random_state<<13;random_state^=random_state>>17;
 random_state^=random_state<<5;return random_state;
}
static void fill_random(uint8_t *out,size_t n) {
 for(size_t i=0;i<n;i++)out[i]=(uint8_t)next_random();
}
static void same_counts(const slh_counters *a,const slh_counters *b) {
 CHECK(!memcmp(a,b,sizeof *a));
}
static void reset_measurements(void) {
 slh_counters_reset();observed_x8_calls=0;
}
static void expect_x8_calls(unsigned expected) {
 CHECK(observed_x8_calls==expected);physical_call_checks++;
}
static void setup_work(work *w,int pid,unsigned sample,unsigned type) {
 uint8_t pk[2*N];fill_random(pk,sizeof pk);init_work(w,lookup(pid),NULL,pk);
 put32(w->adrs,sample%w->p->d);
 set_tree(w,sample==0?0:sample==1?UINT64_MAX:
          ((uint64_t)next_random()<<32)|next_random());
 set_type(w,type);put32(w->adrs+20,sample==0?0:sample==1?
                        (1u<<w->p->hp)-1:next_random()&((1u<<w->p->hp)-1));
 /* Each implementation must overwrite stale hash/tree-height/index fields. */
 put32(w->adrs+24,UINT32_C(0xa5a5a5a5));
 put32(w->adrs+28,UINT32_C(0x5a5a5a5a));
}
static void output_guards(const uint8_t *buffer,size_t written,size_t total) {
 CHECK(buffer[0]==0xa5);
 for(size_t i=written+1;i<total;i++)CHECK(buffer[i]==0xa5);
}
static void fors_expected_counts(const work *w,const slh_counters *actual) {
 slh_counters expected={0};expected.f=w->p->k;
 expected.h=(uint64_t)w->p->k*w->p->a;
 expected.compress=expected.f+expected.h;same_counts(&expected,actual);
}
static void compare_fors(work w,const uint8_t *signature,const uint32_t *choices,
                         uint8_t expected[35*N]) {
 uint8_t guarded[35*N+2];slh_counters ref,simd;
 reset_measurements();fors_from_sig_scalar(w,expected,signature,choices);
 slh_counters_get(&ref);fors_expected_counts(&w,&ref);
 expect_x8_calls(0);
 memset(guarded,0xa5,sizeof guarded);reset_measurements();
 fors_from_sig8(w,guarded+1,signature,choices);slh_counters_get(&simd);
 expect_x8_calls(((w.p->k+7)/8)*(w.p->a+1));
 fors_observed_total+=observed_x8_calls;
 CHECK(!memcmp(expected,guarded+1,w.p->k*N));same_counts(&ref,&simd);
 output_guards(guarded,w.p->k*N,sizeof guarded);fors_cases++;
}
static void fors_tests(int pid) {
 const param *p=lookup(pid);size_t bytes=(size_t)p->k*(p->a+1)*N;
 unsigned before=fors_cases;
 for(unsigned sample=0;sample<32;sample++){
  size_t offset=1+(sample%4)*7;
  /* Exact allocation after the final auth node exposes tail overreads to ASan. */
  uint8_t *storage=malloc(bytes+offset),*snapshot=malloc(bytes+offset);
  CHECK(storage&&snapshot);fill_random(storage,bytes+offset);
  uint8_t *signature=storage+offset;memcpy(snapshot,storage,bytes+offset);
  work w;setup_work(&w,pid,sample,3);work original=w;
  uint32_t choices[35],saved_choices[35];uint32_t maximum=(1u<<p->a)-1;
  for(unsigned i=0;i<p->k;i++){
   choices[i]=sample==0?0:sample==1?maximum:sample==2?(i&1?maximum:0):
              sample==3?1u<<(i%p->a):sample==4?maximum^(1u<<(i%p->a)):
              sample==5?((i&1?UINT32_C(0x55555555):UINT32_C(0xaaaaaaaa))&maximum):
              next_random()&maximum;
  }
  memcpy(saved_choices,choices,p->k*sizeof *choices);
  uint8_t expected[35*N],mutated[35*N];compare_fors(w,signature,choices,expected);
  CHECK(!memcmp(&w,&original,sizeof w));
  CHECK(!memcmp(choices,saved_choices,p->k*sizeof *choices));
  CHECK(!memcmp(storage,snapshot,bytes+offset));
  /* Public dispatch is tested without a CUDA device: no GPU path is invoked
   * by FORS recovery. This exercises only the CUDA hybrid's CPU condition. */
  const int backends[]={SLH_BACKEND_REF,SLH_BACKEND_AVX2,SLH_BACKEND_CUDA};
  for(unsigned b=0;b<sizeof backends/sizeof *backends;b++){
   uint8_t actual[35*N+2];slh_counters counted;w.backend=backends[b];
   memset(actual,0xa5,sizeof actual);reset_measurements();
   fors_from_sig(w,actual+1,signature,choices);slh_counters_get(&counted);
   expect_x8_calls(A15_FORS_VERIFY_X8&&wots_simd(w.backend)?
                   ((p->k+7)/8)*(p->a+1):0);
   CHECK(!memcmp(actual+1,expected,p->k*N));fors_expected_counts(&w,&counted);
   output_guards(actual,p->k*N,sizeof actual);dispatch_cases++;
  }
  /* Exercise secret, first-auth and last-auth offsets in first/last trees
   * and on both sides of the SIMD group boundary when k permits it. */
  const unsigned trees[]={0,p->k-1,p->k>8?7:1,p->k>8?8:2};
  for(unsigned mutation=0;mutation<12;mutation++){
   unsigned tree=trees[mutation/3],part=mutation%3;
   size_t position=((size_t)tree*(p->a+1)+(part==0?0:part==1?1:p->a))*N;
   position+=(sample+mutation)%N;signature[position]^=0x80;
   compare_fors(w,signature,choices,mutated);
   for(unsigned i=0;i<p->k;i++){
    int equal=!memcmp(expected+i*N,mutated+i*N,N);
    CHECK(equal==(i!=tree));
   }
   signature[position]^=0x80;
  }
  CHECK(!memcmp(storage,snapshot,bytes+offset));free(snapshot);free(storage);
 }
 printf("FORS pid=%d k=%u a=%u: %u root/counter comparisons; actual x8 calls, choices, absolute addresses, unaligned inputs, tail masks, isolated mutations PASS\n",
        pid,p->k,p->a,fors_cases-before);
}

/* Independent scalar endpoint recovery, followed by one ordered T_len. */
static void wots_scalar(work w,uint8_t node[N],const uint8_t *signature,
                         const uint32_t *values) {
 uint8_t endpoints[MAX_LEN*N];unsigned maximum=(1u<<w.p->lgw)-1;
 for(unsigned j=0;j<w.p->len;j++){
  put32(w.adrs+24,j);chain(&w,endpoints+j*N,signature+j*N,values[j],maximum-values[j]);
 }
 set_type_kp(&w,1);thash(&w,node,endpoints,w.p->len*N,C_T);
}
static void make_digits(const param *p,unsigned sample,uint32_t values[MAX_LEN]) {
 unsigned maximum=(1u<<p->lgw)-1;
 for(unsigned j=0;j<p->len;j++)values[j]=
  sample==0?0:sample==1?maximum:sample==2?(j&1?maximum:0):
  sample==3?j%(maximum+1):sample==4?maximum-j%(maximum+1):
  sample<24?maximum:next_random()%(maximum+1);
 if(sample>=5&&sample<8){
  unsigned j=sample==5?p->len-1:sample==6?0:p->len/2;
  values[j]=sample==5?maximum-1:0;
 }
 if(sample>=8&&sample<16)for(unsigned j=0;j<sample-7;j++)
  values[p->len-1-j]=maximum-1-j%maximum;
 if(sample>=16&&sample<24)for(unsigned j=0;j<sample-15;j++)
  values[(j*9)%p->len]=maximum-1-j%maximum;
}
static void wots_tests(int pid) {
 const param *p=lookup(pid);unsigned maximum=(1u<<p->lgw)-1,before=wots_cases;
 for(unsigned sample=0;sample<64;sample++){
  size_t offset=1+(sample%4)*7,bytes=p->len*N;
  uint8_t *storage=malloc(bytes+offset),*snapshot=malloc(bytes+offset);
  CHECK(storage&&snapshot);fill_random(storage,bytes+offset);
  uint8_t *signature=storage+offset;memcpy(snapshot,storage,bytes+offset);
  work w;setup_work(&w,pid,sample,0);uint32_t values[MAX_LEN],saved[MAX_LEN];
  make_digits(p,sample,values);
  /* The last 16 cases include valid message and checksum digit combinations. */
  if(sample>=48){uint8_t message[N];fill_random(message,sizeof message);wots_digits(&w,values,message);}
  memcpy(saved,values,p->len*sizeof *values);
  unsigned order[MAX_LEN],old_calls,sorted_calls;
  unsigned total=wots_recovery_plan(p,values,order,&old_calls,&sorted_calls);
  unsigned refill_calls=wots_refill_cost(p,values,order,total);
  unsigned selected=refill_calls<sorted_calls?2:sorted_calls<old_calls?1:0;
  const unsigned selected_calls=selected==2?refill_calls:
                                 selected==1?sorted_calls:old_calls;
  /* The adaptive selector must realize the minimum physical worker-call
   * count, including ties; scalar logical F counts alone cannot prove this. */
  CHECK(selected_calls<=old_calls&&selected_calls<=sorted_calls&&
        selected_calls<=refill_calls);
  const unsigned expected_calls[]={old_calls,sorted_calls<old_calls?sorted_calls:old_calls,
                                    refill_calls,selected_calls,selected_calls};
  adaptive_choices[selected]++;
  CHECK(sorted_calls<=old_calls);
  unsigned seen[MAX_LEN]={0},nonzero=0;
  for(unsigned j=0;j<p->len;j++)nonzero+=values[j]<maximum;
  CHECK(total==nonzero);
  for(unsigned j=0;j<total;j++){
   CHECK(order[j]<p->len&&!seen[order[j]]++&&values[order[j]]<maximum);
   if(j)CHECK(values[order[j-1]]<=values[order[j]]);
  }
  uint8_t expected[N];slh_counters ref,formula={0};
  reset_measurements();wots_scalar(w,expected,signature,values);slh_counters_get(&ref);
  expect_x8_calls(0);
  for(unsigned j=0;j<p->len;j++)formula.f+=maximum-values[j];
  formula.t=1;formula.compress=formula.f+(22+p->len*N+9+63)/64;
  same_counts(&ref,&formula);
  for(unsigned implementation=0;implementation<5;implementation++){
   uint8_t guarded[N+2];slh_counters actual;memset(guarded,0xa5,sizeof guarded);
   reset_measurements();
   switch(implementation){
    case 0:wots_from_sig8_legacy(w,guarded+1,signature,values);break;
    case 1:wots_from_sig8_scheduled(w,guarded+1,signature,values);break;
    case 2:wots_from_sig8_refill(w,guarded+1,signature,values,order,total);break;
    case 3:wots_from_sig8_adaptive(w,guarded+1,signature,values);break;
    default:wots_from_sig8(w,guarded+1,signature,values);break;
   }
   slh_counters_get(&actual);expect_x8_calls(expected_calls[implementation]);
   wots_observed_totals[implementation]+=observed_x8_calls;
   CHECK(!memcmp(expected,guarded+1,N));
   same_counts(&ref,&actual);output_guards(guarded,N,sizeof guarded);wots_cases++;
  }
  CHECK(!memcmp(saved,values,p->len*sizeof *values));
  CHECK(!memcmp(storage,snapshot,bytes+offset));free(snapshot);free(storage);
 }
 printf("WOTS pid=%d lgw=%u len=%u: %u scalar/legacy/sorted/refill/adaptive/dispatch root, 7-counter and actual-x8-call comparisons PASS\n",
        pid,p->lgw,p->len,wots_cases-before);
}
static void length_tests(int pid) {
 slh_ctx *ctx=NULL;CHECK(!slh_ctx_new(&ctx,pid,SLH_BACKEND_AVX2));
 const size_t correct=slh_sig_bytes(pid),lengths[]={0,1,15,correct-1,correct+1,SIZE_MAX};
 uint8_t tiny_signature=0,pk[2*N]={0};slh_counters expected={0},actual;
 for(unsigned i=0;i<sizeof lengths/sizeof *lengths;i++){
  /* Deliberately provide only one byte: size rejection must precede a read. */
  reset_measurements();CHECK(slh_verify_internal(ctx,&tiny_signature,lengths[i],NULL,0,pk)==SLH_ERR_VERIFY);
  expect_x8_calls(0);
  slh_counters_get(&actual);same_counts(&actual,&expected);length_cases++;
 }
 slh_ctx_free(ctx);
}
int main(void) {
 if(!a15_sm3_avx2_available()){
  puts("VERIFY-SCHED SKIP: AVX2 CPU/OS support unavailable; no vector worker called");return 0;
 }
 const int pids[]={1,2,3,201};
 for(unsigned i=0;i<sizeof pids/sizeof *pids;i++){
  fors_tests(pids[i]);wots_tests(pids[i]);length_tests(pids[i]);
 }
 CHECK(adaptive_choices[0]&&adaptive_choices[1]&&adaptive_choices[2]);
 printf("Adaptive public-plan branches legacy=%u sorted=%u refill=%u PASS\n",
        adaptive_choices[0],adaptive_choices[1],adaptive_choices[2]);
 printf("Real SIMD worker calls: FORS=%llu WOTS legacy=%llu sorted=%llu refill=%llu adaptive=%llu dispatch=%llu; %u per-invocation prediction checks PASS\n",
        (unsigned long long)fors_observed_total,
        (unsigned long long)wots_observed_totals[0],(unsigned long long)wots_observed_totals[1],
        (unsigned long long)wots_observed_totals[2],(unsigned long long)wots_observed_totals[3],
        (unsigned long long)wots_observed_totals[4],physical_call_checks);
 printf("VERIFY-SCHED PASS: FORS=%u WOTS=%u CPU-dispatch=%u length-rejections=%u; all 7 counters checked; no timing or large-tree generation\n",
        fors_cases,wots_cases,dispatch_cases,length_cases);
 return 0;
}
