// Evidence adapter only: the frozen Rain source is included read-only.
// No signing/KeyGen/private-key routine is called or exported.
// Hash outputs are supplied by the caller's classical random-oracle table.
// The x4 adapter is used only by verification, never by grind_and_open (whose
// source implementation memcpy-copies its original POD hash state).
#include <array>
#include <vector>
#include <cstdint>
#include <cstring>
#include "hash.hpp"

using q4_ro_callback = int (*)(const uint8_t*, size_t, uint8_t*, size_t);
static q4_ro_callback current_ro = nullptr;

namespace faest {
struct q4_hash_state {
    std::vector<uint8_t> bytes;
    int init(secpar) { bytes.clear(); return 0; }
    int update(const void* p, size_t n) {
        if (n) bytes.insert(bytes.end(), (const uint8_t*)p, (const uint8_t*)p+n);
        return 0;
    }
    int update_byte(uint8_t b) { bytes.push_back(b); return 0; }
    int finalize(void* digest, size_t n) {
        return current_ro(bytes.data(), bytes.size(), (uint8_t*)digest, n);
    }
};
struct q4_hash_state_x4 {
    std::array<q4_hash_state, 4> states;
    void init(secpar s) { for (auto& h : states) h.init(s); }
    void update(const void** data, size_t n) {
        for (size_t i=0; i<4; ++i) states[i].update(data[i],n);
    }
    void update_4(const void* a,const void* b,const void* c,const void* d,size_t n) {
        const void* p[4]={a,b,c,d}; update(p,n);
    }
    void update_1(const void* data,size_t n) { for(auto& h:states) h.update(data,n); }
    void update_1_byte(uint8_t b) { for(auto& h:states) h.update_byte(b); }
    void init_prefix(secpar s,const uint8_t p) {init(s);update_1_byte(p);}
    void finalize(void** out,size_t n) {for(size_t i=0;i<4;++i) states[i].finalize(out[i],n);}
    void finalize_4(void* a,void* b,void* c,void* d,size_t n) {
        void* p[4]={a,b,c,d};finalize(p,n);
    }
};
}

#define hash_state q4_hash_state
#define hash_state_x4 q4_hash_state_x4
#include "all.inc"
#undef hash_state_x4
#undef hash_state

using namespace faest;

template<class P>
static int sizes(size_t* out) {
    using C=typename P::CONSTS; using O=typename P::OWF_CONSTS;
    size_t x[]={P::tau_v,P::delta_bits_v,O::WITNESS_BITS,C::VOLE_ROWS,
      C::VOLE_COL_BLOCKS*sizeof(vole_block),P::bavc_t::OPEN_SIZE,
      FAEST_SIGNATURE_BYTES<P>,C::VOLE_COMMIT_SIZE,C::VOLE_CHECK::PROOF_BYTES,
      C::QS::PROOF_BYTES,C::VOLE_CHECK::CHALLENGE_BYTES,C::QS::CHALLENGE_BYTES};
    memcpy(out,x,sizeof(x)); return 1;
}

template<class P>
static int evaluate(const uint8_t* pk_packed,const uint8_t* signature,
  const uint8_t* iv_bytes,const uint8_t* chal1,const uint8_t* chal2,
  uint8_t* hcom,uint8_t* h22input,size_t* h22len,uint8_t* btilde) {
    using C=typename P::CONSTS; using O=typename P::OWF_CONSTS;
    constexpr auto S=P::secpar_v;
    const uint8_t* ut=signature+C::VOLE_COMMIT_SIZE;
    const uint8_t* d=ut+C::VOLE_CHECK::PROOF_BYTES;
    const uint8_t* a=d+O::WITNESS_BITS/8;
    const uint8_t* opening=a+C::QS::PROOF_BYTES;
    const uint8_t* delta=opening+P::bavc_t::OPEN_SIZE;
    block128 iv;memcpy(&iv,iv_bytes,16);
    std::array<uint8_t,P::delta_bits_v> db;
    expand_bits_to_bytes(db.data(),P::delta_bits_v,delta);
    auto* q=(vole_block*)aligned_alloc(alignof(vole_block),P::secpar_bits*C::VOLE_COL_BLOCKS*sizeof(vole_block));
    if(!vole_reconstruct<P>(iv,q,db.data(),signature,opening,hcom)){free(q);return 0;}

    q4_hash_state h;
    h.init(S);h.update(chal1,C::VOLE_CHECK::CHALLENGE_BYTES);
    h.update(ut,C::VOLE_CHECK::PROOF_BYTES);
    vole_check_receiver<P>(q,db.data(),chal1,ut,h);
    h.update(d,O::WITNESS_BITS/8);h.update_byte(10);
    *h22len=h.bytes.size();memcpy(h22input,h.bytes.data(),h.bytes.size());

    std::array<vole_block,C::WITNESS_BLOCKS> correction{};
    memcpy(correction.data(),d,O::WITNESS_BITS/8);
    vole_receiver_apply_correction<P>(C::WITNESS_BLOCKS,P::delta_bits_v,correction.data(),q,db.data());
    auto* macs=(block_secpar<S>*)aligned_alloc(alignof(block_secpar<S>),C::VOLE_ROWS_PADDED*sizeof(block_secpar<S>));
    transpose_secpar<S>(q,macs,C::VOLE_COL_STRIDE,C::QUICKSILVER_ROWS_PADDED);
    free(q);
    block_secpar<S> delta_block;memcpy(&delta_block,delta,16);
    public_key<P> pk;faest_unpack_public_key(&pk,pk_packed);
    quicksilver_state<S,true,O::QS_DEGREE> qs(macs,O::OWF_NUM_CONSTRAINTS,delta_block,chal2);
    owf_constraints(&qs,&pk);
    qs.verify(O::WITNESS_BITS,a,btilde);
    free(macs);return 1;
}

#define DISPATCH(CALL) switch(which) {\
 case 0: return CALL(rain_sets::rain3_fast);\
 case 1: return CALL(rain_sets::rain3_bal);\
 case 2: return CALL(rain_sets::rain3_short);\
 case 3: return CALL(rain_sets::rain4_fast);\
 case 4: return CALL(rain_sets::rain4_bal);\
 case 5: return CALL(rain_sets::rain4_short);\
 default: return -1; }

extern "C" __declspec(dllexport) int q4_sizes(int which,size_t* out) {
#define DO(P) sizes<P>(out)
 DISPATCH(DO)
#undef DO
}
extern "C" __declspec(dllexport) int q4_evaluate(int which,const uint8_t* pk,
  const uint8_t* sig,const uint8_t* iv,const uint8_t* c1,const uint8_t* c2,
  uint8_t* hc,uint8_t* in2,size_t* n2,uint8_t* bt,q4_ro_callback cb) {
 current_ro=cb;
#define DO(P) evaluate<P>(pk,sig,iv,c1,c2,hc,in2,n2,bt)
 DISPATCH(DO)
#undef DO
}
extern "C" __declspec(dllexport) int q4_verify(int which,const uint8_t* pk,
  const uint8_t* msg,size_t mlen,const uint8_t* sig,q4_ro_callback cb) {
 current_ro=cb;
#define DO(P) (int)faest_verify<P>(sig,msg,mlen,pk)
 DISPATCH(DO)
#undef DO
}
