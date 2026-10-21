// The FAEST v2/v3 suite library: eight sets. Interface: faest_suite_tls.h; implementation:
// faest_suite_tls_impl.hpp. The signature code is the faest-arch-opt tree used unchanged.

#define FAEST_SUITE_TLS_BUILDING 1
#include "faest_suite_tls.h"

#include "all.inc"
#include "api.hpp"

namespace faest_suite_tls_table
{

inline const char* const k_set_names[] = {
    "faest3-em-128f", "faest3-em-128s", "faest3-aes-128f", "faest3-aes-128s",
    "faest2-aes-128f", "faest2-aes-128s", "faest2-em-128f", "faest2-em-128s",
};
inline constexpr int k_set_count = sizeof(k_set_names) / sizeof(k_set_names[0]);

template <typename F> int dispatch(int set, F&& f)
{
    switch (set)
    {
    case 0: return f.template operator()<faest::v3::faest_em_128_f>();
    case 1: return f.template operator()<faest::v3::faest_em_128_s>();
    case 2: return f.template operator()<faest::v3::faest_128_f>();
    case 3: return f.template operator()<faest::v3::faest_128_s>();
    case 4: return f.template operator()<faest::v2::faest_128_f>();
    case 5: return f.template operator()<faest::v2::faest_128_s>();
    case 6: return f.template operator()<faest::v2::faest_em_128_f>();
    case 7: return f.template operator()<faest::v2::faest_em_128_s>();
    default: return FAEST_SUITE_TLS_ERR_SET;
    }
}

} // namespace faest_suite_tls_table

#include "faest_suite_tls_impl.hpp"
