// The Rain-VOLEitH library: the six Rain sets. Interface: rain_voleith_tls.h; implementation:
// rain_voleith_tls_impl.hpp.

#define RAIN_TLS_BUILDING 1
#include "rain_voleith_tls.h"

#include "all.inc"
#include "api.hpp"

namespace rain_tls_table
{

inline const char* const k_set_names[] = {
    "rain3-fast", "rain3-bal", "rain3-short", "rain4-fast", "rain4-bal", "rain4-short",
};
inline constexpr int k_set_count = sizeof(k_set_names) / sizeof(k_set_names[0]);

template <typename F> int dispatch(int set, F&& f)
{
    switch (set)
    {
    case 0: return f.template operator()<faest::rain_sets::rain3_fast>();
    case 1: return f.template operator()<faest::rain_sets::rain3_bal>();
    case 2: return f.template operator()<faest::rain_sets::rain3_short>();
    case 3: return f.template operator()<faest::rain_sets::rain4_fast>();
    case 4: return f.template operator()<faest::rain_sets::rain4_bal>();
    case 5: return f.template operator()<faest::rain_sets::rain4_short>();
    default: return RAIN_TLS_ERR_SET;
    }
}

} // namespace rain_tls_table

#include "rain_voleith_tls_impl.hpp"
