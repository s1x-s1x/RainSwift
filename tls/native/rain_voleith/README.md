# native/rain_voleith: the signature library for the hybrid TLS harness

A C interface (`rain_voleith_tls.h`) over the Rain-VOLEitH signature code, built as a Windows DLL,
`rain_voleith_tls.dll`, and loaded by `tls/pq/rain_voleith.py` through ctypes. It exports the six
Rain sets.

## What is here

| File | Role |
|---|---|
| `rain_voleith_tls.h` | the interface: ABI version, processor check, parameter sets and sizes, keygen, detached sign and verify |
| `rain_voleith_tls_impl.hpp` | the interface over `faest_scheme<P>`; supplies `rand_bytes`, checks lengths, wipes outputs when the random source fails |
| `rain_voleith_tls.cpp` | the parameter-set table |
| `rain_voleith_platform.c` | `BCryptGenRandom` / `getrandom`, and the CPUID check, compiled for the x86-64 baseline |
| `win_aligned_alloc.hpp` | Windows only: maps the library's `aligned_alloc`/`free` pair onto `_aligned_malloc`/`_aligned_free` |
| `xkcp_config/config.h` | XKCP configuration, as in the signature source's meson package files |
| `build.py` | the build |

The signature source itself is not copied here: `--rain-src` is the `src/` directory of this
repository, and `--xkcp-src` is XKCP at the revision pinned in `src/subprojects/xkcp.wrap`
(`64404beeeb261b08a1076fe2f076e4e28dd9b040`).

## Build (Windows, MSYS2 UCRT64 GCC)

From the `tls/` directory:

```
python native/rain_voleith/build.py --gcc-bin C:/msys64/ucrt64/bin ^
    --rain-src ../src --xkcp-src <XKCP> --out build/native-rain
copy build\native-rain\rain_voleith_tls.dll build\
```

`--test-hooks` builds `rain_voleith_tls_test.dll` instead, which additionally exports a
deterministic random source (the splitmix64 stream of the KAT generator), a scripted one (exactly
the given bytes), a switch that makes the OS source fail, and public-key derivation from a secret
key. The test build is for the known-answer gate only; the production DLL does not contain these
functions.

Options follow the release build used for the published measurements (`-O3 -DNDEBUG`,
`RAIN_SHRUNK_KEYSPACE=0`), with the instruction set pinned to x86-64-v3 plus AES-NI and PCLMULQDQ.
The library units are archived and the DLL links the archive, as the meson build does. Three
platform adaptations, none of which edits a source file:

* `win_aligned_alloc.hpp` (above);
* XKCP's one-state Keccak-p uses the portable `plain-64bits/u6` C code, because XKCP's AVX2
  assembly is written for ELF and the System V calling convention (the four-way and two-way
  permutations are intrinsics and are used as they are);
* `rand_bytes` comes from `rain_voleith_tls_impl.hpp`, not from the library's `randomness_os.c`.

GCC cannot guarantee 32-byte stack alignment on 64-bit Windows (GCC bug 54412), so the build
passes `-Wa,-muse-unaligned-vector-move`; libgcc, libstdc++ and winpthread are linked statically,
so the DLL imports system DLLs only. `--toolchain zig` (zig 0.13) also builds a working DLL, but
one that additionally exports the 25 `_Unwind_*`/`unw_*` functions of zig's bundled libunwind.

## Interface in one paragraph

Every call returns `RAIN_TLS_OK` (0) or a negative code. Look parameter sets up by name
(`rain_tls_set_name`): the library exports `rain3-fast`, `rain3-bal`, `rain3-short`,
`rain4-fast`, `rain4-bal` and `rain4-short`. Keys are 32 bytes; signatures have the fixed lengths
`rain_tls_set_sizes` reports. `rain_tls_sign` and `rain_tls_verify` take detached signatures and
run `crypto_sign` / `crypto_sign_open` underneath. Call `rain_tls_cpu_supported()` first.
