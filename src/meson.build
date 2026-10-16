project('faest', ['c', 'cpp'],
  version : '0.1.0',
  license : 'MIT',
  default_options : [
    'c_std=c23',
    'cpp_std=c++23',
    'warning_level=3',
    'b_ndebug=false',
    'cpp_args=-march=native -mtune=native -g',
    'c_args=-march=native -mtune=native -g',
  ],
)

# Flags from the old Makefile
#   'mtune=native',
# CFLAGS+=-g -O2 -march=native -mtune=native -std=c11
# CPPFLAGS+=-DHAVE_OPENSSL -DNDEBUG -MMD -MP -MF $*.d
# -pedantic-errors
# -Wall -Wexte
# -Wno-ignored-attributes

# 迭代030 Q2/B1：缩钥开关对所有目标统一生效
add_project_arguments('-DRAIN_SHRUNK_KEYSPACE=' + (get_option('rain_shrunk_keyspace') ? '1' : '0'),
                      language : ['c', 'cpp'])

xkcp = subproject('xkcp').get_variable('xkcp_dep')

randomness_os_dep = declare_dependency(
  link_with : static_library(
    'randomness_os',
    'randomness_os.c',
  ),
  include_directories : '.',
)

faest_include_dirs = include_directories(['.'])
faest_sources = [
  'avx2/aes_impl.cpp',
  'faest.cpp',
  'owf_proof.cpp',
  'polynomials_constants.cpp',
  'sha3/KeccakHashtimes4.c',
  'sha3/KeccakSpongetimes4.c',
  'small_vole.cpp',
  'vector_com.cpp',
  'vole_commit.cpp',
]
faest_lib = static_library('faest',
  faest_sources,
  dependencies : xkcp,
)
faest_dep = declare_dependency(
  link_with : faest_lib,
  include_directories : faest_include_dirs,
  dependencies : xkcp,
)


# 迭代030：不构建上游 Catch2 测试（需要联网下载）。


pymod = import('python')
python = pymod.find_installation('python3', required: true)

all_names = [
  'faest_128f',
  'faest_128s',
  'faest_192f',
  'faest_192s',
  'faest_256f',
  'faest_256s',
  'faest_em_128f',
  'faest_em_128s',
  'faest_em_192f',
  'faest_em_192s',
  'faest_em_256f',
  'faest_em_256s',
]
run_target(
  'prepare_nist',
  command: [
    python,
    [
      join_paths(meson.project_source_root(), 'tools', 'prepare_nist.py'),
      meson.project_source_root(),
      meson.project_build_root(),
      join_paths(meson.project_build_root(), 'submission'),
    ]
    + all_names,
  ],
)

# 迭代030：Rain-VOLEitH 关卡测试
executable('rain_test', 'rain_test.cpp',
  dependencies : [faest_dep],
)

# 迭代030 Q2：交接 v2 的 T1–T8、B1 与约束证明微基准。测试自带 rand_bytes（系统/确定性/脚本三种模式），不链接 randomness_os。
executable('rain_q2_test', 'rain_q2_test.cpp',
  dependencies : [faest_dep],
)

# GitHub release: usage example and quick benchmark (build-only additions; protocol bytes are checked by verify.sh).
executable('sign_demo', 'examples/sign_demo.cpp',
  dependencies : [faest_dep, randomness_os_dep],
)
executable('rain_bench', 'bench/rain_bench.cpp',
  dependencies : [faest_dep, randomness_os_dep],
)
