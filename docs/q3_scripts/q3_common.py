"""迭代030 Q3：构建、窗口调度、汇总共用的固定表与纯函数。

实现编号 1–3 与 P0（迭代028 summarize_baseline_window.py）相同；4–5 为同源码树的 128s 对照；
6–11 为 Rain 六组（Q2 工作副本，B1=0）。窗口与顺序按冻结计划 00_计划与冻结口径.md §4.1。
本模块不启动任何实验。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

FAEST_V3 = "1d8330979cb467c54edac43ffe695da249fa3417"
RFAEST = "7a59c5c18b199bae427bd71d3b9fb5ea3f3b6d97"
LYNXER = "3fd635a52bf26d9159a2d53e0e7246b42accf800"
RAIN_SOURCE = RFAEST + "+iter030-RAIN_PATCHES+Q2(B1=0)"
XKCP_V3 = "eb5244d6b95fb1c434b211bac293093e18aa8fd1"
XKCP_V2 = "64404beeeb261b08a1076fe2f076e4e28dd9b040"

IMPLS = {
    "faest_v3_128f": {"id": 1, "algorithm": "FAEST-v3-EM-128f-opt", "commit": FAEST_V3, "signature_bytes": 4170, "tree": "faest_v3"},
    "rfaest_128f": {"id": 2, "algorithm": "rFAEST-EM-128f", "commit": RFAEST, "signature_bytes": 4980, "tree": "rfaest"},
    "lynxer_128f": {"id": 3, "algorithm": "Lynxer-128f-opt", "commit": LYNXER, "signature_bytes": 3652, "tree": "lynxer"},
    "rfaest_128s": {"id": 4, "algorithm": "rFAEST-EM-128s", "commit": RFAEST, "signature_bytes": 4014, "tree": "rfaest"},
    "faest_v3_128s": {"id": 5, "algorithm": "FAEST-v3-EM-128s-opt", "commit": FAEST_V3, "signature_bytes": 3466, "tree": "faest_v3"},
    "rain3_fast": {"id": 6, "algorithm": "C030-Rain3-fast", "commit": RAIN_SOURCE, "signature_bytes": 4146, "tree": "rain"},
    "rain3_bal": {"id": 7, "algorithm": "C030-Rain3-bal", "commit": RAIN_SOURCE, "signature_bytes": 3706, "tree": "rain"},
    "rain3_short": {"id": 8, "algorithm": "C030-Rain3-short", "commit": RAIN_SOURCE, "signature_bytes": 3014, "tree": "rain"},
    "rain4_fast": {"id": 9, "algorithm": "C030-Rain4-fast", "commit": RAIN_SOURCE, "signature_bytes": 4112, "tree": "rain"},
    "rain4_bal": {"id": 10, "algorithm": "C030-Rain4-bal", "commit": RAIN_SOURCE, "signature_bytes": 4080, "tree": "rain"},
    "rain4_short": {"id": 11, "algorithm": "C030-Rain4-short", "commit": RAIN_SOURCE, "signature_bytes": 3190, "tree": "rain"},
}

# 冻结计划 §4.1 的两个窗口；元组顺序即轮换的基准顺序。
WINDOWS = {
    "F": ("rain3_fast", "rain3_bal", "rain4_fast", "rain4_bal", "faest_v3_128f", "rfaest_128f", "lynxer_128f"),
    "S": ("rain3_short", "rain4_short", "rfaest_128s", "faest_v3_128s"),
}

TREES = {
    "faest_v3": {"source_dir": "faest_v3", "commit": FAEST_V3, "xkcp_commit": XKCP_V3, "vendor_xkcp": False,
                 "test_subdir": 1, "rng": "v3"},
    "rfaest": {"source_dir": "rfaest/rFAEST", "commit": RFAEST, "xkcp_commit": XKCP_V2, "vendor_xkcp": True,
               "test_subdir": 1, "rng": "legacy"},
    "lynxer": {"source_dir": "lynxer/opt", "commit": LYNXER, "xkcp_commit": XKCP_V2, "vendor_xkcp": True,
               "test_subdir": 1, "rng": "legacy"},
    "rain": {"source_dir": "rain_q2", "commit": RAIN_SOURCE, "xkcp_commit": XKCP_V2, "vendor_xkcp": True,
             "test_subdir": 0, "rng": "legacy"},
}
# Rain 树另建的辅助程序（不计时）：Q2 复测与库方式 KAT。
AUX_EXECUTABLES = {"rain_q2_test": "rain", "q3_rain_kat_lib": "rain"}

RAIN_SETS = ("rain3_fast", "rain3_bal", "rain3_short", "rain4_fast", "rain4_bal", "rain4_short")
# 库内每个翻译单元对单个参数集的显式实例化行数（以 v2::faest_em_128_f 为模板逐行替换）。
RAIN_INSTANCE_TUS = {"faest.cpp": 7, "owf_proof.cpp": 2, "small_vole.cpp": 3, "vole_commit.cpp": 2}
RAIN_TEMPLATE_SET = "v2::faest_em_128_f"

BUILD_FLAGS = {"buildtype": "release", "optimization": 3, "ndebug": True, "lto": False,
               "arch": "native", "c_std": "c23", "cpp_std": "c++23"}

API = "crypto_sign_keypair/crypto_sign/crypto_sign_open"
SIGNING = "randomized signed-message public API including OS randomness and message copies"
RNG = "upstream randomness_os; fail-closed source wrapper with timed counters"
SAMPLES_PER_CHUNK = 167
WARMUPS_PER_CHUNK = 32
CHUNKS = 3
BATCHES = 3
SAMPLES_PER_BATCH = SAMPLES_PER_CHUNK * CHUNKS
SAMPLES_PER_IMPL = SAMPLES_PER_BATCH * BATCHES

GATE_CANDIDATE = "C030-Q2Q3-LAND"
ROOT_PREFIX = "research-iter030-q2q3-"
WRAP_METADATA = "subprojects/xkcp/.meson-subproject-wrap-hash.txt"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def reject_constant(value):
    raise ValueError("non-finite JSON value: " + value)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=reject_constant)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def safe_relative(root, relative):
    require(isinstance(relative, str) and relative, "empty relative evidence path")
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in relative,
            "evidence path is not normalized and relative")
    resolved = (Path(root) / path).resolve(strict=True)
    require(resolved.is_relative_to(Path(root).resolve(strict=True)), "evidence path leaves its root")
    return resolved


def inventory(root):
    """Every regular file below root with size and hash; symlinks and special files are refused."""
    root = Path(root)
    values = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "symlink in immutable tree: " + path.relative_to(root).as_posix())
        if path.is_file():
            values[path.relative_to(root).as_posix()] = {"bytes": path.stat().st_size, "sha256": sha256(path)}
        else:
            require(path.is_dir(), "special filesystem entry: " + path.relative_to(root).as_posix())
    return values


def impl_names_by_tree(tree):
    return [name for name, spec in IMPLS.items() if spec["tree"] == tree]


def executable_name(name):
    return "q3_impl_%d" % IMPLS[name]["id"]


def expected_work_inventory(tree, source_files, patches, created, harness_entry):
    """Expected build-copy content: pinned originals, vendored XKCP and overlay, recorded patches and creations.

    source_files: the manifest's file table (paths relative to inputs/sources).
    patches/created: records from compatibility_patches.json / created_files.json (paths relative to the build dir).
    """
    spec = TREES[tree]
    prefix = spec["source_dir"] + "/"
    expected = {key[len(prefix):]: dict(value) for key, value in source_files.items() if key.startswith(prefix)}
    if spec["vendor_xkcp"]:
        expected.update({"subprojects/xkcp/" + key[len("xkcp_v2/"):]: dict(value)
                         for key, value in source_files.items() if key.startswith("xkcp_v2/")})
        overlay = prefix + "subprojects/packagefiles/xkcp/"
        expected.update({"subprojects/xkcp/" + key[len(overlay):]: dict(value)
                         for key, value in source_files.items() if key.startswith(overlay)})
    work_prefix = "work/" + tree + "/"
    for patch in patches:
        if patch["file"].startswith(work_prefix):
            key = patch["file"][len(work_prefix):]
            require(key in expected and expected[key]["sha256"] == patch["before_sha256"],
                    "patch is not based on the pinned source/overlay: " + tree + "/" + key)
            expected[key] = {"bytes": patch["after_bytes"], "sha256": patch["after_sha256"]}
    for item in created:
        if item["file"].startswith(work_prefix):
            key = item["file"][len(work_prefix):]
            require(key not in expected, "created file shadows a pinned source file: " + tree + "/" + key)
            expected[key] = {"bytes": item["bytes"], "sha256": item["sha256"]}
    require("q3_harness.cpp" not in expected, "harness name collides with a source file: " + tree)
    expected["q3_harness.cpp"] = dict(harness_entry)
    return expected
