"""迭代030 Q5：在构建目录内准备四棵构建副本（只准备，不编译、不计时；由 Q3 版本改写，Rain 树换成 Q5 工作副本）。

用法：python3 -I q5_prepare.py ROOT BUILD SOURCE_ROOT HARNESS KAT_GEN
  SOURCE_ROOT 下为 faest_v3、rfaest/rFAEST、lynxer/opt、xkcp_v2、rain_q5（本机打包上传，哈希见 source_manifest.json）。
输出（均在 BUILD 内）：work/<树>/、backups/（被改文件的原字节）、compatibility_patches.json、
  created_files.json、build_inputs.json。原始输入目录不改。

与 P0 build_baselines_v3.sh 的 prepare 步骤相同的部分：XKCP 64404bee 及上游 overlay 落入 subprojects/xkcp
（FAEST v3 用自带的 eb5244d6）；删去 `#include <cstdalign>`、给 quicksilver.hpp 补 `#include <algorithm>`、
修正 Lynxer 的 NDEBUG 断言宏；去掉 Catch2 测试子目录；只给 OS 随机源翻译单元改符号名
（-Drand_bytes=p0_upstream_rand_bytes），计时程序里的 rand_bytes 包装再调用它。
Q3／Q5 新增：每个实现一个可执行目标 q5_impl_<编号>（同一份 q5_harness.cpp）；Rain 树另加四个显式实例化翻译单元
（把库内同名文件中 v2::faest_em_128_f 的实例化行逐行替换为 Rain 六组，结构与对照的库完全相同），
以及库方式的 KAT 程序 q5_rain_kat_lib（kat_gen.cpp 去掉 all.inc，只经库内实例化）。
"""
import difflib
import json
import os
import re
import shutil
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from q5_common import (IMPLS, RAIN_INSTANCE_TUS, RAIN_SETS, RAIN_TEMPLATE_SET, TREES, executable_name,  # noqa: E402
                       impl_names_by_tree, sha256_bytes)

root, build, supplied, harness, katgen = map(Path, sys.argv[1:])
patches, created, records = [], [], []


def fail(reason):
    raise SystemExit("PREPARE_ERROR " + reason)


def atomically_replace(path, data, reason):
    old = path.read_bytes()
    if old == data:
        return
    relative = path.relative_to(build)
    backup = build / "backups" / relative
    backup.parent.mkdir(parents=True, exist_ok=True)
    if backup.exists():
        fail("duplicate backup path; refusing a second rewrite: " + relative.as_posix())
    shutil.copy2(path, backup)
    tmp = path.with_name(path.name + ".q3-new")
    with tmp.open("xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    diff = "".join(difflib.unified_diff(old.decode(errors="replace").splitlines(True),
                                        data.decode(errors="replace").splitlines(True),
                                        fromfile=relative.as_posix() + ":before", tofile=relative.as_posix() + ":after"))
    patches.append({"file": relative.as_posix(), "reason": reason, "before_sha256": sha256_bytes(old),
                    "after_sha256": sha256_bytes(data), "after_bytes": len(data), "diff": diff})


def create(path, data, reason, rule):
    if path.exists():
        fail("refusing to overwrite an existing file: " + path.relative_to(build).as_posix())
    with path.open("xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    created.append({"file": path.relative_to(build).as_posix(), "reason": reason, "rule": rule,
                    "sha256": sha256_bytes(data), "bytes": len(data)})


TEMPLATE = re.compile(re.escape(RAIN_TEMPLATE_SET) + r"(?![A-Za-z0-9_])")
SKELETON = re.compile(r'^(#include "[A-Za-z0-9_]+\.inc"|namespace faest|\{|\} // namespace faest|// clang-format (on|off)|)$')


def rain_instances(library_tu):
    """Rain 版显式实例化：保留骨架行，删除其他参数集的实例化行，模板参数集的每一行展开为六组。"""
    lines_out, count = [], 0
    for line in library_tu.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        if stripped.startswith("template "):
            if TEMPLATE.search(stripped):
                count += 1
                lines_out.extend(TEMPLATE.sub("rain_sets::" + s, line) for s in RAIN_SETS)
            continue
        if not SKELETON.fullmatch(stripped):
            fail("unexpected non-instantiation line in library TU: " + stripped[:80])
        lines_out.append(line)
    return "".join(lines_out), count


harness_bytes = harness.read_bytes()
for tree, spec in TREES.items():
    original = supplied / spec["source_dir"]
    for filename in ("api.hpp", "meson.build", "parameters.hpp", "randomness_os.c"):
        if not (original / filename).is_file():
            fail("missing pinned source file: " + tree + "/" + filename)
    source = build / "work" / tree
    shutil.copytree(original, source, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    wrap = (source / "subprojects" / "xkcp.wrap").read_text(encoding="utf-8")
    if not re.search(r"^revision\s*=\s*" + re.escape(spec["xkcp_commit"]) + r"\s*$", wrap, re.M):
        fail("pinned XKCP revision mismatch: " + tree)
    if spec["vendor_xkcp"]:
        dependency = source / "subprojects" / "xkcp"
        if dependency.exists():
            fail("unexpected pre-existing legacy dependency; audit before replacing: " + tree)
        shutil.copytree(supplied / "xkcp_v2", dependency, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        package = source / "subprojects" / "packagefiles" / "xkcp"
        for overlay in sorted(package.rglob("*")):
            if overlay.is_file():
                dest = dependency / overlay.relative_to(package)
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.exists():
                    atomically_replace(dest, overlay.read_bytes(), "upstream legacy XKCP Meson overlay")
                else:
                    shutil.copy2(overlay, dest)
    if not (source / "subprojects" / "xkcp" / "meson.build").is_file():
        fail("vendored XKCP Meson overlay missing: " + tree)

    # 兼容性补丁：与 P0（027 构建记录）相同的规则，逐树重放。
    for header in sorted([*source.rglob("*.hpp"), *source.rglob("*.inc")]):
        if "subprojects" in header.relative_to(source).parts:
            continue
        data = header.read_bytes()
        changed = re.sub(rb"(?m)^\s*#include\s*<cstdalign>\s*\r?\n", b"", data)
        if header.name == "quicksilver.hpp" and b"#include <algorithm>" not in changed:
            changed = b"#include <algorithm>\n" + changed
        if tree == "lynxer" and header.name == "util.hpp":
            needle = b"__builtin_unreachable();"
            if changed.count(needle) != 1 or b"#define FAEST_ASSERT(x)" not in changed:
                fail("Lynxer assertion patch precondition differs")
            changed = changed.replace(needle, b"if (!(x)) __builtin_unreachable();", 1)
        atomically_replace(header, changed, "libc++ compatibility / Lynxer NDEBUG assertion correctness")

    meson = source / "meson.build"
    text = meson.read_text(encoding="utf-8")
    if text.count("subdir('test')") != spec["test_subdir"]:
        fail("unexpected upstream test inclusion count: " + tree)
    text = text.replace("subdir('test')", "# P0/Q3: no Catch2 bench/test target in this library-only build.")
    if spec["rng"] == "v3":
        old_rng_args = "    c_args : randomness_args,"
        if text.count(old_rng_args) != 1:
            fail("unexpected FAEST v3 randomness target arguments")
        text = text.replace(old_rng_args, "    c_args : randomness_args + ['-Drand_bytes=p0_upstream_rand_bytes'],", 1)
    else:
        old_rng_source = "    'randomness_os.c',\n"
        if text.count(old_rng_source) != 1:
            fail("unexpected legacy randomness target source: " + tree)
        text = text.replace(old_rng_source, old_rng_source + "    c_args : ['-Drand_bytes=p0_upstream_rand_bytes'],\n", 1)
    if tree == "rain":
        old_sources = "  'vole_commit.cpp',\n]\n"
        if text.count(old_sources) != 1:
            fail("unexpected Rain library source list")
        new_sources = "  'vole_commit.cpp',\n" + "".join("  'q5_rain_%s',\n" % tu for tu in RAIN_INSTANCE_TUS) + "]\n"
        text = text.replace(old_sources, new_sources, 1)
        for tu, expected_count in RAIN_INSTANCE_TUS.items():
            body, count = rain_instances((source / tu).read_text(encoding="utf-8"))
            if count != expected_count:
                fail("unexpected instantiation count in %s: %d" % (tu, count))
            header_comment = ("// 迭代030 Q5 生成（只在构建副本中）：取库内 %s 中 %s 的 %d 行显式实例化，\n"
                              "// 逐行把参数集名替换为 Rain 六组，使 Rain 与对照一样由库实例化、经 api.hpp 调用。\n"
                              % (tu, RAIN_TEMPLATE_SET, expected_count))
            create(source / ("q5_rain_" + tu), (header_comment + body).encode(),
                   "Rain explicit instantiations mirroring the library TU structure",
                   "lines of %s instantiating %s, parameter set replaced by rain_sets::{%s}"
                   % (tu, RAIN_TEMPLATE_SET, ",".join(RAIN_SETS)))
        kat = katgen.read_text(encoding="utf-8")
        if kat.count('#include "all.inc"\n') != 1:
            fail("kat_gen.cpp no longer has exactly one all.inc include")
        kat = ("// 迭代030 Q5 生成：scripts/kat_gen.cpp 去掉 all.inc，只经库内显式实例化；输出须与 Q2 KAT 逐字节相同。\n"
               + kat.replace('#include "all.inc"\n', "", 1))
        create(source / "q5_rain_kat_lib.cpp", kat.encode(), "library-path deterministic KAT generator",
               "scripts/kat_gen.cpp with its single #include \"all.inc\" line removed")
    text += "\n# Q3 complete-API harness only; no cryptographic parameter change.\n"
    for name in impl_names_by_tree(tree):
        text += ("executable('%s', 'q5_harness.cpp',\n  dependencies : [faest_dep, randomness_os_dep],\n"
                 "  cpp_args : ['-DQ5_IMPL_ID=%d'])\n" % (executable_name(name), IMPLS[name]["id"]))
    if tree == "rain":
        text += ("# Q3 library-path KAT (deterministic rand_bytes inside the program; no OS randomness).\n"
                 "executable('q5_rain_kat_lib', 'q5_rain_kat_lib.cpp',\n  dependencies : [faest_dep],\n)\n")
    atomically_replace(meson, text.encode(), "disable unused Catch2 targets; TU-local RNG symbol wrapper; "
                       "add unified complete-API harness targets (Rain: library instantiation TUs and library KAT)")
    with (source / "q5_harness.cpp").open("xb") as f:
        f.write(harness_bytes)
    core = ("api.hpp", "parameters.hpp", "faest.cpp", "faest.inc", "randomness_os.c")
    for name in impl_names_by_tree(tree):
        records.append({
            "impl": name, "impl_id": IMPLS[name]["id"], "algorithm": IMPLS[name]["algorithm"], "tree": tree,
            "declared_fixed_commit": IMPLS[name]["commit"], "xkcp_fixed_commit": spec["xkcp_commit"],
            "harness_sha256": sha256_bytes(harness_bytes), "signature_bytes_declared": IMPLS[name]["signature_bytes"],
            "original_core_hashes": {p: sha256_bytes((original / p).read_bytes()) for p in core},
            "patched_core_hashes": {p: sha256_bytes((source / p).read_bytes()) for p in core},
            "build_dir": "build/" + tree, "executable": "build/" + tree + "/" + executable_name(name),
        })

for filename, value in [("compatibility_patches.json", patches), ("created_files.json", created),
                        ("build_inputs.json", records)]:
    with (build / filename).open("x", encoding="utf-8") as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.write("\n")
print("prepared four isolated build copies (%d implementations, %d patches, %d created files); "
      "original source material unchanged" % (len(records), len(patches), len(created)))
