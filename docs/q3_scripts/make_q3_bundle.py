"""迭代030 Q3：在本机生成上传包与源码清单（只打包，不启动实验）。

用法：python -I make_q3_bundle.py 输出目录 时间戳
输出：输出目录/bundle_q3_<时间戳>.tar.gz、bundle_manifest.json；包内 inputs/source_manifest.json 逐文件记录哈希。
对照源码取自迭代028 资料/sources，并与 P0 正式窗口留存的源码清单逐文件比对（应全部相同）。
递归收集时排除 .git、__pycache__ 以及文件名含“粘贴的”的文件。
"""
import io
import json
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3_common import TREES, canonical_hash, require, sha256, sha256_bytes  # noqa: E402

PROJECT = Path("D:/密码实验2.0")
STAGE = PROJECT / "迭代/迭代030_高把握方案/Q2Q3_落地与实测_20261016"
P0_SOURCES = PROJECT / "迭代/迭代028_P0基线与求解器/资料/sources"
P0_MANIFEST = PROJECT / "迭代/迭代028_P0基线与求解器/原始数据/window_v4/provenance/source_manifest.json"

SOURCE_DIRS = {  # 包内 inputs/sources/<键> ← 本机目录
    "faest_v3": P0_SOURCES / "faest_v3",
    "rfaest/rFAEST": P0_SOURCES / "rfaest/rFAEST",
    "lynxer/opt": P0_SOURCES / "lynxer/opt",
    "xkcp_v2": P0_SOURCES / "xkcp_v2",
    "rain_q2": STAGE / "源码/rain-voleith-q2",
}
SCRIPTS = {name: HERE / name for name in ("q3_harness.cpp", "q3_common.py", "q3_prepare.py", "q3_build.sh",
                                          "run_q3_window.py", "summarize_q3_window.py", "q3_phaseA.sh", "q3_phaseB.sh")}
SCRIPTS["setup_toolchain.sh"] = STAGE / "脚本/setup_toolchain.sh"
SCRIPTS["kat_gen.cpp"] = STAGE / "脚本/kat_gen.cpp"
KAT = {"sigkat_%s.txt" % s: STAGE / ("KAT/sigkat_%s.txt" % s)
       for s in ("rain3_fast", "rain3_bal", "rain3_short", "rain4_fast", "rain4_bal", "rain4_short")}
KAT["kat_gen_q2_b0.txt"] = STAGE / "KAT/kat_gen_工作副本B1=0.txt"
GATE = STAGE / "原始数据/当前实验门控.json"


def collect(directory):
    files = {}
    for path in sorted(directory.rglob("*")):
        parts = path.relative_to(directory).parts
        if ".git" in parts or "__pycache__" in parts or "粘贴的" in path.name:
            continue
        require(not path.is_symlink(), "symlink in source tree: " + str(path))
        if path.is_file():
            files[path.relative_to(directory).as_posix()] = path
    return files


def main():
    out_dir, stamp = Path(sys.argv[1]), sys.argv[2]
    out_dir.mkdir(parents=True, exist_ok=True)
    entries, table = [], {}
    for key, directory in SOURCE_DIRS.items():
        for rel, path in collect(directory).items():
            data = path.read_bytes()
            table[key + "/" + rel] = {"bytes": len(data), "sha256": sha256_bytes(data)}
            entries.append(("inputs/sources/" + key + "/" + rel, data))
    # 与 P0 正式窗口的源码清单逐文件比对（四棵对照源码）。
    p0 = json.loads(P0_MANIFEST.read_text(encoding="utf-8"))["bundle"]["files"]
    probe = [k for k in p0 if k.endswith("faest_v3/api.hpp")]
    require(len(probe) == 1, "cannot locate faest_v3/api.hpp in the P0 manifest")
    p0_prefix = probe[0][: -len("faest_v3/api.hpp")]
    p0_check = {}
    for key in ("faest_v3", "rfaest/rFAEST", "lynxer/opt", "xkcp_v2"):
        mine = {k: v for k, v in table.items() if k.startswith(key + "/")}
        theirs = {k[len(p0_prefix):]: v for k, v in p0.items() if k.startswith(p0_prefix + key + "/")}
        same = sum(1 for k, v in mine.items() if theirs.get(k, {}).get("sha256") == v["sha256"])
        p0_check[key] = {"files": len(mine), "identical_to_p0": same, "only_here": sorted(set(mine) - set(theirs))[:5],
                         "only_in_p0": sorted(set(theirs) - set(mine))[:5]}
        require(same == len(mine) == len(theirs), "comparator source differs from P0 manifest: " + key)
    sources = [{"tree": tree, "path": spec["source_dir"], "commit": spec["commit"],
                "origin": str(SOURCE_DIRS[spec["source_dir"]]).replace("\\", "/")} for tree, spec in TREES.items()]
    manifest = {"schema_version": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                "purpose": "迭代030 Q3 同机同窗口实测：对照与 Rain 源码的逐文件哈希（inputs/sources 下全部文件）",
                "sources": sources, "xkcp_v2": {"path": "xkcp_v2", "commit": "64404beeeb261b08a1076fe2f076e4e28dd9b040"},
                "files": table, "inventory_sha256": canonical_hash(table), "p0_identity_check": p0_check}
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    entries.append(("inputs/source_manifest.json", manifest_bytes))
    for name, path in SCRIPTS.items():
        entries.append(("scripts/" + name, path.read_bytes()))
    for name, path in KAT.items():
        entries.append(("kat/" + name, path.read_bytes()))
    entries.append(("control/gate.json", GATE.read_bytes()))
    bundle = out_dir / ("bundle_q3_%s.tar.gz" % stamp)
    with tarfile.open(bundle, "x:gz") as tar:
        for name, data in sorted(entries):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            tar.addfile(info, io.BytesIO(data))
    inputs = {"inputs/sources/" + k: str(v).replace("\\", "/") for k, v in SOURCE_DIRS.items()}
    inputs.update({"scripts/" + k: str(v).replace("\\", "/") for k, v in SCRIPTS.items()})
    inputs.update({"kat/" + k: str(v).replace("\\", "/") for k, v in KAT.items()})
    inputs["control/gate.json"] = str(GATE).replace("\\", "/")
    record = {"bundle": bundle.name, "sha256": sha256(bundle), "bytes": bundle.stat().st_size,
              "entries": len(entries), "source_files": len(table),
              "source_manifest_sha256": sha256_bytes(manifest_bytes),
              "script_sha256": {k: sha256(v) for k, v in SCRIPTS.items()},
              "kat_sha256": {k: sha256(v) for k, v in KAT.items()}, "gate_sha256": sha256(GATE),
              "p0_identity_check": p0_check, "inputs": inputs}
    (out_dir / "bundle_manifest.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                                                  encoding="utf-8")
    print(json.dumps({k: record[k] for k in ("bundle", "sha256", "bytes", "entries", "source_files")}, ensure_ascii=False))
    print(json.dumps({k: (v["files"], v["identical_to_p0"]) for k, v in p0_check.items()}))


if __name__ == "__main__":
    main()
