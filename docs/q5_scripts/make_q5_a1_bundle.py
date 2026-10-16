"""迭代030 Q5 阶段 A1：打包 Q5 工作副本与 A1 脚本（只打包，不启动实验）。用法：python -I -X utf8 make_q5_a1_bundle.py 输出目录 时间戳"""
import hashlib, io, json, sys, tarfile
from pathlib import Path

ST = Path("D:/密码实验2.0/迭代/迭代030_高把握方案/Q5_建钥优化_20261016")
out_dir, stamp = Path(sys.argv[1]), sys.argv[2]
entries = []
tree = ST / "源码" / "rain-voleith-q5kg"
for path in sorted(tree.rglob("*")):
    parts = path.relative_to(tree).parts
    if path.is_file() and ".git" not in parts and "__pycache__" not in parts and "粘贴的" not in path.name:
        entries.append(("src/rain_q5/" + path.relative_to(tree).as_posix(), path.read_bytes()))
for name in ("q5_a1.sh", "q5_a1c.sh", "setup_toolchain.sh", "q5_export.py"):
    entries.append(("scripts/" + name, (ST / "脚本" / name).read_bytes()))
files = {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in entries}
manifest = json.dumps({"stage": "Q5 A1", "files": files}, ensure_ascii=False, indent=2).encode()
entries.append(("inputs_manifest.json", manifest))
bundle = out_dir / ("bundle_q5a1_%s.tar.gz" % stamp)
with tarfile.open(bundle, "x:gz") as tar:
    for name, data in sorted(entries):
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(data), 0o600, 0
        tar.addfile(info, io.BytesIO(data))
digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
(out_dir / "bundle_manifest.json").write_text(json.dumps({"bundle": bundle.name, "sha256": digest, "bytes": bundle.stat().st_size,
    "entries": len(entries), "inputs_manifest_sha256": hashlib.sha256(manifest).hexdigest(), "files": files}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(bundle.name, digest, bundle.stat().st_size, len(entries))
