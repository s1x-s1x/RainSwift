"""迭代030 Q3：把运行目录中的指定产物复制到新的导出目录，供打包下载（原件留在服务器，不改）。

用法（在运行目录 build/research-iter030-q2q3-<UTC>/ 中）：python3 -I scripts/q3_export.py 导出目录名 产物1 [产物2 ...]
文本文件中的实验目录、家目录与 /home/<账号> 路径替换为 <EXPERIMENT>、<HOME>；二进制文件原样复制，
但若含有家目录路径字节则拒绝导出。逐文件替换次数与导出后哈希写入 导出目录/REDACTION.json。
另统计形似 IPv4 的串（只计数并列出所在文件，不替换），由人工复核。
"""
import hashlib
import json
import re
import sys
from pathlib import Path

run = Path.cwd().resolve()
if not run.name.startswith("research-iter030-q2q3-"):
    raise SystemExit("EXPORT_ERROR must run inside a research-iter030-q2q3-* directory")
name, items = sys.argv[1], sys.argv[2:]
if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
    raise SystemExit("EXPORT_ERROR invalid export name")
export = run / name
export.mkdir()  # never reuse an export directory
home = str(Path.home())
account_bytes = re.compile(rb"/home/[A-Za-z0-9_.-]+")  # v2：只匹配账号名字符，避免误伤代码中的正则字面量
account_text = re.compile(r"/home/[A-Za-z0-9_.-]+")
ipv4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
records, ip_like = [], {}


def export_file(source, relative):
    data = source.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        if account_bytes.search(data) or home.encode() in data:
            raise SystemExit("EXPORT_ERROR binary file contains a home path: " + relative)
        out, count = data, 0
    else:
        count = 0
        for prefix, token in sorted([(str(run), "<EXPERIMENT>"), (home, "<HOME>")], key=lambda x: -len(x[0])):
            count += text.count(prefix)
            text = text.replace(prefix, token)
        text, extra = account_text.subn("<HOME>", text)
        count += extra
        hits = ipv4.findall(text)
        if hits:
            ip_like[relative] = sorted(set(hits))[:10]
        out = text.encode("utf-8")
    target = export / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as f:
        f.write(out)
    records.append({"file": relative, "replacements": count, "sha256": hashlib.sha256(out).hexdigest(),
                    "source_sha256": hashlib.sha256(data).hexdigest()})


for item in items:
    source = (run / item).resolve(strict=True)
    if not source.is_relative_to(run) or source.is_relative_to(export):
        raise SystemExit("EXPORT_ERROR item outside run directory: " + item)
    paths = [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.is_file())
    for path in paths:
        if path.is_symlink():
            raise SystemExit("EXPORT_ERROR symlink: " + path.relative_to(run).as_posix())
        export_file(path, path.relative_to(run).as_posix())

summary = {"export": name, "files": len(records), "files_with_replacements": sum(1 for r in records if r["replacements"]),
           "total_replacements": sum(r["replacements"] for r in records), "ipv4_like_strings": ip_like,
           "note": "originals remain unchanged in the server run directory; source_sha256 is the original file hash",
           "records": records}
with (export / "REDACTION.json").open("x", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)
    f.write("\n")
print(json.dumps({k: summary[k] for k in ("export", "files", "files_with_replacements", "total_replacements")}))
print(json.dumps({"ipv4_like_strings": ip_like}))
