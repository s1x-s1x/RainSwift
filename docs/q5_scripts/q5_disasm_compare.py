"""迭代030 Q5 D3（参考，不阻断）：比对 Q3 构建与 Q5 构建中 Rain 库四个翻译单元里各函数的机器码。

用法：python3 -I q5_disasm_compare.py Q3目标文件目录 Q5目标文件目录 输出JSON
目标文件为 meson 的 libfaest.a.p/q3_rain_*.cpp.o 与 q5_rain_*.cpp.o（同一份库内显式实例化，只是生成文件名不同）。
每个函数的指令序列去掉地址，跳转与调用目标只保留相对函数起点的偏移（v2；v1 未归一节内绝对地址，见版本存档），再求哈希。
预期：只有建钥相关函数（faest_pubkey 的各实例）不同，签发、验签、约束证明等函数相同。
没有 objdump 或找不到目标文件时只记录“不可用”，退出码仍为 0。
"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

q3_dir, q5_dir, out_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
TUS = ("faest", "owf_proof", "small_vole", "vole_commit")


def write(value):
    with out_path.open("x", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write("\n")


tool = shutil.which("objdump") or shutil.which("llvm-objdump")
if tool is None:
    write({"status": "unavailable", "reason": "no objdump on this host"})
    raise SystemExit(0)


def functions(obj):
    text = subprocess.run([tool, "-d", "--no-show-raw-insn", "-C", "-w", str(obj)], capture_output=True,
                          text=True, check=True).stdout
    funcs, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^[0-9a-f]+ <(.*)>:$", line)
        if m:
            cur = m.group(1)
            funcs.setdefault(cur, [])
            continue
        if cur is None:
            continue
        if not line.strip():
            cur = None
            continue
        m = re.match(r"^\s*[0-9a-f]+:\s*(.*)$", line)
        if m:
            ins = m.group(1)
            # 跳转、调用目标形如 "854 <函数名+0x134>"：节内绝对地址随函数排布而变，只保留相对函数起点的偏移
            off = re.search(r"\+0x[0-9a-f]+>$", ins)
            ins = re.sub(r"[0-9a-f]+ <.*$", "<" + (off.group(0)[1:-1] if off else "sym") + ">", ins)
            funcs[cur].append(re.sub(r"\s+", " ", ins).strip())
    return {name: (len(body), hashlib.sha256("\n".join(body).encode()).hexdigest()) for name, body in funcs.items() if body}


result = {"status": "ok", "tool": Path(tool).name, "translation_units": {}}
for tu in TUS:
    a, b = q3_dir / ("q3_rain_%s.cpp.o" % tu), q5_dir / ("q5_rain_%s.cpp.o" % tu)
    if not a.is_file() or not b.is_file():
        result["translation_units"][tu] = {"status": "missing object file"}
        continue
    fa, fb = functions(a), functions(b)
    common = sorted(set(fa) & set(fb))
    same = [n for n in common if fa[n] == fb[n]]
    diff = [n for n in common if fa[n] != fb[n]]
    result["translation_units"][tu] = {
        "functions_q3": len(fa), "functions_q5": len(fb), "common": len(common), "identical": len(same),
        "different": [{"name": n, "instructions_q3": fa[n][0], "instructions_q5": fb[n][0]} for n in diff],
        "only_q3": sorted(set(fa) - set(fb))[:50], "only_q5": sorted(set(fb) - set(fa))[:50]}
    sig = [n for n in common if "faest_sign<" in n or "faest_verify<" in n]
    result["translation_units"][tu]["sign_verify_functions"] = len(sig)
    result["translation_units"][tu]["sign_verify_identical"] = sum(1 for n in sig if fa[n] == fb[n])
write(result)
print(json.dumps({tu: {k: v for k, v in r.items() if k in ("common", "identical", "sign_verify_functions", "sign_verify_identical", "status")}
                  | {"different": len(r.get("different", []))} for tu, r in result["translation_units"].items()}, ensure_ascii=False))
