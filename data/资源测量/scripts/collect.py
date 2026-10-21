#!/usr/bin/env python3
"""Parse massif/time/size outputs into storage_results.csv (Python 3.8 compatible).

M5 口径：共享全族库的模板树若直接统计 libfaest.a，会把同族其它参数集的模板实例
一起算进来。因此 M5 按“最终探针镜像（--gc-sections）的节大小 - 空镜像 - 探针自身
对象”计算，只保留该实现实际链接进来的代码与常量；库口径的原始聚合另存
m5_library_raw.csv 供核对。one-tree 的实现目录本身按参数集独立编译，两种口径接近。
"""
import csv
import os
import re

W = "<HOME>/rain-bench-20261016"
S = os.path.join(W, "storage_test")
RAW = os.path.join(S, "raw")
OUT = os.path.join(S, "results")
MODES = ["none", "keygen", "sign", "verify"]
REPEAT = 3
SECTIONS = [(".text", ".text"), (".rodata", ".rodata"),
            (".data", ".data"), (".bss", ".bss")]


def read_impls():
    with open(os.path.join(S, "scripts", "impls.tsv")) as f:
        return list(csv.DictReader(f, delimiter="\t"))


def massif_peak(path, keys):
    if not os.path.exists(path):
        return None
    with open(path, errors="replace") as f:
        snapshots = f.read().split("snapshot=")[1:]
    best = 0
    for snap in snapshots:
        total = 0
        for k in keys:
            m = re.search(r"%s=(\d+)" % re.escape(k), snap)
            if m:
                total += int(m.group(1))
        best = max(best, total)
    return best


def time_rss(path):
    if not os.path.exists(path):
        return None
    with open(path, errors="replace") as f:
        for line in f:
            if "Maximum resident set size" in line:
                m = re.search(r":\s*(\d+)", line)
                if m:
                    return int(m.group(1))
    return None


def size_prefix(path):
    """Sum .text/.rodata/.data/.bss including their subsections."""
    sums = {".text": 0, ".rodata": 0, ".data": 0, ".bss": 0}
    if not os.path.exists(path):
        return sums
    with open(path, errors="replace") as f:
        for line in f:
            m = re.match(r"^(\.\S+)\s+(\d+)\s+(\d+)\s*$", line)
            if not m:
                continue
            name, size = m.group(1), int(m.group(2))
            for prefix, key in SECTIONS:
                if name.startswith(prefix):
                    sums[key] += size
                    break
    return sums


def dims(key):
    d = {}
    p = os.path.join(S, "impls", key, "work", "dims.txt")
    if os.path.exists(p):
        for line in open(p):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                d[k] = v
    return d


def main():
    os.makedirs(OUT, exist_ok=True)
    impls = read_impls()
    rows = []
    baseline = []
    m5_raw = []
    base = {}
    for impl0 in impls:
        k = impl0["key"]
        bh = [massif_peak(os.path.join(RAW, "heap.%s.none.%d.out" % (k, r)),
                          ["mem_heap_B", "mem_heap_extra_B"]) for r in range(1, REPEAT + 1)]
        bs = [massif_peak(os.path.join(RAW, "stack.%s.none.%d.out" % (k, r)),
                          ["mem_stacks_B"]) for r in range(1, REPEAT + 1)]
        br = [time_rss(os.path.join(RAW, "time.%s.none.%d.txt" % (k, r)))
              for r in range(1, REPEAT + 1)]
        base[k] = (
            max([x for x in bh if x is not None]) if any(x is not None for x in bh) else None,
            max([x for x in bs if x is not None]) if any(x is not None for x in bs) else None,
            max([x for x in br if x is not None]) if any(x is not None for x in br) else None,
        )
    for impl in impls:
        key = impl["key"]
        lib = size_prefix(os.path.join(RAW, "size.%s.txt" % key))
        img = size_prefix(os.path.join(RAW, "size_image.%s.txt" % key))
        emp = size_prefix(os.path.join(RAW, "size_empty.%s.txt" % key))
        prb = size_prefix(os.path.join(RAW, "size_probeobjs.%s.txt" % key))
        sec = {}
        for s in [".text", ".rodata", ".data", ".bss"]:
            sec[s] = max(0, img[s] - emp[s] - prb[s])
        m5_raw.append({"id": impl["id"], "scheme": impl["scheme"],
                       "param_set": impl["param_set"], "key": key,
                       "text_lib_B": lib[".text"], "rodata_lib_B": lib[".rodata"],
                       "data_lib_B": lib[".data"], "bss_lib_B": lib[".bss"],
                       "text_image_B": sec[".text"], "rodata_image_B": sec[".rodata"],
                       "data_image_B": sec[".data"], "bss_image_B": sec[".bss"]})
        d = dims(key)
        for mode in MODES:
            heaps, stacks, rsss = [], [], []
            for r in range(1, REPEAT + 1):
                h = massif_peak(os.path.join(RAW, "heap.%s.%s.%d.out" % (key, mode, r)),
                                ["mem_heap_B", "mem_heap_extra_B"])
                s = massif_peak(os.path.join(RAW, "stack.%s.%s.%d.out" % (key, mode, r)),
                                ["mem_stacks_B"])
                t = time_rss(os.path.join(RAW, "time.%s.%s.%d.txt" % (key, mode, r)))
                if h is not None:
                    heaps.append(h)
                if s is not None:
                    stacks.append(s)
                if t is not None:
                    rsss.append(t)
            notes = []
            if not heaps:
                notes.append("heap missing")
            if not stacks:
                notes.append("stack missing")
            if not rsss:
                notes.append("maxrss missing")
            for label, vals in (("heap", heaps), ("stack", stacks), ("maxrss", rsss)):
                if len(set(vals)) > 1 and max(vals):
                    spread = (max(vals) - min(vals)) / float(max(vals))
                    if spread > 0.01:
                        notes.append("%s varies: %s" % (label, vals))
            bh, bs, br = base[key]
            if mode == "none":
                notes.append("baseline")
            else:
                if bh is not None:
                    notes.append("none_heap=%d" % bh)
                if bs is not None:
                    notes.append("none_stack=%d" % bs)
                if br is not None:
                    notes.append("none_rss_KB=%d" % br)
                if stacks and bs is not None:
                    notes.append("stack_net=%d" % (max(stacks) - bs))
                if rsss and br is not None:
                    notes.append("rss_delta_KB=%d" % (max(rsss) - br))
            row = {
                "id": impl["id"],
                "scheme": impl["scheme"],
                "param_set": impl["param_set"],
                "source_commit": impl["source_commit"],
                "compiler": impl["compiler"],
                "cflags": impl["cflags"],
                "mode": mode,
                "heap_peak_B": max(heaps) if heaps else "",
                "stack_peak_B": max(stacks) if stacks else "",
                "maxrss_KB": max(rsss) if rsss else "",
                "text_B": "",
                "rodata_B": "",
                "data_B": "",
                "bss_B": "",
                "pk_B": d.get("pk", ""),
                "sk_B": d.get("sk", ""),
                "sig_B": d.get("sig", ""),
                "runs": REPEAT,
                "note": "; ".join(notes),
            }
            rows.append(row)
        for row in rows:
            if row["id"] == impl["id"] and row["mode"] == "none":
                row["text_B"] = sec[".text"]
                row["rodata_B"] = sec[".rodata"]
                row["data_B"] = sec[".data"]
                row["bss_B"] = sec[".bss"]
                break

    for impl in impls:
        key = impl["key"]
        bh, bs, br = base[key]
        baseline.append({"key": key, "id": impl["id"], "scheme": impl["scheme"],
                         "param_set": impl["param_set"], "heap_none_B": bh,
                         "stack_none_B": bs, "maxrss_none_KB": br})

    cols = ["id", "scheme", "param_set", "source_commit", "compiler", "cflags", "mode",
            "heap_peak_B", "stack_peak_B", "maxrss_KB", "text_B", "rodata_B", "data_B",
            "bss_B", "pk_B", "sk_B", "sig_B", "runs", "note"]
    out_csv = os.path.join(OUT, "storage_results.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    with open(os.path.join(OUT, "baseline_none.csv"), "w", newline="") as f:
        bcols = ["key", "id", "scheme", "param_set", "heap_none_B", "stack_none_B",
                 "maxrss_none_KB"]
        w = csv.DictWriter(f, fieldnames=bcols)
        w.writeheader()
        w.writerows(baseline)

    with open(os.path.join(OUT, "m5_image_vs_library.csv"), "w", newline="") as f:
        mcols = ["id", "scheme", "param_set", "key", "text_lib_B", "rodata_lib_B",
                 "data_lib_B", "bss_lib_B", "text_image_B", "rodata_image_B",
                 "data_image_B", "bss_image_B"]
        w = csv.DictWriter(f, fieldnames=mcols)
        w.writeheader()
        w.writerows(m5_raw)

    print("wrote", out_csv, len(rows), "rows")
    for m in m5_raw:
        print("M5", m["key"], "image:", m["text_image_B"], m["rodata_image_B"],
              m["data_image_B"], m["bss_image_B"], "lib:", m["text_lib_B"],
              m["rodata_lib_B"], m["data_lib_B"], m["bss_lib_B"])


if __name__ == "__main__":
    main()
