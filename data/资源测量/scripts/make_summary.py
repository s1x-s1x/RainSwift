#!/usr/bin/env python3
"""Build summary.md and a per-implementation pivot table from storage_results.csv."""
import csv
import os
import re

S = "<HOME>/rain-bench-20261016/storage_test"
OUT = os.path.join(S, "results")
MODES = ["none", "keygen", "sign", "verify"]


def rows():
    with open(os.path.join(OUT, "storage_results.csv")) as f:
        return list(csv.DictReader(f))


def note_value(note, key):
    m = re.search(r"%s=(-?\d+)" % re.escape(key), note or "")
    return int(m.group(1)) if m else ""


def main():
    data = rows()
    by_id = {}
    for r in data:
        by_id.setdefault(r["id"], {})[r["mode"]] = r

    pivot_cols = ["id", "scheme", "param_set", "pk_B", "sk_B", "sig_B",
                  "heap_none_B", "heap_keygen_B", "heap_sign_B", "heap_verify_B",
                  "stack_none_B", "stack_keygen_B", "stack_sign_B", "stack_verify_B",
                  "stack_sign_net_B", "stack_verify_net_B",
                  "maxrss_none_KB", "maxrss_keygen_KB", "maxrss_sign_KB", "maxrss_verify_KB",
                  "text_B", "rodata_B", "data_B", "bss_B"]
    pivot = []
    lines = []
    lines.append("| id | 方案 | 参数集 | pk/sk/sig (B) | M2 堆 none/keygen/sign/verify (B) | "
                 "M3 栈 sign/verify 原始(净) (B) | M4 RSS none/sign/verify (KB) | "
                 "M5 text/rodata/data/bss (B) |")
    lines.append("|---:|---|---|---:|---|---|---:|---|")
    for rid in sorted(by_id, key=lambda x: int(x)):
        m = by_id[rid]
        n = m["none"]
        k = m["keygen"]
        s = m["sign"]
        v = m["verify"]
        ss_net = note_value(s["note"], "stack_net")
        sv_net = note_value(v["note"], "stack_net")
        pivot.append({
            "id": rid, "scheme": n["scheme"], "param_set": n["param_set"],
            "pk_B": n["pk_B"], "sk_B": n["sk_B"], "sig_B": n["sig_B"],
            "heap_none_B": n["heap_peak_B"], "heap_keygen_B": k["heap_peak_B"],
            "heap_sign_B": s["heap_peak_B"], "heap_verify_B": v["heap_peak_B"],
            "stack_none_B": n["stack_peak_B"], "stack_keygen_B": k["stack_peak_B"],
            "stack_sign_B": s["stack_peak_B"], "stack_verify_B": v["stack_peak_B"],
            "stack_sign_net_B": ss_net, "stack_verify_net_B": sv_net,
            "maxrss_none_KB": n["maxrss_KB"], "maxrss_keygen_KB": k["maxrss_KB"],
            "maxrss_sign_KB": s["maxrss_KB"], "maxrss_verify_KB": v["maxrss_KB"],
            "text_B": n["text_B"], "rodata_B": n["rodata_B"],
            "data_B": n["data_B"], "bss_B": n["bss_B"],
        })
        lines.append("| %s | %s | %s | %s/%s/%s | %s / %s / %s / %s | %s (%s) / %s (%s) | "
                     "%s / %s / %s | %s/%s/%s/%s |" % (
                         rid, n["scheme"], n["param_set"], n["pk_B"], n["sk_B"], n["sig_B"],
                         n["heap_peak_B"], k["heap_peak_B"], s["heap_peak_B"], v["heap_peak_B"],
                         s["stack_peak_B"], ss_net, v["stack_peak_B"], sv_net,
                         n["maxrss_KB"], s["maxrss_KB"], v["maxrss_KB"],
                         n["text_B"], n["rodata_B"], n["data_B"], n["bss_B"]))

    with open(os.path.join(OUT, "summary.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(OUT, "storage_results_pivot.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=pivot_cols)
        w.writeheader()
        w.writerows(pivot)
    print("wrote summary.md and storage_results_pivot.csv", len(pivot), "implementations")


if __name__ == "__main__":
    main()
