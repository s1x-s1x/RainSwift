#!/usr/bin/env python3
"""Summarize stack-painting results and compare with massif M3."""
import csv
import os
import re

S = "<HOME>/rain-bench-20261016/storage_test"
RAW = os.path.join(S, "raw")
OUT = os.path.join(S, "results")
MODES = ["none", "keygen", "sign", "verify"]


def read_impls():
    with open(os.path.join(S, "scripts", "impls.tsv")) as f:
        return list(csv.DictReader(f, delimiter="\t"))


def val(key, mode, r):
    p = os.path.join(RAW, "stackpaint.%s.%s.%d.txt" % (key, mode, r))
    try:
        return int(open(p).read().strip())
    except Exception:
        return None


def massif_none(key):
    from importlib.machinery import SourceFileLoader
    # reuse the same parsing rule without importing collect.py's main
    import re as _re
    p = os.path.join(RAW, "stack.%s.none.1.out" % key)
    best = 0
    for snap in open(p).read().split("snapshot=")[1:]:
        m = _re.search(r"mem_stacks_B=(\d+)", snap)
        if m:
            best = max(best, int(m.group(1)))
    return best


def main():
    impls = read_impls()
    long_rows = []
    wide = []
    cmp_rows = []
    massif = {}
    with open(os.path.join(OUT, "storage_results.csv")) as f:
        for r in csv.DictReader(f):
            massif.setdefault(r["id"], {})[r["mode"]] = r

    for impl in impls:
        key = impl["key"]
        vals = {}
        for mode in MODES:
            arr = [val(key, mode, r) for r in range(1, 4)]
            arr_ok = [x for x in arr if x is not None]
            mx = max(arr_ok) if arr_ok else None
            vals[mode] = mx
            long_rows.append({"id": impl["id"], "scheme": impl["scheme"],
                              "param_set": impl["param_set"], "key": key, "mode": mode,
                              "run1": arr[0], "run2": arr[1], "run3": arr[2],
                              "max_B": mx if mx is not None else "",
                              "net_B": (mx - vals["none"]) if (mx is not None and vals.get("none") is not None) else ""})
        non = vals.get("none")
        wide.append({"id": impl["id"], "scheme": impl["scheme"], "param_set": impl["param_set"], "key": key,
                     "none_B": non if non is not None else "",
                     "keygen_B": vals.get("keygen") if vals.get("keygen") is not None else "",
                     "sign_B": vals.get("sign") if vals.get("sign") is not None else "",
                     "verify_B": vals.get("verify") if vals.get("verify") is not None else "",
                     "keygen_net_B": (vals["keygen"] - non) if (vals.get("keygen") is not None and non is not None) else "",
                     "sign_net_B": (vals["sign"] - non) if (vals.get("sign") is not None and non is not None) else "",
                     "verify_net_B": (vals["verify"] - non) if (vals.get("verify") is not None and non is not None) else ""})
        m = massif.get(impl["id"], {})
        def mnet(mode):
            if mode not in m or not m[mode]["stack_peak_B"]:
                return ""
            return int(m[mode]["stack_peak_B"]) - int(m["none"]["stack_peak_B"])
        cmp_rows.append({
            "id": impl["id"], "scheme": impl["scheme"], "param_set": impl["param_set"], "key": key,
            "massif_sign_raw_B": m.get("sign", {}).get("stack_peak_B", ""),
            "massif_sign_net_B": mnet("sign"),
            "paint_sign_raw_B": vals.get("sign") if vals.get("sign") is not None else "",
            "paint_sign_net_B": (vals["sign"] - non) if (vals.get("sign") is not None and non is not None) else "",
            "massif_verify_raw_B": m.get("verify", {}).get("stack_peak_B", ""),
            "massif_verify_net_B": mnet("verify"),
            "paint_verify_raw_B": vals.get("verify") if vals.get("verify") is not None else "",
            "paint_verify_net_B": (vals["verify"] - non) if (vals.get("verify") is not None and non is not None) else "",
        })

    with open(os.path.join(OUT, "stack_paint.csv"), "w", newline="") as f:
        cols = ["id", "scheme", "param_set", "key", "mode", "run1", "run2", "run3", "max_B", "net_B"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader(); w.writerows(long_rows)
    with open(os.path.join(OUT, "stack_paint_wide.csv"), "w", newline="") as f:
        cols = ["id", "scheme", "param_set", "key", "none_B", "keygen_B", "sign_B", "verify_B",
                "keygen_net_B", "sign_net_B", "verify_net_B"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader(); w.writerows(wide)
    with open(os.path.join(OUT, "stack_paint_vs_massif.csv"), "w", newline="") as f:
        cols = ["id", "scheme", "param_set", "key", "massif_sign_raw_B", "massif_sign_net_B",
                "paint_sign_raw_B", "paint_sign_net_B", "massif_verify_raw_B",
                "massif_verify_net_B", "paint_verify_raw_B", "paint_verify_net_B"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader(); w.writerows(cmp_rows)

    print("wrote stack_paint.csv / stack_paint_wide.csv / stack_paint_vs_massif.csv")
    for r in wide:
        print(r)


if __name__ == "__main__":
    main()
