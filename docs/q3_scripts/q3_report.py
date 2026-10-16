"""迭代030 Q3：把已审计的窗口摘要汇总为四项指标、比值、参考线与稳定性（本机运行，只读）。

用法：python -I -X utf8 q3_report.py 摘要目录 输出目录
  摘要目录下须有 F1/S1（主窗口）及 F2/S2、F3/S3（重复窗口）的 <标签>_summary.json，
  均为 summarize_q3_window.py 输出且 status = verified_complete_q3_window。
输出：q3_report.json、q3_report.md（新建，不覆盖）。
口径（冻结计划 §4.3–§4.4）：主结果只取主窗口；重复窗口并列报告，不择优；参考线只作参考，不作通过／失败判定。
比值约定：签发、验签“加速倍数”= 对照中位数 ÷ Rain 中位数（>1 表示 Rain 更快）；建钥与签名长度给“Rain ÷ 对照”。
"""
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from q3_common import IMPLS, WINDOWS, read_json, require, sha256  # noqa: E402

PRIMARY = {"F": "F1", "S": "S1"}
REPLICATES = {"F": ("F2", "F3"), "S": ("S2", "S3")}
RAIN = {"F": ("rain3_fast", "rain3_bal", "rain4_fast", "rain4_bal"), "S": ("rain3_short", "rain4_short")}
COMPARATORS = {"F": ("faest_v3_128f", "rfaest_128f", "lynxer_128f"), "S": ("rfaest_128s", "faest_v3_128s")}
P0_REFERENCE = {  # 迭代028 P0 正式窗口（2026-10-10，服务器近乎空闲，load1≈0.3），只作漂移参考
    "faest_v3_128f": {"kg_median_ns": 1212, "sign_median_ns": 667542, "verify_median_ns": 414747},
    "rfaest_128f": {"kg_median_ns": 1222, "sign_median_ns": 398277, "verify_median_ns": 325551},
    "lynxer_128f": {"kg_median_ns": 61275, "sign_median_ns": 420518, "verify_median_ns": 363612},
}


def load(directory):
    summaries = {}
    for window_set in WINDOWS:
        for label in (PRIMARY[window_set],) + REPLICATES[window_set]:
            path = directory / (label + "_summary.json")
            value = read_json(path)
            require(value.get("status") == "verified_complete_q3_window" and value.get("window_set") == window_set
                    and value.get("window_label") == label and value.get("errors") == [], "unverified summary: " + label)
            require(tuple(value["implementations"]) == WINDOWS[window_set], "implementation list drift: " + label)
            value["_sha256"] = sha256(path)
            summaries[label] = value
    return summaries


def pooled(summary, name):
    return summary["results"][name]["all_three_batches"]


def ratios(summary, window_set):
    out = {}
    for rain in RAIN[window_set]:
        r = pooled(summary, rain)
        for comp in COMPARATORS[window_set]:
            c = pooled(summary, comp)
            out[rain + "|" + comp] = {
                "sign_speedup": c["sign_median_ns"] / r["sign_median_ns"],
                "verify_speedup": c["verify_median_ns"] / r["verify_median_ns"],
                "keygen_time_ratio": r["kg_median_ns"] / c["kg_median_ns"],
                "signature_size_ratio": r["signature_bytes"] / c["signature_bytes"],
                "signature_bytes_delta": r["signature_bytes"] - c["signature_bytes"],
            }
    return out


def reference_lines(summary, window_set):
    """冻结计划 §4.4 的参考线逐条对照；met 只表示数值关系，不是验收判定。"""
    lines = []
    def add(rain, line, measured, threshold, relation, met):
        lines.append({"rain": rain, "line": line, "measured": measured, "threshold": threshold,
                      "relation": relation, "met_reference_only": met})
    if window_set == "F":
        rf = pooled(summary, "rfaest_128f")
        fv = pooled(summary, "faest_v3_128f")
        for rain in ("rain3_fast", "rain4_fast"):
            r = pooled(summary, rain)
            s, v = rf["sign_median_ns"] / r["sign_median_ns"], rf["verify_median_ns"] / r["verify_median_ns"]
            add(rain, "快档：签发比 rFAEST-EM-128f 快至少 1.3 倍", s, 1.3, ">=", s >= 1.3)
            add(rain, "快档：验签比 rFAEST-EM-128f 快至少 1.3 倍", v, 1.3, ">=", v >= 1.3)
            add(rain, "快档：签名小于 4,170 B", r["signature_bytes"], 4170, "<", r["signature_bytes"] < 4170)
        for rain in ("rain3_bal", "rain4_bal"):
            r = pooled(summary, rain)
            for comp, c in (("FAEST-v3-EM-128f", fv), ("rFAEST-EM-128f", rf)):
                for key, label in (("kg_median_ns", "建钥"), ("sign_median_ns", "签发"), ("verify_median_ns", "验签"),
                                   ("signature_bytes", "签名长度")):
                    add(rain, "均衡档：%s不输 %s" % (label, comp), r[key], c[key], "<=", r[key] <= c[key])
    for rain in RAIN[window_set]:
        r = pooled(summary, rain)
        for comp in COMPARATORS[window_set]:
            c = pooled(summary, comp)
            ratio = r["kg_median_ns"] / c["kg_median_ns"]
            add(rain, "建钥：不慢于 %s 的 1.05 倍" % IMPLS[comp]["algorithm"], ratio, 1.05, "<=", ratio <= 1.05)
    return lines


def stability(summaries, window_set):
    labels = (PRIMARY[window_set],) + REPLICATES[window_set]
    out = {}
    for name in WINDOWS[window_set]:
        entry = {}
        for key in ("kg_median_ns", "sign_median_ns", "verify_median_ns"):
            values = [pooled(summaries[label], name)[key] for label in labels]
            batch_values = [b[key] for b in summaries[PRIMARY[window_set]]["results"][name]["batches"]]
            entry[key] = {"by_window": dict(zip(labels, values)), "max_over_min_across_windows": max(values) / min(values),
                          "primary_batches": batch_values,
                          "max_over_min_across_primary_batches": max(batch_values) / min(batch_values)}
        out[name] = entry
    ratio_spread = {}
    for label in labels:
        for pair, value in ratios(summaries[label], window_set).items():
            for key in ("sign_speedup", "verify_speedup", "keygen_time_ratio"):
                ratio_spread.setdefault(pair, {}).setdefault(key, {})[label] = value[key]
    return out, ratio_spread


def fmt_us(ns):
    return "%.3f" % (ns / 1000)


def fmt_ms(ns):
    return "%.4f" % (ns / 1e6)


def markdown(report, summaries):
    lines = ["# Q3 同机同窗口实测：汇总表（由 q3_report.py 生成）", "",
             "主结果取主窗口 F1、S1；重复窗口 F2/F3、S2/S3 只作稳定性对照。时间为每实现 1,503 个原始样本的合并中位数，"
             "括号内为四分位数 [Q1, Q3]。参考线只作参考，不作通过／失败判定。", ""]
    for window_set in ("F", "S"):
        label = PRIMARY[window_set]
        s = summaries[label]
        lines += ["## 窗口 %s（主窗口 %s，%s → %s）" % (window_set, label, s["start_utc"], s["end_utc"]), "",
                  "| 实现 | 建钥 / µs | 签发 / ms | 验签 / ms | 签名 / B |", "|---|---:|---:|---:|---:|"]
        for name in WINDOWS[window_set]:
            p = pooled(s, name)
            lines.append("| %s | %s [%s, %s] | %s [%s, %s] | %s [%s, %s] | %d |" % (
                IMPLS[name]["algorithm"], fmt_us(p["kg_median_ns"]), fmt_us(p["kg_q1_ns"]), fmt_us(p["kg_q3_ns"]),
                fmt_ms(p["sign_median_ns"]), fmt_ms(p["sign_q1_ns"]), fmt_ms(p["sign_q3_ns"]),
                fmt_ms(p["verify_median_ns"]), fmt_ms(p["verify_q1_ns"]), fmt_ms(p["verify_q3_ns"]),
                p["signature_bytes"]))
        lines += ["", "比值（主窗口；签发／验签为加速倍数 = 对照 ÷ Rain；建钥、签名为 Rain ÷ 对照）：", "",
                  "| Rain | 对照 | 签发加速 | 验签加速 | 建钥时间比 | 签名长度比 |", "|---|---|---:|---:|---:|---:|"]
        for pair, v in report["primary"][window_set]["ratios"].items():
            rain, comp = pair.split("|")
            lines.append("| %s | %s | %.3f× | %.3f× | %.3f | %.3f（%+d B） |" % (
                IMPLS[rain]["algorithm"], IMPLS[comp]["algorithm"], v["sign_speedup"], v["verify_speedup"],
                v["keygen_time_ratio"], v["signature_size_ratio"], v["signature_bytes_delta"]))
        lines += ["", "参考线（冻结计划 §4.4，只作参考）：", "", "| Rain | 参考线 | 实测 | 参考值 | 关系 | 是否达到参考线 |",
                  "|---|---|---:|---:|---|---|"]
        for item in report["primary"][window_set]["reference_lines"]:
            measured = item["measured"]
            shown = "%.3f" % measured if isinstance(measured, float) else str(measured)
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                IMPLS[item["rain"]]["algorithm"], item["line"], shown, item["threshold"], item["relation"],
                "达到" if item["met_reference_only"] else "未达到"))
        lines += ["", "稳定性（各窗口合并中位数之比 max/min；主窗口三批之比 max/min）：", "",
                  "| 实现 | 建钥 跨窗口 | 签发 跨窗口 | 验签 跨窗口 | 签发 主窗口批间 | 验签 主窗口批间 |",
                  "|---|---:|---:|---:|---:|---:|"]
        for name, e in report["stability"][window_set]["implementations"].items():
            lines.append("| %s | %.3f | %.3f | %.3f | %.3f | %.3f |" % (
                IMPLS[name]["algorithm"], e["kg_median_ns"]["max_over_min_across_windows"],
                e["sign_median_ns"]["max_over_min_across_windows"], e["verify_median_ns"]["max_over_min_across_windows"],
                e["sign_median_ns"]["max_over_min_across_primary_batches"],
                e["verify_median_ns"]["max_over_min_across_primary_batches"]))
        lines.append("")
    lines += ["## 与 P0 基线（迭代028，2026-10-10）的漂移（只作参考）", "",
              "| 对照 | 建钥 Q3/P0 | 签发 Q3/P0 | 验签 Q3/P0 |", "|---|---:|---:|---:|"]
    for name, v in report["p0_drift"].items():
        lines.append("| %s | %.3f | %.3f | %.3f |" % (IMPLS[name]["algorithm"], v["kg_median_ns"], v["sign_median_ns"],
                                                     v["verify_median_ns"]))
    lines.append("")
    return "\n".join(lines)


def main():
    directory, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    summaries = load(directory)
    report = {"schema_version": 1, "inputs": {label: s["_sha256"] for label, s in summaries.items()},
              "primary": {}, "stability": {}, "p0_drift": {},
              "conventions": {"speedup": "comparator median / Rain median (sign, verify)",
                              "keygen_time_ratio": "Rain median / comparator median",
                              "signature_size_ratio": "Rain bytes / comparator bytes",
                              "reference_lines": "frozen plan §4.4; reference only, no pass/fail",
                              "primary_windows": PRIMARY, "replicate_windows": REPLICATES}}
    for window_set in WINDOWS:
        primary = summaries[PRIMARY[window_set]]
        report["primary"][window_set] = {"label": PRIMARY[window_set],
                                         "results": {n: pooled(primary, n) for n in WINDOWS[window_set]},
                                         "ratios": ratios(primary, window_set),
                                         "reference_lines": reference_lines(primary, window_set)}
        impl_stability, ratio_spread = stability(summaries, window_set)
        report["stability"][window_set] = {"implementations": impl_stability, "ratios_by_window": ratio_spread}
    for name, ref in P0_REFERENCE.items():
        now = pooled(summaries["F1"], name)
        report["p0_drift"][name] = {key: now[key] / value for key, value in ref.items()}
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "q3_report.json").open("x", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, allow_nan=False)
        f.write("\n")
    with (out_dir / "q3_report.md").open("x", encoding="utf-8", newline="\n") as f:
        f.write(markdown(report, summaries))
    print("report written:", (out_dir / "q3_report.md").as_posix())


if __name__ == "__main__":
    main()
