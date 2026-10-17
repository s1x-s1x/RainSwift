#!/usr/bin/env python3
"""Finite stage00b source/layout/witness audit. No source writes or security claim.

Reads the frozen Q1 instance and two native protocol dumps; validates dimensions,
hash input lengths, role separation and Rain witness/round equations independently
with scalar GF(2)[x] arithmetic. Outputs must be a fresh Q4 evidence directory.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def clmul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a <<= 1
        b >>= 1
    return out


MOD = (1 << 128) | 0x87


def pmod(a):
    while a.bit_length() > 128:
        a ^= MOD << (a.bit_length() - 129)
    return a


def mul(a, b):
    return pmod(clmul(a, b))


def inv(a):
    if not a:
        return 0
    r0, r1, s0, s1 = MOD, a, 0, 1
    while r1:
        q, rem = 0, r0
        while rem and rem.bit_length() >= r1.bit_length():
            shift = rem.bit_length() - r1.bit_length()
            q ^= 1 << shift
            rem ^= r1 << shift
        r0, r1, s0, s1 = r1, rem, s1, s0 ^ clmul(q, s1)
    return pmod(s0)


def matvec(cols, x):
    out = 0
    for i, col in enumerate(cols):
        if (x >> i) & 1:
            out ^= col
    return out


def flatten(xs):
    if isinstance(xs, list):
        return [y for x in xs for y in flatten(x)]
    return [int(xs, 16)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rain3", type=Path, required=True)
    ap.add_argument("--rain4", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    start = time.monotonic()
    q4 = Path(__file__).resolve().parents[2]
    iteration = q4.parent
    src = iteration / "源码" / "rain-voleith"
    out = args.output.resolve()
    if not out.is_relative_to(q4 / "原始数据" / "重做00b"):
        raise ValueError("Output outside stage evidence directory")
    out.mkdir(parents=True, exist_ok=False)
    frozen_path = iteration / "Q1_实例冻结" / "Q1_冻结参数.json"
    frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
    ptext = (src / "parameters.hpp").read_text(encoding="utf-8")
    rtext = (src / "rain_params.hpp").read_text(encoding="utf-8")
    records = []

    def check(name, ok, detail=None):
        records.append({"check": name, "pass": bool(ok), "detail": detail})

    source_before = {p.relative_to(src).as_posix(): sha(p) for p in src.rglob("*")
                     if p.is_file() and "粘贴的" not in p.name}
    (out / "source_sha256_before.json").write_text(json.dumps(source_before, indent=2), encoding="utf-8")
    params = re.findall(r"using (rain([34])_(fast|bal|short)) = parameter_set<secpar::s128, (\d+), owf::rain[34], prg::aes_ctr, prg::aes_ctr, leaf_hash::aes_ctr, (\d+), \{bavc::ggm_forest, 0\}>;", ptext)
    check("all six exact AES-CTR/GGM template specializations present", len(params) == 6)
    textc = (src / "constants.hpp").read_text(encoding="utf-8")
    check("Rain uses B_bytes=6", bool(re.search(r"if constexpr \(is_owf_rain\(P::owf_v\)\)[^\n]*\n\s*return 6;", textc)))
    leaf_hash = (src / "vector_com.inc").read_text(encoding="utf-8").split("void prg_leaf_hash<PRG>::hash", 1)[1].split("template", 1)[0]
    check("active leaf-hash specialization explicitly ignores small_tweak", "(void) small_tweak" in leaf_hash)
    for name, values in [("PSI", frozen["PSI"])]:
        line = next(x for x in rtext.splitlines() if re.search(r"\b" + name + r"\[", x))
        pairs = re.findall(r"\{(0x[0-9a-f]+)ull, (0x[0-9a-f]+)ull\}", line)
        actual = [int(a, 16) | int(b, 16) << 64 for a, b in pairs]
        check("frozen source " + name + " equals Q1", actual == flatten(values))
    for R in (3, 4):
        for label, key in (("RC_P", "rc_P"), ("MC_P", "M_P_cols")):
            name = label + str(R)
            line = next(x for x in rtext.splitlines() if re.search(r"\b" + name + r"\[", x))
            pairs = re.findall(r"\{(0x[0-9a-f]+)ull, (0x[0-9a-f]+)ull\}", line)
            actual = [int(a, 16) | int(b, 16) << 64 for a, b in pairs]
            check("frozen source " + name + " equals Q1", actual == flatten(frozen["instances"][str(R)][key]))

    datasets = [json.loads(p.read_text(encoding="utf-8")) for p in (args.rain3, args.rain4)]
    data = [o for ds in datasets for o in ds]
    check("18 native instances, six parameter names", len(data) == 18 and len({o["set"] for o in data}) == 6)
    tiers = {(x["R"], x["tau"], x["w"]): x for x in frozen["tiers"]}
    tables = []
    psi = [int(x, 16) for x in frozen["PSI"]]
    for name, rounds, tier, tau, grinding in params:
        R, tau, grinding = int(rounds), int(tau), int(grinding)
        D = 128 - grinding
        kmin, nmax = divmod(D, tau)
        kmax = (D + tau - 1) // tau
        ks = [kmax if t < nmax else kmin for t in range(tau)]
        Ns = [1 << k for k in ks]
        N = sum(Ns)
        L = 128 * R
        qs_rows, rows = L + 128, L + 128 + 176
        m = (rows + 127) // 128
        commit_bytes = (rows // 8) * (tau - 1)
        open_bytes = 16 * (D + tau)
        sig_bytes = commit_bytes + 22 + L // 8 + 16 + open_bytes + 16 + 16 + 4
        input_h1 = 81 + commit_bytes
        input_h2 = 88 + 22 + 128 * 22 + L // 8 + 1
        role_tweaks = [0] + [((d + 1) * tau + t) for t in range(tau) for d in range(ks[t])] + [((ks[t] + 1) * tau + t) for t in range(tau)] + [(1 << 31) + t for t in range(tau)]
        check(name + ": root/tree-depth/commit/tape role tweaks disjoint within fixed IV", len(role_tweaks) == len(set(role_tweaks)))
        check(name + ": Q1 frozen leaves and signature bytes", tiers[R, tau, grinding]["leaves"] == N and tiers[R, tau, grinding]["total"] == sig_bytes)
        leaf_hash_lengths = sorted({16 * n + 1 for n in Ns})
        outer_hash_length = 32 * tau + 1
        check(name + ": two tag-01 hash roles have disjoint input lengths", outer_hash_length not in leaf_hash_lengths)
        logical_sign = (m + 3) * N - tau
        logical_verify = (m + 3) * (N - tau) - 2 * D
        expected = {"tau": tau, "delta_bits": D, "min_k": kmin, "max_k": kmax,
                    "num_max_k": nmax, "vole_rows": rows, "qs_rows": qs_rows,
                    "witness_bits": L, "col_bytes": 16 * m, "sig_bytes": sig_bytes,
                    "open_size": open_bytes, "leaves": N}
        selected = [o for o in data if o["set"] == name]
        check(name + ": includes randomized and deterministic native cases", bool(selected) and {o["det"] for o in selected} == {0, 1})
        inst = frozen["instances"][str(R)]
        rc = [int(x, 16) for x in inst["rc_P"]]
        matrices = [[int(x, 16) for x in row] for row in inst["M_P_cols"]]
        for o in selected:
            tag = f"{name}#{o['idx']}{'det' if o['det'] else ''}"
            check(tag + ": compiled constants equal independently derived dimensions", all(o[key] == val for key, val in expected.items()))
            h = bytes.fromhex
            sk, pk = h(o["sk"]), h(o["pk"])
            k = matvec(psi, int.from_bytes(sk[16:], "little"))
            pt = matvec(psi, int.from_bytes(sk[:16], "little"))
            ct = matvec(psi, int.from_bytes(pk[16:], "little"))
            state, xs, ys = pt, [], []
            for r in range(R):
                x = state ^ k ^ rc[r]
                y = inv(x)
                xs.append(x)
                ys.append(y)
                state = matvec(matrices[r], y) if r + 1 < R else y
            check(tag + ": independent Rain forward equals public key", state ^ k == ct and pk[:16] == sk[:16])
            witness = b"".join(x.to_bytes(16, "little") for x in [k] + ys[:-1])
            check(tag + ": witness is polynomial-basis k,y0,...,y_(R-2)", h(o["witness"]) == witness)
            check(tag + ": every one of R nonzero inverse constraints x_r*y_r=1", all(mul(x, y) == 1 for x, y in zip(xs, ys)))
            check(tag + ": serialized hash and column lengths", all(len(h(o[key])) == val for key, val in {"mu":32,"seed_r":16,"iv_pre":16,"iv":16,"hcom":32,"chal1":88,"chal2":56,"qs_check":16,"witness":L//8,"u":16*m}.items()))
            if "VH_cols" in o:
                cols = [int.from_bytes(h(x), "little") for x in o["VH_cols"]]
                check(tag + ": actual mask rows are identity at independently computed offset", len(cols) == rows and all(cols[qs_rows + j] == 1 << j for j in range(176)))
            if time.monotonic() - start > 60:
                raise TimeoutError("finite 60-second audit budget")
        tables.append({"set":name, "R":R, "tau":tau, "w":grinding, "D":D, "heights":ks,
                       "leaves_per_tree":Ns, "N_total":N, "N_max":max(Ns), "witness_bits":L,
                       "qs_rows":qs_rows, "vole_rows":rows, "tape_AES_blocks":m,
                       "storage_bytes":16*m, "logical_tape_bytes":rows//8,
                       "corrections_bytes":commit_bytes, "open_bytes":open_bytes,
                       "signature_bytes":sig_bytes, "h_leaf_input_lengths":leaf_hash_lengths,
                       "h_com_input_length":outer_hash_length, "chall1_input_length":input_h1,
                       "chall2_input_length":input_h2, "chall3_input_length":93,
                       "max_structural_tweak":max(x for x in role_tweaks if x < 1 << 31),
                       "sign_AES_logical_calls":logical_sign,
                       "verify_AES_logical_calls":logical_verify,
                       "verify_AES_executed_calls":logical_verify + tau,
                       "verify_discarded_zero_key_commitment_calls":tau,
                       "cases":len(selected)})
    leaf_lengths = set(x for row in tables for x in row["h_leaf_input_lengths"])
    outer_lengths = {row["h_com_input_length"] for row in tables}
    check("all six sets: tag-01 leaf/outer hash roles length-separated", not leaf_lengths & outer_lengths)
    source_after = {p.relative_to(src).as_posix(): sha(p) for p in src.rglob("*")
                    if p.is_file() and "粘贴的" not in p.name}
    check("all frozen source paths and bytes unchanged", source_after == source_before)
    before = json.loads((args.rain4.parent / "source_sha256_before.json").read_text(encoding="utf-8"))
    check("native Rain4 build source hashes equal current frozen source", before == source_before)
    failed = sum(not r["pass"] for r in records)
    result = {"status":"PASS" if not failed else "FAIL", "checks":len(records), "failed":failed,
              "stage":"00b source/protocol mapping only; no security conclusion",
              "timestamp_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
              "elapsed_seconds":round(time.monotonic()-start, 3),
              "inputs":{str(p):sha(p) for p in (args.rain3,args.rain4,frozen_path,Path(__file__))},
              "source_files":len(source_before), "tables":tables, "records":records}
    (out / "audit_results.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    (out / "audit_checks.txt").write_text("\n".join(("PASS " if r["pass"] else "FAIL ")+r["check"] for r in records)+f"\n{len(records)} checks, {failed} failed\n",encoding="utf-8")
    (out / "SHA256SUMS.txt").write_text("\n".join(sha(p)+"  "+p.name for p in sorted(out.iterdir()) if p.is_file())+"\n",encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("status","checks","failed","elapsed_seconds","source_files")},ensure_ascii=False))
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
