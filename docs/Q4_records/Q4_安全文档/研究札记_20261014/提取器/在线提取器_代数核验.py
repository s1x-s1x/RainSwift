"""有限 evidence-audit：独立枚举 q，验证在线仿射提取和旧秩乘积的反例。

本脚本不实现签名、不搜索实际密钥、不修改冻结输入。抽象层是给定已知叶子
带和已冻结 H2 输入的 VOLE 转换；它不能替代 oracle 覆盖性或密码安全证明。
"""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
import random
import time


START = time.monotonic()
LIMIT_SECONDS = 110.0


def xor_all(xs):
    z = 0
    for x in xs:
        z ^= x
    return z


def linear_hash(x: int, data_bits: int, rows: list[int]) -> int:
    """H(x)=A data xor mask；row 的位编号与 x 的低端位一致。"""
    data = x & ((1 << data_bits) - 1)
    mask = x >> data_bits
    out = mask
    for b, row in enumerate(rows):
        out ^= ((data & row).bit_count() & 1) << b
    return out


def extract(known, corrections, ks, H, ut, vt, *, strict=True):
    """输入不含 Delta/open。strict=False 时返回允许挑战上的仿射扩展。"""
    descriptors = []
    free_values = []
    for t, (m, c, k) in enumerate(zip(known, corrections, ks)):
        missing = [j for j, x in enumerate(m) if x is None]
        if len(missing) >= 2:
            return {"status": "infeasible", "reason": "two_unknown_leaves", "tree": t}
        z = [0 if x is None else x for x in m]
        U0 = xor_all(z)
        V0 = [xor_all(z[j] for j in range(1 << k) if (j >> b) & 1) for b in range(k)]
        a = U0 ^ c
        if missing:
            beta = missing[0]
            qbeta = [V0[b] ^ (a if (beta >> b) & 1 else 0) for b in range(k)]
            if any(H(qbeta[b]) != (vt[t][b] ^ (ut if (beta >> b) & 1 else 0)) for b in range(k)):
                return {"status": "infeasible", "reason": "fixed_tree_hash_mismatch", "tree": t}
            descriptors.append({"kind": "fixed_missing", "beta": beta, "q": qbeta})
            continue
        D = H(a) ^ ut
        E = [H(v) ^ vhash for v, vhash in zip(V0, vt[t])]
        if D == 0:
            if any(E):
                return {"status": "infeasible", "reason": "free_tree_hash_mismatch", "tree": t}
            descriptors.append({"kind": "free", "a": a, "V": V0})
            free_values.append(a)
        else:
            if any(e not in (0, D) for e in E):
                return {"status": "infeasible", "reason": "no_binary_challenge", "tree": t}
            beta = sum((e == D) << b for b, e in enumerate(E))
            qbeta = [V0[b] ^ (a if (beta >> b) & 1 else 0) for b in range(k)]
            descriptors.append({"kind": "fixed_full", "beta": beta, "q": qbeta})
    if free_values and any(u != free_values[0] for u in free_values):
        return {"status": "au_collision", "free_values": free_values}
    if not free_values and strict:
        return {"status": "fixed_only", "target": [d["beta"] for d in descriptors]}
    U = free_values[0] if free_values else 0
    V = []
    for d, k in zip(descriptors, ks):
        if d["kind"] == "free":
            V.append(d["V"])
        else:
            V.append([d["q"][b] ^ (U if (d["beta"] >> b) & 1 else 0) for b in range(k)])
    return {"status": "ok", "u": U, "V": V, "descriptors": descriptors,
            "hash_compatible": bool(free_values)}


def verifier_q(known, corrections, ks, delta):
    """由被打开的叶子直接重算 q；不调用 extract 的任何辅助计算。"""
    q = []
    for m, c, k, h in zip(known, corrections, ks, delta):
        if any(m[j] is None for j in range(1 << k) if j != h):
            return None
        row = []
        for b in range(k):
            z = c if (h >> b) & 1 else 0
            for j in range(1 << k):
                if j != h and ((j ^ h) >> b) & 1:
                    z ^= m[j]
            row.append(z)
        q.append(row)
    return q


def inspect_case(known, c, ks, H, ut, vt, result):
    ex = extract(known, c, ks, H, ut, vt)
    result["statuses"][ex["status"]] = result["statuses"].get(ex["status"], 0) + 1
    num_valid = 0
    for delta in itertools.product(*(range(1 << k) for k in ks)):
        q = verifier_q(known, c, ks, delta)
        if q is None:
            continue
        if any(H(q[t][b]) != (vt[t][b] ^ (ut if (delta[t] >> b) & 1 else 0))
               for t, k in enumerate(ks) for b in range(k)):
            continue
        num_valid += 1
        result["hash_valid_openings"] += 1
        assert ex["status"] != "infeasible", (known, c, ut, vt, delta, ex)
        if ex["status"] == "au_collision":
            result.setdefault("first_au_collision", {"known": known, "c": c, "u_tilde": ut,
                                                     "V_tilde": vt, "delta": delta,
                                                     "free_values": ex["free_values"]})
            continue
        if ex["status"] == "fixed_only":
            assert list(delta) == ex["target"], (known, c, ut, vt, delta, ex)
            affine = extract(known, c, ks, H, ut, vt, strict=False)
            assert affine["status"] == "ok"
            assert all(q[t][b] == (affine["V"][t][b] ^ (affine["u"] if (delta[t] >> b) & 1 else 0))
                       for t, k in enumerate(ks) for b in range(k))
            continue
        assert ex["status"] == "ok"
        assert H(ex["u"]) == ut
        assert all(H(ex["V"][t][b]) == vt[t][b] for t, k in enumerate(ks) for b in range(k))
        assert all(q[t][b] == (ex["V"][t][b] ^ (ex["u"] if (delta[t] >> b) & 1 else 0))
                   for t, k in enumerate(ks) for b in range(k)), (known, c, ut, vt, delta, ex)
        result["affine_equalities"] += sum(ks)
    if ex["status"] == "fixed_only":
        assert num_valid <= 1
    result["cases"] += 1
    if result["cases"] % 1024 == 0 and time.monotonic() - START > LIMIT_SECONDS:
        raise TimeoutError("预设墙钟上限触发；没有扩大测试范围")


def exhaustive_two_trees():
    H = lambda x: linear_hash(x, 1, [1])
    result = {"name": "two_trees_exhaustive", "tape_bits": 2, "hash_bits": 1,
              "tree_heights": [1, 1], "cases": 0, "statuses": {},
              "hash_valid_openings": 0, "affine_equalities": 0}
    # 所有 2 位带、所有纠正值、所有 1 位 hash 目标、所有已知/未知模式。
    for tapes in itertools.product(range(4), repeat=4):
        for mask in range(16):
            known = [[tapes[2*t+j] if (mask >> (2*t+j)) & 1 else None for j in range(2)] for t in range(2)]
            for c1 in range(4):
                for ut, v0, v1 in itertools.product(range(2), repeat=3):
                    inspect_case(known, [0, c1], [1, 1], H, ut, [[v0], [v1]], result)
    assert result["cases"] == 131072
    return result


def wider_deterministic_cases():
    rng = random.Random(20261014)
    ks = [2, 1, 2]
    H = lambda x: linear_hash(x, 2, [1, 2, 3])
    result = {"name": "mixed_height_deterministic", "tape_bits": 5, "hash_bits": 3,
              "tree_heights": ks, "seed": 20261014, "cases": 0,
              "statuses": {}, "hash_valid_openings": 0, "affine_equalities": 0}
    for index in range(1024):
        m = [[rng.randrange(32) for _ in range(1 << k)] for k in ks]
        U = xor_all(m[0])
        c = [0] + [U ^ xor_all(tapes) for tapes in m[1:]]
        vt = [[H(xor_all(tapes[j] for j in range(1 << k) if (j >> b) & 1))
               for b in range(k)] for tapes, k in zip(m, ks)]
        ut = H(U)
        known = [list(tapes) for tapes in m]
        for t, k in enumerate(ks):
            count = (index // (3**t)) % 3
            for j in rng.sample(range(1 << k), count):
                known[t][j] = None
        if index % 2:
            c = [0, rng.randrange(32), rng.randrange(32)]
            ut = rng.randrange(8)
            vt = [[rng.randrange(8) for _ in range(k)] for k in ks]
        inspect_case(known, c, ks, H, ut, vt, result)
    return result


def old_rank_counterexamples():
    # 2-bit data, 6-bit mask：真实 VHash 的 [A|I] 形态，满秩为 6。
    rows = [1, 2, 3, 1, 2, 3]
    H = lambda x: linear_hash(x, 2, rows)
    outputs = {H(x) for x in range(256)}
    assert len(outputs) == 64
    kernel = [x for x in range(256) if H(x) == 0]
    assert len(kernel) == 4
    # λtoy=4；同一密钥两个 tape 输入已返回 3、10。commit 输入不同且还未查询。
    tape_outputs = [3, 10]
    tape = tape_outputs[0] | (tape_outputs[1] << 4)
    target_hash = H(tape)  # 在 commit 查询前选定，之后不再改动。
    remaining_outputs = [x for x in range(16) if x not in tape_outputs]
    target_com = remaining_outputs[0]
    hit_count = sum(y == target_com and H(tape) == target_hash for y in remaining_outputs)
    assert hit_count == 1
    # 每个未占用输出都对应同样数目的完整置换，因此 1/14 是精确条件概率。
    return {
        "scope": "只反驳旧的无条件LateHit乘VHash因子，不是签名伪造",
        "global_rank": 6,
        "rank_kernel_counterexample": {"kernel": kernel, "H_on_kernel": [H(x) for x in kernel],
                                      "conditional_Pr_H_zero": "1", "claimed_uniform_Pr": "1/64"},
        "old_tape_new_com": {"lambda_toy": 4, "known_tape_outputs": tape_outputs,
                             "remaining_commit_outputs": remaining_outputs,
                             "fixed_commit_target": target_com, "fixed_tape_hash": target_hash,
                             "conditional_Pr_VHash_pass_given_LateHit": "1",
                             "exact_joint_probability": "1/14",
                             "unjustified_product": "1/(14*64)", "ratio": 64},
    }


def unknown_leaf_example():
    H = lambda x: linear_hash(x, 1, [1])
    known = [[1, 2], [3, None]]
    ex = extract(known, [0, 0], [1, 1], H, 0, [[1], [0]])
    assert ex["status"] == "ok"
    assert ex["u"] == 3
    # 第 1 树只能隐藏叶子 1；第 0 树两种挑战都成立。缺一叶仍可完成提取。
    valid = []
    for d in itertools.product(range(2), repeat=2):
        q = verifier_q(known, [0, 0], [1, 1], d)
        if q is not None and all(H(q[t][0]) == ([1, 0][t] ^ (0 if d[t] else 0)) for t in range(2)):
            valid.append(list(d))
    assert valid == [[0, 1], [1, 1]]
    return {"known": known, "u_tilde": 0, "V_tilde": [[1], [0]], "extraction": ex,
            "valid_delta_tuples": valid, "point": "单树未知叶不应被当作整个提取器稀有失败"}


def main():
    result = {"date_local": "2026-10-14", "timezone": "Asia/Shanghai",
              "activity": "finite evidence-audit", "status": "running",
              "limits": {"wall_seconds": 110, "processes": 1, "target_memory_mib": 512},
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    target = Path(__file__).parent / "原始数据" / "提取器代数核验_20261014.json"
    target.parent.mkdir(exist_ok=True)
    try:
        result["exhaustive"] = exhaustive_two_trees()
        result["mixed_height"] = wider_deterministic_cases()
        result["counterexamples"] = old_rank_counterexamples()
        result["unknown_leaf_example"] = unknown_leaf_example()
        result["status"] = "PASS_FOR_STATED_FINITE_CHECKS"
    except Exception as exc:
        result["status"] = "FAIL_OR_LIMIT"
        result["error"] = repr(exc)
        raise
    finally:
        result["elapsed_seconds"] = round(time.monotonic() - START, 6)
        temp = target.with_suffix(".json.tmp")
        temp.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temp.replace(target)
        print(json.dumps({"status": result["status"], "output": str(target),
                          "elapsed_seconds": result["elapsed_seconds"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
