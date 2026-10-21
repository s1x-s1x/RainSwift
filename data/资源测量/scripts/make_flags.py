#!/usr/bin/env python3
"""Generate build_flags/<key>.txt: compiler, full flags, API/probe/link commands."""
import csv
import json
import os
import re

S = "<HOME>/rain-bench-20261016/storage_test"
W = "<HOME>/rain-bench-20261016"
OUT = os.path.join(S, "build_flags")
os.makedirs(OUT, exist_ok=True)


def read_impls():
    with open(os.path.join(S, "scripts", "impls.tsv")) as f:
        return list(csv.DictReader(f, delimiter="\t"))


def first_command(path):
    with open(path, errors="replace") as f:
        for line in f:
            if " -c " in line or " -o " in line:
                return line.strip()
    return ""


def link_line(setting):
    path = os.path.join(S, "logs", "onetree2.log")
    with open(path, errors="replace") as f:
        for line in f:
            if setting in line and "_bench" in line and line.strip().startswith("/"):
                return line.strip()
    return ""


def meson_includes(tree):
    path = os.path.join(S, "build", tree, "meson-info", "intro-targets.json")
    if not os.path.exists(path):
        return ""
    with open(path) as f:
        data = json.load(f)
    out = []
    for t in data:
        if t.get("name") != "faest":
            continue
        for s in t.get("target_sources", []):
            for p in s.get("parameters", []):
                if p.startswith("-I"):
                    out.append(p)
    return " ".join(dict.fromkeys(out))


def main():
    impls = read_impls()
    tree_src = {"rain": "q5/work/rain", "rfaest": "q5/work/rfaest", "faest": "q5/work/faest_v3"}
    for row in impls:
        key = row["key"]
        tree = row["tree"]
        lines = []
        lines.append("# %s %s (id=%s)" % (row["scheme"], row["param_set"], row["id"]))
        lines.append("# source: %s" % row["source_commit"])
        lines.append("# compiler: %s" % row["compiler"])
        lines.append("# optimization/ISA are identical to the A-line build except -march native -> x86-64-v3")
        lines.append("")
        if tree != "one-tree":
            lib = os.path.join(OUT, "lib_%s.txt" % tree)
            with open(lib, errors="replace") as f:
                cmds = [l.strip() for l in f if l.strip()]
            lines.append("## implementation library compile commands (ninja -t commands)")
            lines.extend(cmds)
            lines.append("")
            lines.append("## NIST API wrapper (new file; implementation sources untouched)")
            incs = meson_includes(tree)
            lines.append("zig-c++ -std=c++23 -O3 -DNDEBUG -march=x86_64_v3 -maes -mpclmul -g0 \\")
            lines.append("  -I%s %s \\" % (tree_src[tree], incs))
            lines.append("  -c impls/%s/work/api.cpp -o impls/%s/work/api.o" % (key, key))
            lines.append("")
            lines.append("## probe and randomness bridge")
            lines.append("zig-cc -O2 -std=c11 -Iimpls/%s/work -c scripts/probe.c -o impls/%s/work/probe.o" % (key, key))
            lines.append("zig-cc -O2 -std=c11 -c scripts/rand_wrap.c -o impls/%s/work/rand_wrap.o" % key)
            lines.append("")
            lines.append("## link (--gc-sections supplies the M5 image scope)")
            lines.append("zig-c++ -O3 -Wl,--gc-sections \\")
            lines.append("  impls/%s/work/probe.o impls/%s/work/api.o impls/%s/work/rand_wrap.o \\" % (key, key, key))
            lines.append("  build/%s/libfaest.a build/%s/librandomness_os.a build/%s/subprojects/xkcp/libxkcp.a \\" % (tree, tree, tree))
            lines.append("  -lm -o impls/%s/probe_%s" % (key, key))
        else:
            setting = row["setting"]
            lines.append("## implementation compile command (measured; Makefile.variant, all objects share these flags)")
            lines.append("gcc -std=c11 -pedantic-errors -Wall -Wextra -Wno-ignored-attributes \\")
            lines.append("  -O2 -march=x86-64-v3 -maes -mpclmul -DNDEBUG -MMD -MP \\")
            lines.append("  -c -o Additional_Implementations/%s/api.o Additional_Implementations/%s/api.c" % (setting, setting))
            lines.append("# all C objects use the same flags; C++ objects add -std=c++20")
            lines.append("")
            lines.append("## link (implementation objects + probe; -Wl,--gc-sections)")
            lines.append("# The line below is the author's bench link command, recorded only to show the")
            lines.append("# Makefile's complete link flags. It includes Catch2 and is NOT used by the probe.")
            link = link_line(setting)
            if link:
                lines.append("# " + link.replace(W + "/源码/faest-one-tree/", "<SRC>/"))
            lines.append("g++ -O2 -Wl,--gc-sections -static-libstdc++ -static-libgcc \\")
            lines.append("  impls/%s/work/probe.o <all non-test objects of %s> \\" % (key, setting))
            lines.append("  -lcrypto -lm -o impls/%s/probe_%s" % (key, key))
        with open(os.path.join(OUT, "%s.txt" % key), "w") as f:
            f.write("\n".join(lines) + "\n")
        print("wrote", key)


if __name__ == "__main__":
    main()
