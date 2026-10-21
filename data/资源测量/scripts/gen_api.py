#!/usr/bin/env python3
"""Generate NIST api.h / api.cpp from the implementation's own templates."""
import argparse
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", required=True, choices=["rain", "rfaest", "faest"])
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--pk", required=True, type=int)
    ap.add_argument("--sk", required=True, type=int)
    ap.add_argument("--sig", required=True, type=int)
    args = ap.parse_args()

    mapping = {
        "%PARAMSTYPE%": args.param,
        "%VERSION%": args.name,
        "%PUBLICKEYBYTES%": str(args.pk),
        "%SECRETKEYBYTES%": str(args.sk),
        "%SIGBYTES%": str(args.sig),
    }
    os.makedirs(args.out, exist_ok=True)
    for src_name, dst_name in (("api.h.in", "api.h"), ("api.cpp.in", "api.cpp")):
        with open(os.path.join(args.src, src_name)) as f:
            text = f.read()
        for key, value in mapping.items():
            text = text.replace(key, value)
        with open(os.path.join(args.out, dst_name), "w") as f:
            f.write(text)
    print("generated api.h/api.cpp in", args.out)


if __name__ == "__main__":
    main()
