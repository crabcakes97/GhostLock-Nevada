#!/usr/bin/env python3
"""embed_payloads.py — 将二进制荷载嵌入为 C 数组

用法:
  python3 embed_payloads.py \
    --unplus ../build/unplus \
    --preload ../build/unplus_preload.so \
    --magiskpolicy ~/Downloads/.../magiskpolicy \
    --ksud ~/Downloads/.../libksud.so \
    --kernelsu ~/Downloads/.../kernelsu.ko \
    --out payload/

生成 payload/payload_data.h
"""

import argparse
import os
import sys

# Device-side release paths (must match src/root.c and wrapper/main.c).
PAYLOAD_DIR = "/data/local/tmp"
PAYLOADS = [
    ("unplus",        "unplus",          f"{PAYLOAD_DIR}/unplus_exploit"),
    ("preload",       "preload.so",      f"{PAYLOAD_DIR}/unplus_preload.so"),
    ("magiskpolicy",  "magiskpolicy",    f"{PAYLOAD_DIR}/magiskpolicy"),
    ("ksud",          "ksud",            f"{PAYLOAD_DIR}/ksud"),
    ("kernelsu",      "kernelsu.ko",     f"{PAYLOAD_DIR}/android15-6.6_kernelsu.ko"),
]

def main():
    parser = argparse.ArgumentParser(description="Embed binaries as C arrays")
    for p in PAYLOADS:
        parser.add_argument(f"--{p[0]}", help=f"Path to {p[1]}")
    parser.add_argument("--out", default="payload", help="Output directory")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    payloads = []
    for flag, name, dest in PAYLOADS:
        src = getattr(args, flag)
        if not src:
            print(f"  SKIP {name}: no --{flag}")
            continue
        if not os.path.exists(src):
            print(f"  ERROR: {src} not found")
            sys.exit(1)
        with open(src, "rb") as f:
            data = f.read()
        is_exec = not name.endswith(".so") and not name.endswith(".ko")
        payloads.append({"name": name, "dest": dest, "data": data, "is_exec": is_exec})
        print(f"  {name}: {len(data)} bytes ({src})")

    if not payloads:
        print("ERROR: at least one payload required")
        sys.exit(1)

    out_path = os.path.join(args.out, "payload_data.h")
    with open(out_path, "w") as f:
        f.write("// AUTO-GENERATED — DO NOT EDIT\n")
        f.write("#pragma once\n")
        f.write("#include <stdint.h>\n")
        f.write("#include <stddef.h>\n\n")

        f.write("struct payload {\n")
        f.write("  const char *name;\n")
        f.write("  const char *dest_path;\n")
        f.write("  const uint8_t *data;\n")
        f.write("  size_t size;\n")
        f.write("  int is_exec;\n")
        f.write("};\n\n")

        for p in payloads:
            var = f"_payload_{p['name'].replace('.','_').replace('-','_')}"
            sz = len(p["data"])
            f.write(f"static const uint8_t {var}[{sz}] = {{\n  ")
            for i, b in enumerate(p["data"]):
                f.write(f"0x{b:02x},")
                if (i + 1) % 12 == 0 and i + 1 < sz:
                    f.write(f"\n  ")
            f.write(f"\n}};\n\n")

        f.write(f"#define PAYLOAD_COUNT {len(payloads)}\n\n")
        f.write("static const struct payload payloads[] = {\n")
        for p in payloads:
            var = f"_payload_{p['name'].replace('.','_').replace('-','_')}"
            f.write(f'  {{ "{p["name"]}", "{p["dest"]}", {var}, {len(p["data"])}, {1 if p["is_exec"] else 0} }},\n')
        f.write("};\n")

    total = sum(len(p["data"]) for p in payloads)
    print(f"\n  wrote {out_path} ({total} bytes total)")

if __name__ == "__main__":
    main()
