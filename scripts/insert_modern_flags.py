#!/usr/bin/env python3
import sys, re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "lib/core/ArgumentsParser.py"

with open(TARGET, "r", encoding="utf-8") as f:
    src = f.read()

if "--modern-runner" in src and "modern_max_concurrent" in src:
    print("[*] Flags already present in", TARGET)
    raise SystemExit(0)

pat = re.compile(r"(running\.add_argument\(\s*'-d'.*?dest='debug'.*?\)\s*\))", re.S)
m = pat.search(src)
if not m:
    print("[!] Could not find debug flag block to anchor insertion.", file=sys.stderr)
    raise SystemExit(2)

insertion = """
    # Modern async execution engine
    running.add_argument(
        '--modern-runner',
        help='Use asyncio-based modern runner (non-blocking subprocesses)',
        action='store_true', dest='modern_runner', default=False)
    running.add_argument(
        '--modern-max-concurrent',
        help='Max concurrent commands for modern runner (default: 8)',
        type=int, dest='modern_max_concurrent', default=8)
"""

new_src = src[:m.end()] + insertion + src[m.end():]
with open(TARGET, "w", encoding="utf-8") as f:
    f.write(new_src)
print("[*] Inserted modern-runner flags into", TARGET)
