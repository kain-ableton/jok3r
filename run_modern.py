#!/usr/bin/env python3
import os, sys, importlib.util

def main():
    argv = sys.argv[1:]
    maxc = 8
    for i, a in enumerate(argv):
        if a == "--modern-max-concurrent" and i + 1 < len(argv):
            try:
                maxc = int(argv[i+1])
            except Exception:
                pass

    if "--modern-runner" in argv:
        try:
            from lib.modern_runner_patch import enable as _enable_modern_runner
            _enable_modern_runner(maxc)
        except Exception as e:
            print(f"[modern-runner] enable failed: {e}", file=sys.stderr)

    repo_dir = os.path.dirname(os.path.abspath(__file__))
    main_script = os.path.join(repo_dir, "jok3r.py")
    if not os.path.isfile(main_script):
        print("[!] jok3r.py not found next to run_modern.py", file=sys.stderr)
        sys.exit(1)

    spec = importlib.util.spec_from_file_location("jok3r_main", main_script)
    mod = importlib.util.module_from_spec(spec)
    sys.argv = ["jok3r.py"] + argv
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

if __name__ == "__main__":
    main()
