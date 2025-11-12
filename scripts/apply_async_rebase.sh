#!/usr/bin/env bash
set -e
REPO="${1:-.}"
ZIP_NAME="jok3r_async_overlay.zip"
if [ ! -f "../${ZIP_NAME}" ]; then
  echo "[!] Expected ../${ZIP_NAME} next to the repo. Move the zip there and re-run."
  exit 1
fi
cd "$REPO"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "[!] Not a git repo"; exit 1; }
BRANCH="modern-runner"
git fetch --all || true
git checkout -b "${BRANCH}" || git checkout "${BRANCH}"
unzip -o "../${ZIP_NAME}"
git add lib/async_runtime.py lib/execution_v2.py lib/db_v2.py lib/modern_runner_patch.py README_MODERN.md scripts/apply_async_rebase.sh || true
git commit -m "Add modern async runner overlay (opt-in via --modern-runner)" || true
git push -u origin "${BRANCH}" || true
echo "[*] Overlay extracted. Now wire --modern-runner flags and enable the patch in your attack path."
