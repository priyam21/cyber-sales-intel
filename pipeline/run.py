"""Orchestrate many scan files: extract each new file once (idempotent), then rescore the window.

    python -I pipeline/run.py "/landing/*.zst" data --top 6000

* Map: every file is independent -> extracted once to data/facts/file_id=<sha>/ and recorded in
  data/manifest.json. Re-running skips files already done, so a cron/queue can call this blindly.
  On a cluster the same function runs one file per container (S3 event -> job), nothing shared.
* Reduce: score.py reads only the Parquet facts (~0.5% of raw JSON size), so rescoring a month
  is one DuckDB aggregation rather than re-parsing raw JSON.
* Publish: copy the scored data into app/data/ and rebuild report/exposure-radar-app.html, the
  single-file offline replica of the live app, so the two never drift apart.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def file_id(path: str) -> str:
    return hashlib.sha1(os.path.abspath(path).encode()).hexdigest()[:12]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pattern", help="glob of input .zst files")
    ap.add_argument("data_dir")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--top", type=int, default=6000)
    ap.add_argument("--app-dir", default=os.path.join(ROOT, "app"), help="static app whose data/ is refreshed")
    ap.add_argument("--replica", default=os.path.join(ROOT, "report", "exposure-radar-app.html"),
                    help="single-file offline copy of the app, rebuilt on every run")
    a = ap.parse_args()

    facts, out = os.path.join(a.data_dir, "facts"), os.path.join(a.data_dir, "out")
    manifest_path = os.path.join(a.data_dir, "manifest.json")
    manifest = json.load(open(manifest_path)) if os.path.exists(manifest_path) else {}

    for path in sorted(glob.glob(a.pattern)):
        fid = file_id(path)
        if manifest.get(fid, {}).get("status") == "done":
            print(f"skip {path} (already extracted as {fid})")
            continue
        t0 = time.time()
        subprocess.run([sys.executable, "-I", os.path.join(HERE, "extract.py"), path, facts,
                        "--workers", str(a.workers)], check=True)
        manifest[fid] = {"path": path, "status": "done", "secs": round(time.time() - t0),
                         "bytes": os.path.getsize(path)}
        with open(manifest_path, "w") as fh:
            json.dump(manifest, fh, indent=1)

    subprocess.run([sys.executable, "-I", os.path.join(HERE, "score.py"), facts, out, "--top", str(a.top)], check=True)
    subprocess.run([sys.executable, "-I", os.path.join(HERE, "evaluate.py"), out], check=True)

    # Publish: refresh the app's data, then rebuild the single-file replica of the live app.
    os.makedirs(os.path.join(a.app_dir, "data"), exist_ok=True)
    for name in ("app_data.json", "evaluation.json"):
        shutil.copyfile(os.path.join(out, name), os.path.join(a.app_dir, "data", name))
    os.makedirs(os.path.dirname(os.path.abspath(a.replica)), exist_ok=True)
    subprocess.run([sys.executable, "-I", os.path.join(HERE, "bundle_app.py"), a.app_dir, a.replica], check=True)


if __name__ == "__main__":
    main()
