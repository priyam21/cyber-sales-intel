"""Bundle the static app into ONE offline HTML file: the same page as the live link, data included.

    python -I pipeline/bundle_app.py app report/exposure-radar-app.html

style.css and app.js are inlined unchanged. The two JSON files go into <script type="application/json">
tags, and a small fetch shim answers app.js's `fetch("data/...")` calls from those tags, so app.js
stays byte-identical to the hosted version and the file works from file:// with no server or network.
"""
from __future__ import annotations

import argparse
import json
import os

DATA_FILES = ["data/app_data.json", "data/evaluation.json"]

SHIM = """<script>
// Offline bundle: serve the app's data/*.json requests from the inline tags below.
(() => {
  const inline = %s;
  const realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = (url, opts) => {
    const id = inline[String(url)];
    if (id) {
      const body = document.getElementById(id).textContent;
      return Promise.resolve(new Response(body, { status: 200, headers: { "Content-Type": "application/json" } }));
    }
    return realFetch ? realFetch(url, opts) : Promise.reject(new Error("offline"));
  };
})();
</script>"""


def safe_script_text(s: str) -> str:
    """JSON inside <script> must not contain '</' (would close the tag early)."""
    return s.replace("</", "<\\/")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("app_dir")
    ap.add_argument("out_path")
    a = ap.parse_args()

    read = lambda p: open(os.path.join(a.app_dir, p), encoding="utf-8").read()
    page = read("index.html")
    css, js = read("style.css"), read("app.js")

    tags, ids = [], {}
    for i, path in enumerate(DATA_FILES):
        full = os.path.join(a.app_dir, path)
        if not os.path.exists(full):
            continue
        # re-serialise compactly; content is identical, whitespace is not
        body = json.dumps(json.load(open(full, encoding="utf-8")), separators=(",", ":"), ensure_ascii=False)
        ids[path] = f"inline-data-{i}"
        tags.append(f'<script type="application/json" id="inline-data-{i}">{safe_script_text(body)}</script>')

    assert '<link rel="stylesheet" href="style.css">' in page and '<script src="app.js"></script>' in page
    page = page.replace('<link rel="stylesheet" href="style.css">', f"<style>\n{css}\n</style>")
    page = page.replace('<script src="app.js"></script>',
                        "\n".join(tags) + "\n" + SHIM % json.dumps(ids) + f"\n<script>\n{safe_script_text(js)}\n</script>")
    with open(a.out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"wrote {a.out_path} ({os.path.getsize(a.out_path) / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
