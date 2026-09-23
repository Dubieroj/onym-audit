#!/usr/bin/env python3
"""Render the public pages in every language from web/*.html + web/i18n.json.

  python3 tools/build_landing.py          # write public/{,ru/,cnr/}{,order/}index.html
  python3 tools/build_landing.py --check  # non-zero if the committed pages are stale

One template per page and one string file, so hand-kept copies cannot drift.
Standard library only.
"""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "https://foldy.io/audit/"
LANGS = [  # code, path, BCP 47 tag, switcher label
    ("en", "", "en", "EN"),
    ("ru", "ru/", "ru", "RU"),
    ("cnr", "cnr/", "sr-Latn-ME", "CNR"),
]
PAGES = [  # template, page path under the language, the JS strings key
    ("landing.html", "", "js"),
    ("order.html", "order/", "order_js"),
]
JS_KEYS = {js for _, _, js in PAGES}

def render(template, strings, code, lpath, tag, ppath, jskey):
    here = lpath + ppath
    root = "../" * here.count("/")
    s = {k: (v.replace("{{root}}", root) if isinstance(v, str) else v)
         for k, v in strings[code].items() if k not in JS_KEYS}
    s["lang_tag"] = tag
    s["root"] = root
    s["home"] = "../" * ppath.count("/") or "./"
    s["js"] = json.dumps(strings[code][jskey], ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    s["alternates"] = "\n".join(
        f'<link rel="alternate" hreflang="{t}" href="{BASE}{p}{ppath}">' for _, p, t, _ in LANGS
    ) + f'\n<link rel="alternate" hreflang="x-default" href="{BASE}{ppath}">'
    s["switcher"] = "".join(
        f'<a href="{root}{p}{ppath}" hreflang="{t}" lang="{t}"' + (' aria-current="page"' if c == code else "") + f">{label}</a>"
        for c, p, t, label in LANGS
    )
    out = re.sub(r"\{\{(\w+)\}\}", lambda m: s[m.group(1)] if m.group(1) in s else m.group(0), template)
    left = re.findall(r"\{\{\w+\}\}", out)
    if left:
        sys.exit(f"{code}/{ppath}: unfilled placeholders {sorted(set(left))}")
    return out

def main():
    strings = json.loads((ROOT / "web/i18n.json").read_text())
    check = "--check" in sys.argv
    stale = []
    for tname, ppath, jskey in PAGES:
        template = (ROOT / "web" / tname).read_text()
        for code, lpath, tag, _ in LANGS:
            out = render(template, strings, code, lpath, tag, ppath, jskey)
            dest = ROOT / "public" / lpath / ppath / "index.html"
            if check:
                if not dest.exists() or dest.read_text() != out:
                    stale.append(str(dest.relative_to(ROOT)))
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(out)
                print("wrote", dest.relative_to(ROOT))
    if stale:
        sys.exit("stale: " + ", ".join(stale) + " (run python3 tools/build_landing.py)")

main()
