#!/usr/bin/env python3
"""Render the landing in every language from web/landing.html + web/i18n.json.

  python3 tools/build_landing.py          # write public/{,ru/,cnr/}index.html
  python3 tools/build_landing.py --check  # non-zero if the committed pages are stale

One template and one string file, so three hand-kept copies cannot drift.
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

def render(template, strings, code, path, tag):
    s = dict(strings[code])
    js = s.pop("js")
    s["lang_tag"] = tag
    s["root"] = "../" if path else ""
    s["js"] = json.dumps(js, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    s["alternates"] = "\n".join(
        f'<link rel="alternate" hreflang="{t}" href="{BASE}{p}">' for _, p, t, _ in LANGS
    ) + f'\n<link rel="alternate" hreflang="x-default" href="{BASE}">'
    here = s["root"]
    s["switcher"] = "".join(
        f'<a href="{here}{p}" hreflang="{t}" lang="{t}"' + (' aria-current="page"' if c == code else "") + f">{label}</a>"
        for c, p, t, label in LANGS
    )
    out = re.sub(r"\{\{(\w+)\}\}", lambda m: s[m.group(1)] if m.group(1) in s else m.group(0), template)
    left = re.findall(r"\{\{\w+\}\}", out)
    if left:
        sys.exit(f"{code}: unfilled placeholders {sorted(set(left))}")
    return out

def main():
    template = (ROOT / "web/landing.html").read_text()
    strings = json.loads((ROOT / "web/i18n.json").read_text())
    check = "--check" in sys.argv
    stale = []
    for code, path, tag, _ in LANGS:
        out = render(template, strings, code, path, tag)
        dest = ROOT / "public" / path / "index.html"
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
