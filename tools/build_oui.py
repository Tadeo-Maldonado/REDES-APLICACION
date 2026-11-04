"""Construye netorch/oui_data/ieee_oui.tsv.gz a partir de archivos oficiales del IEEE.

Uso:  python tools/build_oui.py oui.txt [iab.txt]        (formato texto del IEEE)
      python tools/build_oui.py oui.csv mam.csv oui36.csv iab.csv   (CSV oficiales)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from netorch.oui import BUNDLED_DB, _write_db, parse_ieee_csv, parse_ieee_text  # noqa: E402

entries = {}
for arg in sys.argv[1:]:
    text = Path(arg).read_text(encoding="utf-8", errors="replace")
    if arg.lower().endswith(".csv"):
        part = parse_ieee_csv(text)
    else:
        part = parse_ieee_text(text, iab="iab" in Path(arg).name.lower())
    print(f"{arg}: {len(part)}")
    entries.update(part)
_write_db(BUNDLED_DB, entries, "IEEE registry (" + ", ".join(Path(a).name for a in sys.argv[1:]) + ")")
print(f"{len(entries)} prefijos -> {BUNDLED_DB}")
