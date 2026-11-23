"""CI helper: print what the latest scan covered and fail if any module crashed."""
import glob
import json
import sys

reports = sorted(glob.glob("reports/2*/findings.json"))
if not reports:
    sys.exit("no scan report was written")
doc = json.load(open(reports[-1], encoding="utf-8"))
print("os:", doc["meta"].get("os"), "| admin:", doc["meta"].get("admin"), "| mode:", doc["meta"].get("mode"))
bad = []
for m in doc["modules"]:
    print(f"\n[{m['name']}] {m['status']}: {m['findings']} findings in {m['duration_s']}s")
    for k, v in m["coverage"].items():
        print(f"    {k}: {str(v)[:160]}")
    for n in m["notes"]:
        print(f"    note: {n[:400]}")
    if m["status"] == "error":
        bad.append(m["name"])
print("\ntop findings:")
for f in doc["findings"][:40]:
    print(f"  [{f['severity']:8}] {f['module']}: {f['title'][:90]} -> {f['evidence'][:90]}")
    if f["severity"] != "info":
        print(f"             why: {f['why'][:260]}")
if bad:
    sys.exit(f"modules crashed: {', '.join(bad)}")
print("\nall modules finished without crashing")
