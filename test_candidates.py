"""Non-destructive check: does _candidates() skip our own .fix.txt output?"""
import os

import auto_scan

folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

all_files = sorted(os.listdir(folder))
picked = [os.path.basename(p) for p in auto_scan._candidates(folder)]

print("=== semua file di logs/ ===")
for f in all_files:
    tag = "  <- DIPAKAI" if f in picked else "  (dilewati)"
    print(f"  {f}{tag}")

print()
print(f"total files : {len(all_files)}")
print(f"dipilih     : {len(picked)}")
print(f"dilewati    : {len(all_files) - len(picked)}")

bad = [f for f in picked if ".fix" in f]
print()
if bad:
    print(f"!! GAGAL — masih ada output yg ke-ingest: {bad}")
else:
    print("OK — tidak ada file .fix* yang masuk ingest. loop tertutup.")