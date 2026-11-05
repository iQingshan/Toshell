import sys
try:
    import yaml
except ImportError:
    print("pyyaml not installed"); sys.exit(0)
d = yaml.safe_load(open(r".github/workflows/release.yml", encoding="utf-8"))
print("jobs:", list(d["jobs"].keys()))
for k, v in d["jobs"].items():
    print(" ", k, "needs=", v.get("needs"), "steps=", len(v.get("steps", [])))