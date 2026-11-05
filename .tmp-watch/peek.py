import subprocess, json
def tok():
    c = subprocess.run(["git","credential","fill"], input=b"protocol=https\nhost=github.com\n\n", capture_output=True)
    for l in c.stdout.decode("utf-8","replace").splitlines():
        if l.startswith("password="): return l.split("=",1)[1].strip()
T = tok()
def get(p):
    cfg = ('url = "https://api.github.com%s"\nheader = "Authorization: Bearer %s"\n'
           'header = "Accept: application/vnd.github+json"\nheader = "User-Agent: toshell-local"\n' % (p, T))
    r = subprocess.run(["curl.exe","-sS","--max-time","120","--config","-"], capture_output=True, input=cfg.encode())
    return (r.stdout or b"").decode("utf-8","replace")
runs = json.loads(get("/repos/iQingshan/Toshell/actions/runs?per_page=6"))["workflow_runs"]
for r in runs:
    print("%-8s %-9s %-9s head=%s %s" % (r["name"], r["status"], r["conclusion"], r["head_sha"][:8], r["created_at"]))
run = next((x for x in runs if x["head_sha"].startswith("640e6a0")), None)
if run:
    print("\nRUN", run["id"], run["status"], run["html_url"])
    jobs = json.loads(get("/repos/iQingshan/Toshell/actions/runs/%d/jobs" % run["id"]))
    for j in jobs["jobs"]:
        print(" job %-24s %-9s %s" % (j["name"][:24], j["status"], j["conclusion"]))
        for s in j["steps"]:
            if s["status"] != "completed" or s["conclusion"] == "failure":
                print("    step %-40s %s/%s" % (s["name"][:40], s["status"], s["conclusion"]))