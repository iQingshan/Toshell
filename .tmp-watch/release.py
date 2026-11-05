import subprocess, json, time, sys


def token():
    c = subprocess.run(["git", "credential", "fill"], input=b"protocol=https\nhost=github.com\n\n", capture_output=True)
    for l in c.stdout.decode("utf-8", "replace").splitlines():
        if l.startswith("password="):
            return l.split("=", 1)[1].strip()
    raise SystemExit("no token")


T = token()


def get(path):
    cfg = ('url = "https://api.github.com%s"\n'
           'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n'
           'header = "User-Agent: toshell-local"\n' % (path, T))
    p = subprocess.run(["curl.exe", "-sS", "--max-time", "120", "--config", "-"], capture_output=True, input=cfg.encode())
    return (p.stdout or b"").decode("utf-8", "replace")


deadline = time.time() + 2700
run = None
while time.time() < deadline:
    runs = json.loads(get("/repos/iQingshan/Toshell/actions/runs?per_page=8"))["workflow_runs"]
    run = next((r for r in runs if r["name"] == "Release" and r["head_sha"].startswith("640e6a0")), None)
    if run and run.get("conclusion"):
        break
    print("waiting... status=%s" % (run["status"] if run else "-"), flush=True)
    time.sleep(20)

if not run:
    print("NO RUN")
    sys.exit(1)
print("RUN", run["id"], run["status"], run["conclusion"], run["html_url"], flush=True)
jobs = json.loads(get("/repos/iQingshan/Toshell/actions/runs/%d/jobs" % run["id"]))
for j in jobs["jobs"]:
    print(" job=%-26s %s" % (j["name"][:26], j["conclusion"]), flush=True)
    for s in j["steps"]:
        if s["conclusion"] == "failure":
            print("    FAIL:", s["name"], flush=True)
