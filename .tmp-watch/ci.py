import subprocess, json, re
def tok():
    c = subprocess.run(["git","credential","fill"], input=b"protocol=https\nhost=github.com\n\n", capture_output=True)
    for l in c.stdout.decode("utf-8","replace").splitlines():
        if l.startswith("password="): return l.split("=",1)[1].strip()
T = tok()
def get(p):
    cfg = ('url = "https://api.github.com%s"\nheader = "Authorization: Bearer %s"\n'
           'header = "Accept: application/vnd.github+json"\nheader = "User-Agent: toshell-local"\n' % (p, T))
    r = subprocess.run(["curl.exe","-sS","--max-time","150","--config","-"], capture_output=True, input=cfg.encode())
    return (r.stdout or b"").decode("utf-8","replace")

runs = json.loads(get("/repos/iQingshan/Toshell/actions/runs?per_page=6&event=push"))["workflow_runs"]
ci = next((x for x in runs if x["name"] == "CI" and x["head_sha"].startswith("640e6a0")), None)
if ci:
    jobs = json.loads(get("/repos/iQingshan/Toshell/actions/runs/%d/jobs" % ci["id"]))
    for j in jobs["jobs"]:
        if j["conclusion"] != "success":
            print("CI job", j["name"], j["conclusion"], "id", j["id"])
ci_log = subprocess.run(["curl.exe","-sSL","--max-time","180","--config","-"], capture_output=True,
    input=('url = "https://api.github.com/repos/iQingshan/Toshell/actions/jobs/%d/logs"\n'
           'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n'
           'header = "User-Agent: toshell-local"\n' % (jobs["jobs"][-1]["id"], T)).encode())
txt = (ci_log.stdout or b"").decode("utf-8","replace")
print("=== CI 失败日志片段（job: server）===")
lines = txt.splitlines()
idx = [i for i,l in enumerate(lines) if re.search(r"--- FAIL|^FAIL\s|panic:|##\[error\]", l)]
if idx:
    print("\n".join(lines[max(0, idx[0]-6): idx[0]+25]))
else:
    print("\n".join(lines[-40:]))