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
jobs = json.loads(get("/repos/iQingshan/Toshell/actions/runs/42061740552/jobs"))["jobs"]
bad = [j for j in jobs if j["conclusion"] == "failure"]
print("failed jobs:", [(j["name"], j["id"]) for j in bad])
jid = bad[0]["id"]
log = subprocess.run(["curl.exe","-sSL","--max-time","180","--config","-"], capture_output=True,
    input=('url = "https://api.github.com/repos/iQingshan/Toshell/actions/jobs/%d/logs"\n'
           'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n'
           'header = "User-Agent: toshell-local"\n' % (jid, T)).encode())
txt = (log.stdout or b"").decode("utf-8","replace")
lines = txt.splitlines()
idx = [i for i,l in enumerate(lines) if "Upload to GitHub Release" in l]
print("=== 上传步骤日志 ===")
start = idx[-1] if idx else 0
print("\n".join(lines[max(0,start-5): start+40]))