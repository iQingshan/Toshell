import subprocess, json, sys


def token():
    c = subprocess.run(["git", "credential", "fill"], input=b"protocol=https\nhost=github.com\n\n", capture_output=True)
    for l in c.stdout.decode("utf-8", "replace").splitlines():
        if l.startswith("password="):
            return l.split("=", 1)[1].strip()
    raise SystemExit("no token")


T = token()


def call(method, path):
    cfg = ('url = "https://api.github.com%s"\nrequest = "%s"\n'
           'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n'
           'header = "User-Agent: toshell-local"\nwrite-out = "\\n%%{http_code}"\n' % (path, method, T))
    p = subprocess.run(["curl.exe", "-sS", "--max-time", "120", "--config", "-"], capture_output=True, input=cfg.encode())
    body = (p.stdout or b"").decode("utf-8", "replace")
    lines = body.rstrip().splitlines()
    return (lines[-1] if lines else "?"), "\n".join(lines[:-1])


# 1) 取消可能已启动的 tag 运行（tag 会被重建）
code, body = call("GET", "/repos/iQingshan/Toshell/actions/runs?per_page=8")
if code == "200":
    for r in json.loads(body)["workflow_runs"]:
        if r["name"] == "Release" and r["head_sha"].startswith("8161c8c") and not r.get("conclusion"):
            c2, _ = call("POST", "/repos/iQingshan/Toshell/actions/runs/%d/cancel" % r["id"])
            print("cancel run", r["id"], "->", c2)

# 2) 删掉刚建的 release + tag（要在新 tag 前清掉）
code, body = call("GET", "/repos/iQingshan/Toshell/releases/tags/v1.4.3")
print("release exists ->", code)
if code == "200":
    rid = json.loads(body)["id"]
    print("delete release", rid, "->", call("DELETE", "/repos/iQingshan/Toshell/releases/%d" % rid)[0])
print("delete tag ->", call("DELETE", "/repos/iQingshan/Toshell/git/refs/tags/v1.4.3")[0])
print("recheck tag ->", call("GET", "/repos/iQingshan/Toshell/git/ref/tags/v1.4.3")[0])
