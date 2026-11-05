import subprocess, json, io, sys


def token():
    c = subprocess.run(["git", "credential", "fill"], input=b"protocol=https\nhost=github.com\n\n", capture_output=True)
    for l in c.stdout.decode("utf-8", "replace").splitlines():
        if l.startswith("password="):
            return l.split("=", 1)[1].strip()
    raise SystemExit("no token")


T = token()
REPO = "iQingshan/Toshell"
comments = json.load(io.open(r".tmp-watch/comments.json", encoding="utf-8"))

for num, body in comments.items():
    payload = json.dumps({"body": body}, ensure_ascii=False)
    io.open(r".tmp-watch/payload.json", "w", encoding="utf-8").write(payload)
    cfg = ('url = "https://api.github.com/repos/%s/issues/%s/comments"\n'
           'request = "POST"\n'
           'header = "Authorization: Bearer %s"\n'
           'header = "Accept: application/vnd.github+json"\n'
           'header = "Content-Type: application/json; charset=utf-8"\n'
           'header = "User-Agent: toshell-local"\n'
           'data-binary = "@.tmp-watch/payload.json"\n'
           'write-out = "\\n%%{http_code}"\n' % (REPO, num, T))
    p = subprocess.run(["curl.exe", "-sS", "--max-time", "120", "--config", "-"], capture_output=True, input=cfg.encode())
    out = (p.stdout or b"").decode("utf-8", "replace")
    code = out.rstrip().splitlines()[-1] if out.strip() else "?"
    print("comment #%s -> HTTP %s" % (num, code))
    if code != "201":
        print(out[:400])
        continue

    io.open(r".tmp-watch/patch.json", "w", encoding="utf-8").write(
        json.dumps({"state": "closed", "state_reason": "completed"}, ensure_ascii=False))
    cfg2 = ('url = "https://api.github.com/repos/%s/issues/%s"\n'
            'request = "PATCH"\n'
            'header = "Authorization: Bearer %s"\n'
            'header = "Accept: application/vnd.github+json"\n'
            'header = "Content-Type: application/json; charset=utf-8"\n'
            'header = "User-Agent: toshell-local"\n'
            'data-binary = "@.tmp-watch/patch.json"\n'
            'write-out = "\\n%%{http_code}"\n' % (REPO, num, T))
    p2 = subprocess.run(["curl.exe", "-sS", "--max-time", "120", "--config", "-"], capture_output=True, input=cfg2.encode())
    out2 = (p2.stdout or b"").decode("utf-8", "replace")
    code2 = out2.rstrip().splitlines()[-1] if out2.strip() else "?"
    state = ""
    try:
        state = json.loads("\n".join(out2.rstrip().splitlines()[:-1])).get("state", "")
    except Exception:
        pass
    print("close #%s -> HTTP %s state=%s" % (num, code2, state))
