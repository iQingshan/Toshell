import subprocess, json, re
def tok():
    c = subprocess.run(["git","credential","fill"], input=b"protocol=https\nhost=github.com\n\n", capture_output=True)
    for l in c.stdout.decode("utf-8","replace").splitlines():
        if l.startswith("password="): return l.split("=",1)[1].strip()
T = tok()
jid = 127366404872
log = subprocess.run(["curl.exe","-sSL","--max-time","180","--config","-"], capture_output=True,
    input=('url = "https://api.github.com/repos/iQingshan/Toshell/actions/jobs/%d/logs"\n'
           'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n'
           'header = "User-Agent: toshell-local"\n' % (jid, T)).encode())
txt = (log.stdout or b"").decode("utf-8","replace")
lines = txt.splitlines()
print("total lines:", len(lines))
print("=== 尾部 45 行 ===")
print("\n".join(lines[-45:]))