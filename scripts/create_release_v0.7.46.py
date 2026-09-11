#!/usr/bin/env python3
"""Создаёт GitHub Release для v0.7.46 и прикрепляет wheel."""
import json
import os
import urllib.request
import urllib.error
from base64 import b64encode

OWNER = "multi81"
REPO = "ddos-monitoring-remnawave-admin-panel"
TAG = "v0.7.46"
TARGET = "main"
WHEEL_PATH = "/tmp/ddos-0728-src/dist/ddos_monitoring-0.7.46-py3-none-any.whl"
TARBALL_PATH = "/tmp/ddos-0728-src/dist/ddos_monitoring-0.7.46.tar.gz"

token = ""
env = os.environ.get("GITHUB_TOKEN", "")
if env:
    token = env
else:
    p = "/root/.hermes/profiles/kod/.env"
    if os.path.exists(p):
        for ln in open(p):
            if ln.startswith("GITHUB_TOKEN="):
                token = ln.split("=", 1)[1].strip().strip('"\'')
                break
assert token, "GITHUB_TOKEN not found"
print(f"[i] TOKEN_LEN={len(token)}")

B = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
S = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json", "Content-Type": "application/json"}
API = f"https://api.github.com/repos/{OWNER}/{REPO}"

# 1) Tag already exists (HEAD has commit 1ce8334 tagged locally by git push? no — push не создаёт теги).
# Проверим что тега нет.
print("[1/5] check tag...")
req = urllib.request.Request(f"{API}/git/refs/tags/{TAG}", headers=B)
try:
    r = urllib.request.urlopen(req).read()
    print(f"[i] tag exists: {r[:80].decode()}")
except urllib.error.HTTPError as e:
    if e.code == 404:
        print("[i] tag does not exist yet, creating via release")
    else:
        raise

# 2) Create release (without uploaded assets first to get upload_url)
notes = """## v0.7.46 — race fix для имён нод + 5 багов из production

### Что нового
- **poller race fix**: для Hermes и других ручных нод имя больше не перезатирается пустым после первого UPDATE
- UUID Hermes (`9167ddba-...`) стабильно отображается как «Hermes» сразу после tick'а
- Install-handler: errors инициализируется ДО precheck (no NameError)
- Install-handler: SQL fallback для UUID которых нет в panel_api (ручные ноды)
- UI: показ `errors` (uuid: сообщение) при `установлено: 0`
- UI: сохранение состояния <details> «Расшифровка по нодам» при refresh

### Исправленные баги
1. NameError `cannot access local variable 'errors'`
2. Hermes уходил в `unknown` в install-handler
3. Race: после ручного UPDATE poller перезатирал имя обратно в пустое
4. UI скрывал сообщения об ошибках установки
5. <details> схлопывался при каждом 15-секундном refresh

### Тесты
- 140 passed + 5 skipped (precheck + race fix)

### Что НЕ проверено
- GPG-signed commits (verified: False на GitHub)
- Demo-key `kod-hermes-demo` оставлен exposed
- Ветка `block/s-fastnetmon` (локальный артефакт) не удалена
"""
body = {"tag_name": TAG, "target_commitish": TARGET, "name": "v0.7.46 — race fix для имён + install UX", "body": notes, "draft": False, "prerelease": False}
print("[2/5] create release...")
req = urllib.request.Request(f"{API}/releases", data=json.dumps(body).encode(), headers=S, method="POST")
data = json.loads(urllib.request.urlopen(req).read())
release_id = data["id"]
upload_url = data["upload_url"].split("{")[0]
print(f"[i] release_id={release_id} upload_url={upload_url}")

# 3) Upload wheel (asset name = wheel filename)
def upload(name: str, path: str, label: str = ""):
    print(f"[3/5] upload asset: {name}...")
    with open(path, "rb") as f:
        content = f.read()
    up_url = f"{upload_url}?name={name}"
    HDR = {"Authorization": f"token {token}", "Content-Type": "application/zip" if name.endswith(".whl") else "application/gzip"}
    req = urllib.request.Request(up_url, data=content, headers=HDR, method="POST")
    r = json.loads(urllib.request.urlopen(req).read())
    print(f"[i]   state={r['state']} size={r['size']} download_url={r['browser_download_url']}")

upload("ddos_monitoring-0.7.46-py3-none-any.whl", WHEEL_PATH, "wheel binary")

# 4) Upload tarball too
print("[4/5] upload tarball...")
upload("ddos_monitoring-0.7.46.tar.gz", TARBALL_PATH, "source tarball")

# 5) Verify
print("[5/5] verify...")
data = json.loads(urllib.request.urlopen(urllib.request.Request(f"{API}/releases/tags/{TAG}", headers=B)).read())
print(f"[i] tag: {data['tag_name']} assets: {len(data.get('assets', []))}")
for a in data.get("assets", []):
    print(f"  - {a['name']:60s} {a['size']}b  {a['browser_download_url']}")
print(f"[i] URL: https://github.com/{OWNER}/{REPO}/releases/tag/{TAG}")