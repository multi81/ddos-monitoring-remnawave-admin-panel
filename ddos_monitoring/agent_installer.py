"""Сборка и установка ddos-agent на ноды.

Агент — один python-файл (шаблон ниже), systemd-юнит, интервал сбора настраивается.
Установка — через exec_script канала агентов панели; скан — по маркеру версии.
"""

AGENT_VERSION = "1.1.0"

_AGENT_TEMPLATE = '''#!/usr/bin/env python3
"""ddos-agent {version} — лёгкий сборщик метрик ноды для DDoS-мониторинга панели.

Без внешних зависимостей. Ставится как ddos-agent.service.
"""
import hashlib
import hmac
import json
import time
import urllib.request

PANEL_URL = "{panel_url}"
NODE_UUID = "{node_uuid}"
AGENT_SECRET_FILE = "/etc/ddos-monitoring/agent-secret"
INTERVAL_S = {interval}
VERSION = "{version}"

IP_LIMIT = {ip_limit}          # max соединений с одного IP (0 = выключено)
TOP_IPS_N = {top_ips_n}        # сколько топ-источников слать


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def collect():
    m = {}
    # CPU/load/mem из /proc
    loadavg = _read("/proc/loadavg").split()
    if loadavg:
        m["load1"] = float(loadavg[0])
    try:
        with open("/proc/meminfo") as f:
            info = dict(
                (line.split(":", 1)[0], int(line.split()[1]) * 1024)
                for line in f if ":" in line
            )
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", 0)
        if total:
            m["ram_pct"] = round(100.0 * (total - avail) / total, 1)
        stotal = info.get("SwapTotal", 0)
        sfree = info.get("SwapFree", 0)
        if stotal:
            m["swap_pct"] = round(100.0 * (stotal - sfree) / stotal, 1)
    except OSError:
        pass
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("cpu "):
                    parts = [int(x) for x in line.split()[1:]]
                    idle = parts[3] + parts[4]
                    m["_cpu_total"] = sum(parts)
                    m["_cpu_idle"] = idle
                    break
    except OSError:
        pass
    nproc = _read("/proc/cpuinfo").count("processor\\t")
    m["cores"] = max(nproc, 1)

    # диск
    try:
        st = os_statvfs("/")
        m["disk_pct"] = round(100.0 * (st.f_blocks - st.f_bfree) / max(st.f_blocks, 1), 1)
    except OSError:
        pass

    # соединения: SYN_RECV / ESTABLISHED / per-IP
    syn = est = 0
    per_ip = {}
    uniq = set()
    for line in (_read("/proc/net/tcp").splitlines() + _read("/proc/net/tcp6").splitlines())[1:]:
        cols = line.split()
        if len(cols) < 4:
            continue
        state = cols[3]
        remote_ip = cols[2].rsplit(":", 1)[0]
        uniq.add(remote_ip)
        if state == "02":  # SYN_RECV
            syn += 1
            per_ip[remote_ip] = per_ip.get(remote_ip, 0) + 1
        elif state == "01":  # ESTABLISHED
            est += 1
            per_ip[remote_ip] = per_ip.get(remote_ip, 0) + 1
    m["syn_recv"] = syn
    m["established"] = est
    m["unique_ips"] = len(uniq)
    top = sorted(per_ip.items(), key=lambda kv: -kv[1])[:TOP_IPS_N]
    m["top_ips"] = [{"ip": _fmt_ip(k), "count": v} for k, v in top]
    if IP_LIMIT > 0:
        m["ip_limit_breaches"] = [
            {"ip": _fmt_ip(k), "count": v} for k, v in per_ip.items() if v > IP_LIMIT
        ]

    # conntrack
    ct = _read("/proc/sys/net/netfilter/nf_conntrack_count").strip()
    cm = _read("/proc/sys/net/netfilter/nf_conntrack_max").strip()
    if ct:
        m["conntrack_count"] = int(ct)
    if cm:
        m["conntrack_max"] = int(cm)

    # упавшие службы
    failed = []
    try:
        import subprocess
        out = subprocess.run(
            ["systemctl", "list-units", "--failed", "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=10,
        ).stdout
        for ln in out.splitlines():
            parts = ln.split()
            if parts and not parts[0].endswith(".target"):
                failed.append(parts[0])
    except Exception:
        pass
    m["failed_units"] = failed

    # сетевые счётчики (RX/TX/drop/pps) — дельты между вызовами
    _net_deltas(m)
    return m


def os_statvfs(path):
    import os

    return os.statvfs(path)


def _fmt_ip(hexip):
    if ":" not in hexip and len(hexip) == 32:
        # IPv4-mapped IPv6 (::ffff:a.b.c.d) — раскодируем в точечный вид
        hexip = hexip[-8:]
    try:
        b = bytes.fromhex(hexip)
    except ValueError:
        return hexip
    if len(b) == 4:
        return ".".join(str(x) for x in reversed(b))
    if len(b) == 16:
        import socket as _s
        try:
            return _s.inet_ntop(_s.AF_INET6, b)
        except (OSError, ValueError):
            return hexip
    return hexip


_net_prev = {}


def _net_deltas(m):
    import time as _t

    rx = tx = rxd = txd = 0
    for ln in _read("/proc/net/dev").splitlines():
        if ":" not in ln:
            continue
        iface, data = ln.split(":", 1)
        if iface.strip() == "lo":
            continue
        c = data.split()
        rx += int(c[0]); rxd += int(c[2]); tx += int(c[8]); txd += int(c[10])
    now = _t.monotonic()
    prev = _net_prev.get("v")
    _net_prev["v"] = (now, rx, tx, rxd, txd)
    if prev:
        dt = now - prev[0]
        if dt > 0:
            m["rx_bps"] = int((rx - prev[1]) * 8 / dt)
            m["tx_bps"] = int((tx - prev[2]) * 8 / dt)
            m["rx_pps"] = 0  # пакеты считаем ниже через /proc/net/dev поля 1,9
            m["tx_pps"] = 0
            m["rx_drop"] = max(rxd - prev[3], 0)
            m["tx_drop"] = max(txd - prev[4], 0)
    # pps: отдельный проход по пакетам
    rp = tp = 0
    for ln in _read("/proc/net/dev").splitlines():
        if ":" not in ln:
            continue
        iface, data = ln.split(":", 1)
        if iface.strip() == "lo":
            continue
        c = data.split()
        rp += int(c[1]); tp += int(c[9])
    prevp = _net_prev.get("p")
    _net_prev["p"] = (now, rp, tp)
    if prevp and now - prevp[0] > 0:
        m["rx_pps"] = int((rp - prevp[1]) / (now - prevp[0]))
        m["tx_pps"] = int((tp - prevp[2]) / (now - prevp[0]))


def _agent_secret():
    value = _read(AGENT_SECRET_FILE).strip()
    if len(value) < 32:
        raise RuntimeError("agent secret is not configured")
    return value


def report(metrics):
    ts = int(time.time())
    body = json.dumps(metrics, sort_keys=True)
    sig = hmac.new(_agent_secret().encode(), f"{NODE_UUID}|{ts}|{body}".encode(),
                   hashlib.sha256).hexdigest()
    payload = json.dumps({"node_uuid": NODE_UUID, "ts": ts,
                           "metrics": metrics, "sig": sig,
                           "agent_version": VERSION}).encode()
    req = urllib.request.Request(
        PANEL_URL.rstrip("/") + "/api/v2/plugins/ddos-monitoring/agent/report",
        data=payload, headers={"Content-Type": "application/json",
                               "User-Agent": "ddos-agent/%s" % VERSION})
    urllib.request.urlopen(req, timeout=10)


def main():
    while True:
        try:
            m = collect()
            # CPU% считается по дельте /proc/stat между циклами.
            # Сохраняем текущий baseline ДО чтения prev (фикс: раньше prev_idle
            # использовался как undefined name → NameError → silent pass).
            cur_cpu_total = m.get("_cpu_total")
            cur_cpu_idle = m.get("_cpu_idle", 0)
            prev = _net_prev.get("cpu")
            if prev is not None and cur_cpu_total:
                dt = cur_cpu_total - prev[0]
                didle = cur_cpu_idle - prev[1]
                if dt > 0:
                    m["cpu_pct"] = round(100.0 * (dt - didle) / dt, 1)
            # Обновляем baseline для следующего цикла.
            if cur_cpu_total:
                _net_prev["cpu"] = (cur_cpu_total, cur_cpu_idle)
            report({k: v for k, v in m.items() if not k.startswith("_")})
        except Exception:
            pass
        time.sleep(INTERVAL_S)


if __name__ == "__main__":
    main()
'''

# В шаблоне выше фигурные скобки кода агента сохранены как есть;
# подстановка параметров — строковым replace в build_agent_file.


def build_agent_file(panel_url: str, node_uuid: str,
                     interval: int = 15, ip_limit: int = 50,
                     top_ips_n: int = 10) -> str:
    code = _AGENT_TEMPLATE
    code = code.replace("{version}", AGENT_VERSION)
    code = code.replace("{panel_url}", panel_url)
    code = code.replace("{node_uuid}", node_uuid)

    code = code.replace("{interval}", str(interval))
    code = code.replace("{ip_limit}", str(ip_limit))
    code = code.replace("{top_ips_n}", str(top_ips_n))
    return code


def build_unit_file() -> str:
    return """[Unit]
Description=DDoS monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/ddos-agent
Restart=always
RestartSec=5
Nice=5

[Install]
WantedBy=multi-user.target
"""


def build_install_script(panel_url: str, node_uuid: str,
                         interval: int = 15, ip_limit: int = 50,
                         top_ips_n: int = 10) -> str:
    """Bash-скрипт для exec_script: идемпотентен, переустанавливает при смене параметров."""
    agent = build_agent_file(panel_url, node_uuid, interval, ip_limit, top_ips_n)
    unit = build_unit_file()
    marker = f"# ddos-agent {AGENT_VERSION}"
    return f"""set -e
mkdir -p /usr/local/bin /etc/systemd/system /etc/ddos-monitoring
if [ -z "${{DDOS_AGENT_SECRET:-}}" ]; then
  echo "agent secret is not configured" >&2
  exit 1
fi
umask 077
printf '%s' "$DDOS_AGENT_SECRET" > /etc/ddos-monitoring/agent-secret
unset DDOS_AGENT_SECRET

cat > /usr/local/bin/ddos-agent <<'DDOS_AGENT_EOF'
{marker}
{agent}
DDOS_AGENT_EOF
chmod +x /usr/local/bin/ddos-agent

cat > /etc/systemd/system/ddos-agent.service <<'UNIT_EOF'
{unit}
UNIT_EOF

systemctl daemon-reload
systemctl enable ddos-agent >/dev/null 2>&1 || true
if systemctl is-active --quiet ddos-agent; then
  systemctl restart ddos-agent
else
  systemctl start ddos-agent
fi
echo "installed {AGENT_VERSION}"
"""
