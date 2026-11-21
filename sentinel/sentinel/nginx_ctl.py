import ipaddress
import logging
import os
import signal

log = logging.getLogger("sentinel.nginx")


def master_pid():
    """Find nginx's master process through the PID namespace shared with the waf container."""
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as fh:
                    if b"nginx: master process" in fh.read():
                        return int(entry)
            except OSError:
                continue
    return None


def apply_blocklist(path, ips):
    valid = []
    for ip in sorted(ips):
        try:
            valid.append(str(ipaddress.ip_address(ip)))
        except ValueError:
            log.warning("skipping invalid ip %r", ip)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write("# managed by ShieldWall Sentinel, do not edit\n")
        fh.writelines(f"{ip} 1;\n" for ip in valid)
    os.replace(tmp, path)                    # atomic swap so nginx never reads a half-written file
    pid = master_pid()
    if pid:
        os.kill(pid, signal.SIGHUP)          # graceful reload, no dropped connections
        log.info("blocklist updated (%d ips), nginx reloaded", len(valid))
    else:
        log.warning("nginx master not found; blocklist written but not reloaded")
