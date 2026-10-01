#!/usr/bin/env python3
"""Verify the range network fabric end to end, with evidence.

Stands up two throwaway Debian guests (VMID 9250 on `user`, 9251 on `server`)
from the baked test-guest image, drives them through the QEMU guest agent, and
checks:

  * each guest gets a DHCP lease, a default route, and DNS from the router;
  * the router's local DNS resolves range names but NOT internet names;
  * with an allow-list hole (user->server icmp + tcp 8080), user reaches server
    on exactly those, and nothing else -- reverse direction and other ports are
    denied (default-deny between segments);
  * containment invariant 1: no guest reaches the hypervisor (10.77.0.10), the
    range host (10.77.0.1), or the internet (1.1.1.1);
  * containment invariant 3: the node firewall drops guest->node on the new
    bridges (shown from the node).

Applies the allow-list through the real path (configure_router.py), and restores
the default (deny-all) allow-list on exit. Tears the test guests down. Idempotent
and re-runnable.

Run on the range host (vanilla):
    python3 verify.py [--keep]
"""
import os
import subprocess
import sys
import tempfile
import time
import urllib.error

_here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [_here, os.path.join(_here, "..", "range-host"),
                os.path.expanduser("~/cathedral")]
from pve import Pve  # noqa: E402

TOKEN = os.path.expanduser("~/cathedral/pve-api-token.json")
SEG = os.path.join(_here, "segments.json")
RULES = os.path.join(_here, "firewall-allow.rules")
CONFIGURE = os.path.join(_here, "configure_router.py")
TEST_IMG = "/root/netbuild/test-guest.qcow2"

USER_VM, SRV_VM = 9250, 9251          # scratch band 9250-9259
PLACES = {USER_VM: ("user", "vmbr3"), SRV_VM: ("server", "vmbr4")}
keep = "--keep" in sys.argv
p = Pve(TOKEN)
failed = False
results = []


def record(ok, label, detail=""):
    global failed
    failed = failed or not ok
    mark = "PASS" if ok else "FAIL"
    results.append((ok, label, detail))
    print(f"  [{mark}] {label}" + (f"  -- {detail}" if detail else ""))


def sh(vmid, script, timeout=60):
    code, out, err = p.guest_exec(vmid, ["bash", "-lc", script], timeout)
    return code, (out or "").strip(), (err or "").strip()


def tcp_open(vmid, host, port, timeout=4):
    code, out, _ = sh(vmid, f"timeout {timeout} bash -c 'echo > /dev/tcp/{host}/{port}' "
                            f"2>/dev/null && echo OPEN || echo CLOSED")
    return out == "OPEN"


def pingable(vmid, host):
    code, _, _ = sh(vmid, f"ping -c1 -W2 {host} >/dev/null 2>&1 && echo up")
    return code == 0


def configure_with(rules_path):
    subprocess.run([sys.executable, CONFIGURE, SEG, rules_path],
                   check=True, stdout=subprocess.DEVNULL)


def node(*args, check=True):
    """Run a command on the Proxmox node as root. Scratch VM lifecycle uses
    `qm` directly because the non-root API token may not reference arbitrary
    disk paths (import-from); guest-agent exec still goes through the API."""
    env = {**os.environ, "PATH": "/snap/bin:" + os.environ.get("PATH", "")}
    r = subprocess.run(["lxc", "exec", "cathedral-pve", "--", *args],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        raise RuntimeError(f"node {' '.join(args)} -> {r.returncode}: {r.stderr.strip()}")
    return r


def exists(vmid):
    return node("qm", "status", str(vmid), check=False).returncode == 0


def destroy(vmid):
    if not exists(vmid):
        return
    node("qm", "stop", str(vmid), "--skiplock", "1", check=False)
    for _ in range(20):
        node("qm", "destroy", str(vmid), "--purge", "1", "--skiplock", "1", check=False)
        if not exists(vmid):
            return
        time.sleep(1)
    raise RuntimeError(f"could not destroy {vmid}")


def create(vmid, bridge):
    t = time.time()
    node("qm", "create", str(vmid), "--name", f"net-verify-{vmid}",
         "--memory", "512", "--cores", "1", "--cpu", "host", "--ostype", "l26",
         "--scsihw", "virtio-scsi-single", "--agent", "enabled=1",
         "--serial0", "socket", "--vga", "serial0", "--boot", "order=scsi0",
         "--net0", f"virtio,bridge={bridge}",
         "--scsi0", f"local:0,import-from={TEST_IMG}")
    node("qm", "start", str(vmid))
    print(f"  created+started {vmid} on {bridge} ({time.time() - t:.0f}s)")


try:
    leftover = {v["vmid"] for v in p.call("GET", f"/nodes/{p.node}/qemu")} & set(PLACES)
    for vmid in leftover:
        print(f"cleaning leftover {vmid}")
        destroy(vmid)

    # --- allow-list hole for the test: user -> server icmp + tcp 8080 ---------
    tmp = tempfile.NamedTemporaryFile("w", suffix=".rules", delete=False)
    tmp.write("user server icmp any\nuser server tcp 8080\n")
    tmp.close()
    print("applying test allow-list (user->server icmp + tcp 8080) via configure_router.py")
    configure_with(tmp.name)

    # --- stand up the two guests ---------------------------------------------
    t0 = time.time()
    for vmid, (_, bridge) in PLACES.items():
        create(vmid, bridge)
    for vmid in PLACES:
        p.wait_agent(vmid, 600)
    print(f"  both guest agents up ({time.time() - t0:.0f}s after first create)")

    # Wait for DHCP to settle, then read each guest's address.
    addr = {}
    for vmid in PLACES:
        ip = ""
        for _ in range(40):
            _, ip, _ = sh(vmid, "ip -br -4 addr show scope global | awk '{print $3}' | head -1")
            if ip:
                break
            time.sleep(2)
        addr[vmid] = ip.split("/")[0]

    print("\n== DHCP + DNS ==")
    seg_of = {USER_VM: "10.78.20.", SRV_VM: "10.78.30."}
    for vmid in PLACES:
        record(addr[vmid].startswith(seg_of[vmid]), f"{PLACES[vmid][0]} guest got DHCP lease",
               f"{addr[vmid]}")
        _, route, _ = sh(vmid, "ip route | awk '/default/{print $3}'")
        gw = seg_of[vmid] + "1"
        record(route == gw, f"{PLACES[vmid][0]} guest default route via router", route or "none")
        dom = {USER_VM: "user.range.lab", SRV_VM: "srv.range.lab"}[vmid]
        _, dns, _ = sh(vmid, f"getent hosts router.{dom} | awk '{{print $1}}'")
        record(dns == gw, f"{PLACES[vmid][0]} guest resolves router.{dom} via router DNS",
               dns or "no answer")
    # Internet DNS must fail (router has no upstream resolver).
    code, out, _ = sh(USER_VM, "getent hosts example.com >/dev/null 2>&1 && echo RESOLVED || echo NXDOMAIN")
    record(out == "NXDOMAIN", "internet name does NOT resolve (no DNS egress)", out)

    # --- start a listener on the server guest for the positive TCP test ------
    sh(SRV_VM, "nohup python3 -m http.server 8080 >/tmp/h.log 2>&1 & disown; sleep 1")
    sh(SRV_VM, "nohup python3 -m http.server 8081 >/tmp/h2.log 2>&1 & disown; sleep 1")

    print("\n== inter-segment policy (allow-list: user->server icmp + tcp 8080) ==")
    record(pingable(USER_VM, addr[SRV_VM]), "user CAN ping server (allowed icmp)", addr[SRV_VM])
    record(tcp_open(USER_VM, addr[SRV_VM], 8080), "user CAN reach server:8080 (allowed)", "")
    record(not tcp_open(USER_VM, addr[SRV_VM], 8081), "user CANNOT reach server:8081 (not in allow-list)", "")
    record(not pingable(SRV_VM, addr[USER_VM]), "server CANNOT ping user (reverse, default-deny)", addr[USER_VM])
    record(not tcp_open(SRV_VM, addr[USER_VM], 8080), "server CANNOT reach user:8080 (reverse, default-deny)", "")

    print("\n== containment invariant 1 (no path to hypervisor/host/internet) ==")
    for host, port, what in [("10.77.0.10", 8006, "hypervisor API 10.77.0.10:8006"),
                             ("10.77.0.10", 22, "hypervisor SSH 10.77.0.10:22"),
                             ("10.77.0.1", 3128, "range host proxy 10.77.0.1:3128"),
                             ("1.1.1.1", 443, "internet 1.1.1.1:443")]:
        record(not tcp_open(USER_VM, host, port), f"user CANNOT reach {what}", "")
    record(not pingable(USER_VM, "10.77.0.10"), "user CANNOT ping hypervisor 10.77.0.10", "")
    record(not pingable(USER_VM, "1.1.1.1"), "user CANNOT ping internet 1.1.1.1", "")

    print("\n== containment invariant 3 (node firewall covers new bridges) ==")
    txt = node("nft", "list", "table", "inet", "range_containment").stdout
    ok = ('"lo", "vmbr0"' in txt or 'iifname != "vmbr0"' in txt) and "drop" in txt
    record(ok, "node range_containment present (accepts only lo/vmbr0, drops the rest)")
    for ln in txt.splitlines():
        print("      " + ln)

except Exception as e:  # noqa: BLE001
    failed = True
    print("ERROR:", e)
finally:
    print("\n== teardown ==")
    if keep:
        print("  --keep: leaving guests in place")
    else:
        for vmid in PLACES:
            destroy(vmid)
        print("  test guests destroyed")
    print("  restoring default (deny-all) allow-list")
    try:
        configure_with(RULES)
    except Exception as e:  # noqa: BLE001
        print("  WARN: could not restore allow-list:", e)

print("\nRESULT:", "FAIL" if failed else "PASS")
sys.exit(1 if failed else 0)
