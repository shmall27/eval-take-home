#!/usr/bin/env python3
"""Prove the Windows template is usable the way the harness will use it.

Linked-clones the template twice onto the isolated bridge, waits for first
boot, runs commands inside the guests via the QEMU guest agent, checks the
two guests can reach each other, probes containment from inside a guest,
exercises snapshot/rollback, and destroys both clones.

Run on the range host:
    python3 verify_clone.py ~/cathedral/pve-api-token.json [--keep]
"""
import os
import sys
import time
import urllib.error

_here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [_here, os.path.join(_here, "..", "range-host")]  # deployed flat, or repo layout
from pve import Pve  # noqa: E402

TEMPLATE = 9000
A, B = 9101, 9102                      # A probes; B is the positive control
ADDR = {A: "10.77.0.50", B: "10.77.0.51"}   # deliberately inside the management subnet
keep = "--keep" in sys.argv
p = Pve(sys.argv[1])
failed = False


def ps(vmid, script, timeout=300):
    code, out, err = p.guest_powershell(vmid, script, timeout)
    return code, out.strip(), err.strip()


def show(title, text):
    print(f"  --- {title} ---")
    for line in text.splitlines():
        print("   ", line)


def wait_setup(vmid):
    """The agent first answers while Windows is still specializing, and the
    guest reboots during that phase, so commands can fail or time out. Wait
    until setup reports finished on two consecutive checks."""
    t0, stable = time.time(), 0
    while stable < 2:
        if time.time() - t0 > 1200:
            raise RuntimeError("Windows setup did not finish")
        try:
            code, out, _ = ps(vmid, "$s = Get-ItemProperty 'HKLM:\\SYSTEM\\Setup'; \"$($s.SystemSetupInProgress)$($s.OOBEInProgress)$($s.SetupPhase)\"", timeout=60)
            stable = stable + 1 if (code == 0 and out == "000") else 0
        except (urllib.error.URLError, RuntimeError, TimeoutError):
            stable = 0
        time.sleep(5)


PROBE = (
    "foreach ($t in @(%s)) { $h, $port = $t.Split(':');"
    "  $c = New-Object Net.Sockets.TcpClient; $r = $c.BeginConnect($h,[int]$port,$null,$null);"
    "  $ok = $r.AsyncWaitHandle.WaitOne(3000) -and $c.Connected; $c.Close();"
    "  \"$t reachable=$ok\" };"
    "foreach ($ip in @(%s)) { ping -n 1 -w 1500 $ip | Out-Null;"
    "  $n = Get-NetNeighbor -AddressFamily IPv4 -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1;"
    "  \"arp $ip -> $(if ($n -and $n.LinkLayerAddress -notmatch '^(00-){5}00$' -and $n.State -ne 'Unreachable') { $n.LinkLayerAddress } else { 'no answer' })\" }"
)

try:
    existing = {v["vmid"] for v in p.call("GET", f"/nodes/{p.node}/qemu")}
    if existing & {A, B}:
        raise RuntimeError(f"leftover verify VMs {sorted(existing & {A, B})}; cleaning up")
    t0 = time.time()
    for vmid in (A, B):
        p.wait(p.call("POST", p.vm(TEMPLATE) + "/clone", newid=vmid, name=f"win-verify-{vmid}"), f"linked clone {vmid}")
        p.call("POST", p.vm(vmid) + "/config", net0="virtio,bridge=vmbr1")
        p.wait(p.call("POST", p.vm(vmid) + "/status/start"), f"start {vmid}")
    for vmid in (A, B):
        p.wait_agent(vmid)
    print(f"  {'guest agents answering':<34} ok  ({time.time() - t0:.0f}s after first clone call)")
    for vmid in (A, B):
        wait_setup(vmid)
    print(f"  {'Windows first-boot setup finished':<34} ok  ({time.time() - t0:.0f}s after first clone call, both guests)")

    for vmid in (A, B):
        code, out, err = ps(
            vmid,
            "$os = Get-CimInstance Win32_OperatingSystem;"
            "\"hostname   : $env:COMPUTERNAME\";"
            "\"os         : $($os.Caption) build $($os.BuildNumber)\";"
            "\"whoami     : $(whoami)\";"
            "\"machine sid: $((Get-LocalUser -Name Administrator).SID.AccountDomainSid)\";"
            "\"nic        : $((Get-NetAdapter | Select-Object -First 1).InterfaceDescription)\";"
            "\"answerfile : $(Test-Path C:\\Windows\\System32\\Sysprep\\clone-unattend.xml) (should be False)\""
        )
        show(f"inside guest {vmid}", out)
        if code != 0:
            raise RuntimeError(f"guest command failed: {err}")

    # Address both guests. The management subnet is used on purpose: it is
    # the most favourable case for a guest trying to reach the hypervisor.
    for vmid in (A, B):
        code, out, err = ps(
            vmid,
            "$a = Get-NetAdapter | Select-Object -First 1;"
            f"New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress {ADDR[vmid]} -PrefixLength 24 -DefaultGateway 10.77.0.10 | Out-Null;"
            "for ($i = 0; $i -lt 20; $i++) { if ((Get-NetIPAddress -IPAddress " + ADDR[vmid] + " -ErrorAction SilentlyContinue).AddressState -eq 'Preferred') { break }; Start-Sleep 1 };"
            f"(Get-NetIPAddress -IPAddress {ADDR[vmid]}).AddressState",
            timeout=120,
        )
        if out != "Preferred":
            raise RuntimeError(f"could not address guest {vmid}: {out} {err}")

    # Positive control: A must reach B (WinRM is open to the local subnet by
    # default on Windows Server). Proves range guests can talk to each other
    # and that the probe can see an open port at all.
    code, out, _ = ps(A, PROBE % (f"'{ADDR[B]}:5985'", f"'{ADDR[B]}'"), timeout=120)
    show("guest to guest (must be reachable)", out)
    if "reachable=True" not in out or "no answer" in out:
        failed = True
        print("  FAILURE: guests on the range bridge cannot reach each other")

    code, out, _ = ps(A, PROBE % ("'10.77.0.10:8006','10.77.0.10:22','10.77.0.1:3128','1.1.1.1:443'", "'10.77.0.10','10.77.0.1'"), timeout=180)
    show("guest to hypervisor, range host, internet (must not be reachable)", out)
    if "reachable=True" in out or out.count("no answer") != 2:
        failed = True
        print("  CONTAINMENT FAILURE: a range guest reached or resolved a management address")

    vm = p.vm(A)
    ps(A, "Set-Content C:\\marker.txt 'before snapshot'")
    p.wait(p.call("POST", vm + "/snapshot", snapname="clean", vmstate=1), "snapshot with RAM")
    ps(A, "Set-Content C:\\marker.txt 'DIRTY'")
    p.wait(p.call("POST", vm + "/snapshot/clean/rollback"), "rollback")
    print(f"  {'agent answers after rollback':<34} ok  ({p.wait_agent(A, 300):.1f}s)")
    code, out, _ = ps(A, "Get-Content C:\\marker.txt")
    print(f"  marker after rollback: {out!r} (expected 'before snapshot')")
    if out != "before snapshot":
        failed = True
except Exception as e:  # noqa: BLE001
    failed = True
    print("FAILED:", e)
finally:
    if keep:
        print(f"  --keep given: leaving VMs {A} and {B} in place")
    else:
        for vmid in (A, B):
            try:
                vm = p.vm(vmid)
                if p.call("GET", vm + "/status/current")["status"] != "stopped":
                    p.retry_locked(lambda: p.wait(p.call("POST", vm + "/status/stop"), "stop", quiet=True))
                p.wait(p.call("DELETE", vm, purge=1), f"destroy {vmid}")
            except urllib.error.HTTPError:
                pass  # never created
            except Exception as e:  # noqa: BLE001
                failed = True
                print("cleanup issue:", e)
print("RESULT:", "FAIL" if failed else "PASS")
sys.exit(1 if failed else 0)
