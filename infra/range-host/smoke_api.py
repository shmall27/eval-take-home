#!/usr/bin/env python3
"""End-to-end smoke test of the Proxmox API path the harness will use.

Creates a throwaway VM on the isolated bridge, starts it under nested KVM,
snapshots, rolls back, and destroys it, timing each step. Uses only the
automation token, so it also proves the token's permissions.

Run on the range host:  python3 smoke_api.py ~/cathedral/pve-api-token.json
"""
import json
import ssl
import sys
import time
import urllib.parse
import urllib.request

BASE = "https://10.77.0.10:8006/api2/json"
NODE = "cathedral-pve"
VMID = 9999

tok = json.load(open(sys.argv[1]))
AUTH = f"PVEAPIToken={tok['full-tokenid']}={tok['value']}"
CTX = ssl._create_unverified_context()  # self-signed cert on a private bridge


def call(method, path, **params):
    # Proxmox rejects a body on GET/DELETE; those take query parameters.
    data = None
    if params and method in ("GET", "DELETE"):
        path += "?" + urllib.parse.urlencode(params)
    elif params:
        data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Authorization": AUTH})
    with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
        return json.load(r)["data"]


def wait(upid, what):
    t0 = time.time()
    while True:
        st = call("GET", f"/nodes/{NODE}/tasks/{urllib.parse.quote(upid, safe='')}/status")
        if st["status"] == "stopped":
            dt = time.time() - t0
            ok = st.get("exitstatus") == "OK"
            print(f"  {what:<22} {'ok' if ok else 'FAILED: ' + str(st.get('exitstatus'))}  ({dt:.1f}s)")
            if not ok:
                raise RuntimeError(f"{what}: {st.get('exitstatus')}")
            return dt
        time.sleep(0.3)


def stop_with_retry(vm, attempts=8):
    """After a live rollback, Proxmox's cleanup handler for the replaced QEMU
    process holds the VM's file lock for several seconds, so the next
    state-changing call can fail with a lock timeout. Retry until it clears
    and report how long the VM was unavailable for the next operation."""
    t0 = time.time()
    for i in range(attempts):
        try:
            wait(call("POST", vm + "/status/stop"), "stop")
            return time.time() - t0
        except RuntimeError as e:
            if "lock" not in str(e) or i == attempts - 1:
                raise
    raise RuntimeError("unreachable")


vm = f"/nodes/{NODE}/qemu/{VMID}"
print("version:", call("GET", "/version")["version"])
print("node:   ", [n["node"] + "=" + n["status"] for n in call("GET", "/nodes")])
exists = any(v["vmid"] == VMID for v in call("GET", f"/nodes/{NODE}/qemu"))
failed = False
try:
    if exists:  # leftover from an interrupted run
        raise RuntimeError(f"VM {VMID} already exists; cleaning up")
    wait(call("POST", f"/nodes/{NODE}/qemu", vmid=VMID, name="api-smoke", memory=512, cores=1,
              net0="virtio,bridge=vmbr1", scsi0="local:1,format=qcow2", kvm=1), "create")
    wait(call("POST", vm + "/status/start"), "start (nested KVM)")
    cur = call("GET", vm + "/status/current")
    print(f"  status: {cur['status']}, qmpstatus: {cur.get('qmpstatus')}")
    wait(call("POST", vm + "/snapshot", snapname="base", vmstate=1), "snapshot (with RAM)")
    wait(call("POST", vm + "/snapshot/base/rollback"), "rollback")
    print(f"  status after rollback: {call('GET', vm + '/status/current')['status']}")
    print(f"  next operation accepted {stop_with_retry(vm):.1f}s after rollback finished")
except Exception as e:  # noqa: BLE001
    failed = True
    print("FAILED:", e)
finally:
    try:
        if call("GET", vm + "/status/current")["status"] != "stopped":
            stop_with_retry(vm)
        wait(call("DELETE", vm, purge=1), "destroy")
    except Exception as e:  # noqa: BLE001
        failed = True
        print("cleanup issue:", e)
left = [v["vmid"] for v in call("GET", f"/nodes/{NODE}/qemu")]
print("VMs remaining:", left)
sys.exit(1 if failed or left else 0)
