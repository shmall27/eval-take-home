#!/usr/bin/env python3
"""End-to-end smoke test of the Proxmox API path the harness will use.

Creates a throwaway VM on the isolated bridge, starts it under nested KVM,
snapshots, rolls back, and destroys it, timing each step. Uses only the
automation token, so it also proves the token's permissions.

Run on the range host:  python3 smoke_api.py ~/cathedral/pve-api-token.json
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pve import Pve  # noqa: E402

VMID = 9999
p = Pve(sys.argv[1])
vm = p.vm(VMID)
failed = False

print("version:", p.call("GET", "/version")["version"])
print("node:   ", [n["node"] + "=" + n["status"] for n in p.call("GET", "/nodes")])
try:
    if any(v["vmid"] == VMID for v in p.call("GET", f"/nodes/{p.node}/qemu")):
        raise RuntimeError(f"VM {VMID} already exists; cleaning up")  # leftover from an interrupted run
    p.wait(p.call("POST", f"/nodes/{p.node}/qemu", vmid=VMID, name="api-smoke", memory=512, cores=1,
                  net0="virtio,bridge=vmbr1", scsi0="local:1,format=qcow2", kvm=1), "create")
    p.wait(p.call("POST", vm + "/status/start"), "start (nested KVM)")
    cur = p.call("GET", vm + "/status/current")
    print(f"  status: {cur['status']}, qmpstatus: {cur.get('qmpstatus')}")
    p.wait(p.call("POST", vm + "/snapshot", snapname="base", vmstate=1), "snapshot (with RAM)")
    p.wait(p.call("POST", vm + "/snapshot/base/rollback"), "rollback")
    print(f"  status after rollback: {p.call('GET', vm + '/status/current')['status']}")
    t0 = time.time()
    p.retry_locked(lambda: p.wait(p.call("POST", vm + "/status/stop"), "stop", quiet=True))
    print(f"  next state change accepted {time.time() - t0:.1f}s after rollback finished")
except Exception as e:  # noqa: BLE001
    failed = True
    print("FAILED:", e)
finally:
    try:
        if p.call("GET", vm + "/status/current")["status"] != "stopped":
            p.retry_locked(lambda: p.wait(p.call("POST", vm + "/status/stop"), "stop", quiet=True))
        p.wait(p.call("DELETE", vm, purge=1), "destroy")
    except Exception as e:  # noqa: BLE001
        failed = True
        print("cleanup issue:", e)
left = [v["vmid"] for v in p.call("GET", f"/nodes/{p.node}/qemu") if v["vmid"] == VMID]
print("smoke VM remaining:", left)
sys.exit(1 if failed or left else 0)
