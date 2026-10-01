"""Minimal Proxmox API client shared by the infra smoke scripts.

Stdlib only. The Rust harness will carry its own client; this exists so the
infrastructure can be verified before any harness code is written.
"""
import base64
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


class Pve:
    def __init__(self, token_file, base="https://10.77.0.10:8006/api2/json", node="cathedral-pve"):
        tok = json.load(open(token_file))
        self.auth = f"PVEAPIToken={tok['full-tokenid']}={tok['value']}"
        self.base, self.node = base, node
        self.ctx = ssl._create_unverified_context()  # self-signed cert on a private bridge

    def call(self, method, path, **params):
        # Proxmox rejects a body on GET/DELETE; those take query parameters.
        data = None
        if params and method in ("GET", "DELETE"):
            path += "?" + urllib.parse.urlencode(params, doseq=True)
        elif params:
            data = urllib.parse.urlencode(params, doseq=True).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={"Authorization": self.auth})
        with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
            return json.load(r)["data"]

    def vm(self, vmid):
        return f"/nodes/{self.node}/qemu/{vmid}"

    def wait(self, upid, what, quiet=False):
        """Block until a task finishes; return seconds taken, raise on failure."""
        t0 = time.time()
        while True:
            st = self.call("GET", f"/nodes/{self.node}/tasks/{urllib.parse.quote(upid, safe='')}/status")
            if st["status"] == "stopped":
                dt = time.time() - t0
                ok = st.get("exitstatus") == "OK"
                locked = "lock" in str(st.get("exitstatus"))
                if not quiet or (not ok and not locked):
                    print(f"  {what:<34} {'ok' if ok else 'FAILED: ' + str(st.get('exitstatus'))}  ({dt:.1f}s)")
                if not ok:
                    raise RuntimeError(f"{what}: {st.get('exitstatus')}")
                return dt
            time.sleep(0.3)

    def retry_locked(self, fn, attempts=10):
        """After a live rollback, Proxmox's cleanup handler for the replaced
        QEMU process holds the VM's file lock for ~30 s and state-changing
        calls fail with a lock timeout. Retry until it clears."""
        for i in range(attempts):
            try:
                return fn()
            except RuntimeError as e:
                if "lock" not in str(e) or i == attempts - 1:
                    raise

    def agent_up(self, vmid):
        try:
            self.call("POST", self.vm(vmid) + "/agent/ping")
            return True
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            return False

    def wait_agent(self, vmid, timeout=1800):
        t0 = time.time()
        while not self.agent_up(vmid):
            if time.time() - t0 > timeout:
                raise RuntimeError("guest agent did not come up")
            time.sleep(3)
        return time.time() - t0

    def _agent_call(self, method, path, tries=30, **params):
        """Agent calls go through a short Proxmox-side timeout, and a busy
        Windows guest (first boot, Defender, .NET optimisation) regularly
        misses it. Retry on that specific error."""
        for i in range(tries):
            try:
                return self.call(method, path, **params)
            except urllib.error.HTTPError as e:
                if e.code != 500 or i == tries - 1:
                    raise
                time.sleep(2)

    def guest_exec(self, vmid, argv, timeout=300):
        """Run a command inside the guest through the QEMU guest agent.
        Needs no network path to the guest. Returns (exitcode, stdout, stderr).

        Starting the command is retried on agent timeout, so a command may in
        rare cases start twice; keep guest commands idempotent."""
        pid = self._agent_call("POST", self.vm(vmid) + "/agent/exec", tries=5, command=argv)["pid"]
        t0 = time.time()
        while True:
            st = self._agent_call("GET", self.vm(vmid) + "/agent/exec-status", pid=pid)
            if st.get("exited"):
                return st.get("exitcode"), st.get("out-data", ""), st.get("err-data", "")
            if time.time() - t0 > timeout:
                raise RuntimeError("guest command timed out")
            time.sleep(0.5)

    def guest_powershell(self, vmid, script, timeout=300):
        enc = base64.b64encode(("$ProgressPreference='SilentlyContinue';" + script).encode("utf-16-le")).decode()
        return self.guest_exec(vmid, ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc], timeout)
