#!/usr/bin/env python3
"""Allowlisted forward proxy for the range hypervisor.

The Proxmox VM sits on a host bridge with no forwarded route to the internet
(the host's FORWARD policy is DROP). This proxy is the single, auditable
egress point: it only serves clients on the range bridge, only reaches
destinations whose hostname matches the allowlist, and logs every request.

Stop this process and the range has no egress at all.

Usage: egress_proxy.py --listen 10.77.0.1:3128 --allowlist allowlist.txt --log egress.log
Allowlist: one hostname suffix per line ("debian.org" matches deb.debian.org).
           A line containing only "*" allows everything. "#" starts a comment.
"""
import argparse
import asyncio
import ipaddress
import time
from urllib.parse import urlsplit


def load_allowlist(path):
    entries = []
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    entries.append(line)
    except FileNotFoundError:
        pass
    return entries


def allowed(host, entries):
    host = host.lower().rstrip(".")
    for e in entries:
        if e == "*" or host == e or host.endswith("." + e):
            return True
    return False


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class Proxy:
    def __init__(self, args):
        self.args = args
        self.clients = ipaddress.ip_network(args.clients)
        self.logf = open(args.log, "a", buffering=1)

    def log(self, peer, verdict, method, target):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.logf.write(f"{ts} {peer} {verdict} {method} {target}\n")

    async def deny(self, writer, code, msg):
        writer.write(f"HTTP/1.1 {code} {msg}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())
        try:
            await writer.drain()
        finally:
            writer.close()

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")[0]
        try:
            if ipaddress.ip_address(peer) not in self.clients:
                self.log(peer, "DENY-CLIENT", "-", "-")
                return await self.deny(writer, 403, "Forbidden")
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            lines = head.decode("latin-1").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
            if method.upper() == "CONNECT":
                host, _, port = target.rpartition(":")
                port = int(port)
                path = None
            else:
                u = urlsplit(target)
                if u.scheme != "http" or not u.hostname:
                    return await self.deny(writer, 400, "Bad Request")
                host, port = u.hostname, u.port or 80
                path = u.path or "/"
                if u.query:
                    path += "?" + u.query
            # Re-read the allowlist on every request so edits apply immediately.
            if not allowed(host, load_allowlist(self.args.allowlist)):
                self.log(peer, "DENY", method, target)
                return await self.deny(writer, 403, "Forbidden by egress allowlist")
            try:
                up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), 30)
            except Exception as e:
                self.log(peer, f"FAIL({type(e).__name__})", method, target)
                return await self.deny(writer, 502, "Bad Gateway")
            self.log(peer, "ALLOW", method, target)
            if path is None:
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
            else:
                # One request per connection: strip hop-by-hop headers and
                # force close so a kept-alive client cannot reuse this upstream
                # socket for a different (unchecked) host.
                hdrs = [h for h in lines[1:] if h and not h.lower().startswith(("proxy-connection:", "connection:"))]
                req = f"{method} {path} {version}\r\n" + "\r\n".join(hdrs) + "\r\nConnection: close\r\n\r\n"
                up_w.write(req.encode("latin-1"))
                await up_w.drain()
            await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError, ConnectionError):
            try:
                writer.close()
            except Exception:
                pass


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="10.77.0.1:3128")
    ap.add_argument("--clients", default="10.77.0.0/24")
    ap.add_argument("--allowlist", required=True)
    ap.add_argument("--log", required=True)
    args = ap.parse_args()
    host, _, port = args.listen.rpartition(":")
    server = await asyncio.start_server(Proxy(args).handle, host, int(port))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
