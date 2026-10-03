"""Audit trusted, saved Docker inspect JSON without contacting Docker or a host.

This is a declarative configuration audit, not an isolation test.  Even a passing
snapshot cannot establish runtime DNS/egress isolation, snapshot authenticity,
absence of hidden host access, or trusted placement of an event collector.

Policy (all keys required, no extra keys)::

    {
      "schema_version": 1,
      "allowed_containers": [
        {"id": "full-container-id", "name": "agent",
         "network_ids": ["full-network-id"]}
      ],
      "private_networks": [{"id": "full-network-id", "name": "eval"}],
      "allowed_readonly_mounts": [
        {"container_id": "full-container-id", "type": "bind",
         "source": "/srv/eval/public", "destination": "/task"}
      ]
    }

Container/network inputs are arrays from docker inspect, restricted to exactly
the policy's identities.  IDs are matched exactly, not by prefix. Container
names may have Docker's single leading slash. Each container's network_ids is
its complete expected membership; an empty list requires network mode "none".
For that mode, attachments may be empty or contain only Docker's "none" entry;
the built-in null network is excluded from the private-network record array.
Private networks must be local bridge networks with Internal=true and a full
Containers map. Other drivers/scopes are unassessed. No namespace sharing,
added capabilities, devices, published ports, or writable/extraneous mounts are
allowed by this deliberately narrow policy. Allowed mounts may be bind or
volume and must match Source, Destination and Type exactly with RW=false.
Allowlisting cannot override runtime-socket or broad host bind rejection.

Missing/malformed evidence is unknown; observed disallowed configuration fails.
Failure takes precedence over unknown; runtime unknowns are reported separately
and never converted into a configuration failure or a claim of isolation.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import PurePosixPath
from typing import Any


_POLICY_KEYS = {"schema_version", "allowed_containers", "private_networks", "allowed_readonly_mounts"}
_BROAD_BINDS = {
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
    "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/sys", "/tmp",
    "/usr", "/var", "/Users", "/Volumes", "/private", "/private/var",
    "/var/run", "/var/lib", "/var/lib/docker", "/var/lib/containerd",
    "/run/containerd", "/run/podman", "/var/run/podman",
}
_SOCKET_NAMES = {"docker.sock", "containerd.sock", "crio.sock", "podman.sock", "cri-dockerd.sock"}


def _string(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and not any(ord(c) < 32 for c in value)


def _path(value: Any) -> bool:
    return _string(value) and value.startswith("/") and not value.startswith("//") and str(PurePosixPath(value)) == value and ".." not in value.split("/")


def _name(value: Any) -> str | None:
    if not _string(value):
        return None
    value = value[1:] if value.startswith("/") else value
    return value if value and "/" not in value else None


def _policy_valid(policy: Any) -> bool:
    if not isinstance(policy, dict) or set(policy) != _POLICY_KEYS:
        return False
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        return False
    containers, networks, mounts = (policy[k] for k in ("allowed_containers", "private_networks", "allowed_readonly_mounts"))
    if not isinstance(containers, list) or not containers or not isinstance(networks, list) or not isinstance(mounts, list):
        return False
    for rows, keys in ((containers, {"id", "name", "network_ids"}), (networks, {"id", "name"})):
        ids, names = set(), set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != keys or not _string(row["id"]) or _name(row["name"]) is None or _name(row["name"]) != row["name"]:
                return False
            if row["id"] in ids or row["name"] in names:
                return False
            ids.add(row["id"])
            names.add(row["name"])
    network_ids = {row["id"] for row in networks}
    container_ids = {row["id"] for row in containers}
    for row in containers:
        refs = row["network_ids"]
        if not isinstance(refs, list) or not all(_string(ref) for ref in refs) or len(set(refs)) != len(refs) or not set(refs) <= network_ids:
            return False
    seen_mounts = set()
    for row in mounts:
        if not isinstance(row, dict) or set(row) != {"container_id", "type", "source", "destination"}:
            return False
        if not _string(row["container_id"]) or row["container_id"] not in container_ids or row["type"] not in ("bind", "volume"):
            return False
        if not _path(row["source"]) or not _path(row["destination"]):
            return False
        key = (row["container_id"], row["type"], row["source"], row["destination"])
        if key in seen_mounts:
            return False
        seen_mounts.add(key)
    return True


def audit_containment(containers: Any, networks: Any, policy: Any) -> dict[str, Any]:
    """Return redacted findings; never perform I/O, execute probes, or mutate input."""
    findings: list[dict[str, str]] = []

    def add(status: str, code: str, subject: str, message: str) -> None:
        findings.append({"status": status, "code": code, "subject": subject, "message": message})

    def result() -> dict[str, Any]:
        statuses = {row["status"] for row in findings}
        return {
            "schema_version": 1,
            "configuration_status": "fail" if "fail" in statuses else "unknown" if "unknown" in statuses else "pass",
            "findings": findings,
            "evidence_scope": "saved_configuration_only",
            "runtime_egress_verified": False,
            "runtime_egress_status": "unknown",
            "runtime_dns_status": "unknown",
            "collector_trust_status": "unknown",
        }

    if not _policy_valid(policy):
        add("unknown", "invalid_policy", "policy", "Policy does not conform to the closed version-1 schema.")
        return result()
    wanted_containers = {row["id"]: row for row in policy["allowed_containers"]}
    wanted_networks = {row["id"]: row for row in policy["private_networks"]}
    permitted_mounts = {(row["container_id"], row["type"], row["source"], row["destination"]) for row in policy["allowed_readonly_mounts"]}

    def records(data: Any, wanted: dict[str, Any], kind: str) -> dict[str, Any]:
        found: dict[str, Any] = {}
        seen_names: set[str] = set()
        if not isinstance(data, list):
            add("unknown", "invalid_inspect_array", kind, "Inspect evidence must be an array of records.")
            data = []
        for index, row in enumerate(data):
            subject = f"{kind}[{index}]"
            if not isinstance(row, dict) or not _string(row.get("Id")) or _name(row.get("Name")) is None:
                add("unknown", "missing_identity", subject, "A record lacks a valid identity.")
                continue
            rid, name = row["Id"], _name(row["Name"])
            if kind == "network" and row["Name"] != name:
                add("unknown", "missing_identity", subject, "A network record has a malformed name.")
                continue
            if rid in found or name in seen_names:
                add("unknown", "duplicate_identity", subject, "Inspect evidence has duplicate identities.")
            if rid not in wanted:
                add("fail", "unexpected_identity", subject, "An inspected identity is outside the allowlist.")
                continue
            if name != wanted[rid]["name"]:
                add("fail", "identity_conflict", subject, "The inspected name and ID contradict the policy.")
            seen_names.add(name)
            if rid not in found:
                found[rid] = row
        for index, rid in enumerate(wanted):
            if rid not in found:
                add("unknown", "missing_inspect_record", f"{kind}.expected[{index}]", "An allowlisted identity has no inspect record.")
        return found

    actual_containers = records(containers, wanted_containers, "container")
    actual_networks = records(networks, wanted_networks, "network")

    def false_boolean(obj: dict[str, Any], key: str, subject: str, code: str) -> None:
        if type(obj.get(key)) is not bool:
            add("unknown", "missing_or_invalid_field", subject, f"{key} must be an explicit boolean.")
        elif obj[key]:
            add("fail", code, subject, f"{key} is enabled.")

    def empty_list(obj: dict[str, Any], key: str, subject: str, code: str, *, nullable: bool = False) -> None:
        value = obj.get(key)
        if key in obj and nullable and value is None:
            return
        if not isinstance(value, list):
            add("unknown", "missing_or_invalid_field", subject, f"{key} evidence is missing or malformed.")
        elif value:
            expected_type = str if key == "DeviceCgroupRules" else dict
            if not all(isinstance(entry, expected_type) and bool(entry) for entry in value):
                add("unknown", "missing_or_invalid_field", subject, f"{key} entries are malformed.")
            else:
                add("fail", code, subject, f"{key} contains a disallowed configuration.")

    def mount_paths(source: str, destination: str, kind: str, subject: str) -> None:
        if any(PurePosixPath(path).name in _SOCKET_NAMES for path in (source, destination)):
            add("fail", "runtime_socket_mount", subject, "A mount references a known runtime-socket path.")
        parts = PurePosixPath(source).parts
        restricted_tree = any(source.startswith(prefix + "/") for prefix in ("/proc", "/sys", "/dev", "/var/lib/docker", "/var/lib/containerd", "/run/containerd"))
        if kind == "bind" and (source in _BROAD_BINDS or restricted_tree or (len(parts) == 3 and parts[1] in ("home", "Users"))):
            add("fail", "broad_host_bind", subject, "A bind mount exposes a broad or runtime-sensitive host path.")
        if destination == "/":
            add("fail", "root_mount_destination", subject, "A mount replaces the container root.")

    for index, (cid, row) in enumerate(actual_containers.items()):
        subject = f"container[{index}]"
        before = len(findings)
        host = row.get("HostConfig")
        if not isinstance(host, dict):
            add("unknown", "missing_host_config", subject, "HostConfig evidence is missing or malformed.")
            host = {}
        false_boolean(host, "Privileged", subject, "privileged")
        false_boolean(host, "PublishAllPorts", subject, "published_ports")
        for key in ("Devices", "DeviceRequests", "DeviceCgroupRules"):
            empty_list(host, key, subject, "device_passthrough", nullable=key != "Devices")
        caps = host.get("CapAdd")
        if "CapAdd" not in host or (caps is not None and (not isinstance(caps, list) or not all(_string(c) for c in caps))):
            add("unknown", "missing_or_invalid_field", subject, "CapAdd evidence is missing or malformed.")
        elif caps:
            add("fail", "added_capabilities", subject, "Capability additions are outside this policy.")
        for key, allowed in (("PidMode", {"", "private"}), ("IpcMode", {"none", "private"})):
            value = host.get(key)
            if not isinstance(value, str):
                add("unknown", "missing_or_invalid_field", subject, f"{key} evidence is missing or malformed.")
            elif value == "host" or value.startswith("container:"):
                add("fail", "shared_namespace", subject, f"{key} shares a host or container namespace.")
            elif value not in allowed:
                add("unknown", "unassessed_namespace_mode", subject, f"{key} has an unassessed mode.")
        if "UTSMode" in host:
            value = host["UTSMode"]
            if not isinstance(value, str):
                add("unknown", "missing_or_invalid_field", subject, "UTSMode evidence is malformed.")
            elif value == "host" or value.startswith("container:"):
                add("fail", "shared_namespace", subject, "UTSMode shares a host or container namespace.")
            elif value != "":
                add("unknown", "unassessed_namespace_mode", subject, "UTSMode has an unassessed mode.")
        bindings = host.get("PortBindings")
        if "PortBindings" not in host or (bindings is not None and not isinstance(bindings, dict)):
            add("unknown", "missing_or_invalid_field", subject, "PortBindings evidence is missing or malformed.")
        elif isinstance(bindings, dict):
            for value in bindings.values():
                if value is not None and not isinstance(value, list):
                    add("unknown", "missing_or_invalid_field", subject, "Host port-binding evidence is malformed.")
                elif value:
                    add("fail", "published_ports", subject, "Host port bindings are outside this policy.")
        expected = set(wanted_containers[cid]["network_ids"])
        mode = host.get("NetworkMode")
        expected_modes = expected | {wanted_networks[nid]["name"] for nid in expected}
        if not isinstance(mode, str):
            add("unknown", "missing_or_invalid_field", subject, "NetworkMode evidence is missing or malformed.")
        elif mode == "host" or mode.startswith("container:"):
            add("fail", "shared_network_namespace", subject, "NetworkMode shares a host or container namespace.")
        elif mode not in (expected_modes if expected else {"none"}):
            add("fail", "unexpected_network_mode", subject, "NetworkMode contradicts the expected private topology.")

        settings = row.get("NetworkSettings")
        attached = settings.get("Networks") if isinstance(settings, dict) else None
        if not isinstance(attached, dict):
            add("unknown", "missing_network_memberships", subject, "Network attachment evidence is missing or malformed.")
        else:
            observed = set()
            for network_name, attachment in attached.items():
                if not isinstance(attachment, dict) or not _string(attachment.get("NetworkID")):
                    add("unknown", "missing_network_identity", subject, "An attachment lacks a valid network ID.")
                    continue
                if mode == "none" and not expected and network_name == "none":
                    continue
                nid = attachment["NetworkID"]
                if nid in observed:
                    add("unknown", "duplicate_attachment", subject, "The same network appears more than once.")
                observed.add(nid)
                if nid not in expected:
                    add("fail", "unexpected_network_attachment", subject, "A network attachment is outside the expected topology.")
                elif network_name != wanted_networks[nid]["name"]:
                    add("fail", "network_identity_conflict", subject, "An attachment's name and ID contradict the policy.")
            if expected - observed:
                add("unknown", "missing_network_attachment", subject, "An expected network attachment is absent from the snapshot.")
        ports = settings.get("Ports") if isinstance(settings, dict) else None
        if not isinstance(settings, dict) or "Ports" not in settings or (ports is not None and not isinstance(ports, dict)):
            add("unknown", "missing_or_invalid_field", subject, "Effective Ports evidence is missing or malformed.")
        elif isinstance(ports, dict):
            for value in ports.values():
                if value is not None and not isinstance(value, list):
                    add("unknown", "missing_or_invalid_field", subject, "Effective port-binding evidence is malformed.")
                elif value:
                    add("fail", "published_ports", subject, "Effective host port bindings are outside this policy.")

        mounts = row.get("Mounts")
        if not isinstance(mounts, list):
            add("unknown", "missing_mount_inventory", subject, "The effective mount inventory is missing or malformed.")
        else:
            destinations = set()
            for mount in mounts:
                if not isinstance(mount, dict) or mount.get("Type") not in ("bind", "volume") or not _path(mount.get("Source")) or not _path(mount.get("Destination")):
                    add("unknown", "unassessed_mount", subject, "A mount has missing fields or an unassessed type.")
                    continue
                source, destination = mount["Source"], mount["Destination"]
                if destination in destinations:
                    add("unknown", "duplicate_mount_destination", subject, "Multiple mounts use the same destination.")
                destinations.add(destination)
                if type(mount.get("RW")) is not bool:
                    add("unknown", "missing_or_invalid_field", subject, "Mount RW must be an explicit boolean.")
                elif mount["RW"]:
                    add("fail", "writable_mount", subject, "Writable persistent mounts are outside this policy, including private artifact mounts.")
                mount_paths(source, destination, mount["Type"], subject)
                if (cid, mount["Type"], source, destination) not in permitted_mounts:
                    add("fail", "unlisted_mount", subject, "A mount is outside the exact read-only allowlist.")
        # Check optional requested-mount declarations against the effective list.
        # Malformed or contradictory snapshots must not silently pass.
        requested = []
        binds = host.get("Binds")
        if binds is not None:
            if not isinstance(binds, list):
                add("unknown", "malformed_mount_declaration", subject, "Binds evidence is malformed.")
            else:
                for bind in binds:
                    fields = bind.split(":") if isinstance(bind, str) else []
                    if len(fields) not in (2, 3) or not _path(fields[0]) or not _path(fields[1]):
                        add("unknown", "malformed_mount_declaration", subject, "A bind declaration is malformed or unsupported.")
                        continue
                    flags = fields[2].split(",") if len(fields) == 3 else []
                    requested.append({"Type": "bind", "Source": fields[0], "Destination": fields[1], "RW": "ro" not in flags})
        declared = host.get("Mounts")
        if declared is not None:
            if not isinstance(declared, list):
                add("unknown", "malformed_mount_declaration", subject, "Requested Mounts evidence is malformed.")
            else:
                for entry in declared:
                    if not isinstance(entry, dict) or entry.get("Type") != "bind" or not _path(entry.get("Source")) or not _path(entry.get("Target")) or type(entry.get("ReadOnly")) is not bool:
                        add("unknown", "unassessed_mount_declaration", subject, "A requested mount declaration is malformed or outside the supported bind comparison.")
                        continue
                    requested.append({"Type": "bind", "Source": entry["Source"], "Destination": entry["Target"], "RW": not entry["ReadOnly"]})
        for entry in requested:
            mount_paths(entry["Source"], entry["Destination"], entry["Type"], subject)
            if entry["RW"]:
                add("fail", "writable_mount_declaration", subject, "A requested writable mount is outside this policy.")
            if not isinstance(mounts, list) or not any(isinstance(mount, dict) and all(type(mount.get(key)) is type(value) and mount.get(key) == value for key, value in entry.items()) for mount in mounts):
                add("unknown", "mount_declaration_conflict", subject, "Requested and effective mount evidence do not agree.")
        # These configuration surfaces can exist separately from the effective
        # Mounts list (notably tmpfs); do not silently assume the list covers them.
        for key in ("Tmpfs", "VolumesFrom"):
            value = host.get(key)
            expected_type = dict if key == "Tmpfs" else list
            if key not in host or (value is not None and not isinstance(value, expected_type)):
                add("unknown", "missing_or_invalid_field", subject, f"{key} evidence is missing or malformed.")
            elif value:
                add("fail", "additional_mount_configuration", subject, f"{key} is outside the mount policy.")
        if len(findings) == before:
            add("pass", "container_configuration_checked", subject, "The inspected container matches the declared configuration policy.")

    for index, (nid, row) in enumerate(actual_networks.items()):
        subject = f"network[{index}]"
        before = len(findings)
        if type(row.get("Internal")) is not bool:
            add("unknown", "missing_or_invalid_field", subject, "Internal must be an explicit boolean.")
        elif not row["Internal"]:
            add("fail", "non_internal_network", subject, "The expected private network is not marked Internal.")
        for key, value in (("Driver", "bridge"), ("Scope", "local")):
            if row.get(key) != value:
                add("unknown", "unassessed_network_kind", subject, f"The network's {key} is missing or outside the supported audit scope.")
        members = row.get("Containers")
        expected = {cid for cid, container in wanted_containers.items() if nid in container["network_ids"]}
        if not isinstance(members, dict):
            add("unknown", "missing_network_member_inventory", subject, "Network Containers evidence is missing or malformed.")
        else:
            for cid, member in members.items():
                if cid not in expected:
                    add("fail", "unexpected_network_member", subject, "The network has a member outside its expected container set.")
                elif not isinstance(member, dict) or _name(member.get("Name")) is None:
                    add("unknown", "missing_member_identity", subject, "A network member lacks a valid name.")
                elif _name(member["Name"]) != wanted_containers[cid]["name"]:
                    add("fail", "member_identity_conflict", subject, "A network member's name and ID contradict the policy.")
            if expected - set(members):
                add("unknown", "missing_network_member", subject, "The network snapshot omits an expected container member.")
        if len(findings) == before:
            add("pass", "network_configuration_checked", subject, "The inspected network matches the declared configuration policy.")
    return result()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--containers", required=True, help="Saved container inspect JSON array")
    parser.add_argument("--networks", required=True, help="Saved network inspect JSON array (use [] for network mode none)")
    parser.add_argument("--policy", required=True, help="Closed version-1 policy JSON; see the schema above")
    args = parser.parse_args(argv)
    try:
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON object key")
                result[key] = value
            return result

        def reject_constant(value: str) -> Any:
            raise ValueError("non-finite JSON number")

        def finite_float(value: str) -> float:
            result = float(value)
            if not math.isfinite(result):
                raise ValueError("non-finite JSON number")
            return result

        def read(path: str) -> Any:
            with open(path, encoding="utf-8") as handle:
                return json.load(handle, object_pairs_hook=unique_object,
                                 parse_constant=reject_constant, parse_float=finite_float)
        output = audit_containment(read(args.containers), read(args.networks), read(args.policy))
    except (OSError, ValueError, UnicodeError):
        output = audit_containment(None, None, None)
        output["findings"] = [{"status": "unknown", "code": "input_unreadable", "subject": "input", "message": "At least one input file could not be read as JSON."}]
    print(json.dumps(output, indent=2, sort_keys=True))
    return {"pass": 0, "fail": 1, "unknown": 2}[output["configuration_status"]]


if __name__ == "__main__":
    raise SystemExit(main())
