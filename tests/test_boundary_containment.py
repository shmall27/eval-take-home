"""Offline containment checks using fabricated inspect objects only."""

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from boundary_eval.containment import audit_containment, main


def sample():
    policy = {
        "schema_version": 1,
        "allowed_containers": [
            {"id": "c-agent", "name": "agent", "network_ids": ["n-eval"]},
            {"id": "c-target", "name": "target", "network_ids": ["n-eval"]},
        ],
        "private_networks": [{"id": "n-eval", "name": "eval"}],
        "allowed_readonly_mounts": [],
    }
    containers = []
    for cid, name in (("c-agent", "agent"), ("c-target", "target")):
        containers.append({
            "Id": cid,
            "Name": "/" + name,
            "HostConfig": {
                "Privileged": False, "PublishAllPorts": False,
                "CapAdd": None, "Devices": [], "DeviceRequests": None,
                "DeviceCgroupRules": None, "PidMode": "", "IpcMode": "private",
                "NetworkMode": "eval", "PortBindings": {},
                "Tmpfs": None, "VolumesFrom": None,
            },
            "NetworkSettings": {
                "Networks": {"eval": {"NetworkID": "n-eval"}},
                "Ports": {"8080/tcp": None},
            },
            "Mounts": [],
            "Config": {"Env": ["TOKEN=secret-marker-never-emit"]},
        })
    networks = [{
        "Id": "n-eval", "Name": "eval", "Driver": "bridge", "Scope": "local",
        "Internal": True,
        "Containers": {"c-agent": {"Name": "agent"}, "c-target": {"Name": "target"}},
    }]
    return containers, networks, policy


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.containers, self.networks, self.policy = sample()

    def audit(self):
        return audit_containment(self.containers, self.networks, self.policy)

    def assertFinding(self, status, code):
        result = self.audit()
        self.assertEqual(result["configuration_status"], status, result)
        self.assertIn(code, [item["code"] for item in result["findings"]])
        return result

    def add_mount(self, source="/srv/eval/public", destination="/task", kind="bind", rw=False):
        self.containers[0]["Mounts"].append({"Type": kind, "Source": source, "Destination": destination, "RW": rw})
        self.policy["allowed_readonly_mounts"].append({
            "container_id": "c-agent", "type": kind, "source": source, "destination": destination,
        })

    def test_private_topology_passes_without_proving_runtime_isolation(self):
        result = self.audit()
        self.assertEqual(result["configuration_status"], "pass")
        self.assertTrue(all(row["status"] == "pass" for row in result["findings"]))
        self.assertIs(result["runtime_egress_verified"], False)
        self.assertEqual(result["runtime_egress_status"], "unknown")
        self.assertEqual(result["runtime_dns_status"], "unknown")
        self.assertEqual(result["collector_trust_status"], "unknown")

    def test_no_mutation_and_no_secret_disclosure(self):
        original = copy.deepcopy((self.containers, self.networks, self.policy))
        serialized = json.dumps(self.audit())
        self.assertNotIn("secret-marker", serialized)
        self.assertEqual((self.containers, self.networks, self.policy), original)

    def test_network_mode_none_with_empty_memberships(self):
        self.policy["private_networks"] = []
        self.networks = []
        for record, rule in zip(self.containers, self.policy["allowed_containers"]):
            rule["network_ids"] = []
            record["HostConfig"]["NetworkMode"] = "none"
            record["NetworkSettings"]["Networks"] = {}
        self.assertEqual(self.audit()["configuration_status"], "pass")

    def test_network_mode_none_with_builtin_null_entry(self):
        self.policy["private_networks"] = []
        self.networks = []
        for record, rule in zip(self.containers, self.policy["allowed_containers"]):
            rule["network_ids"] = []
            record["HostConfig"]["NetworkMode"] = "none"
            record["NetworkSettings"]["Networks"] = {"none": {"NetworkID": "builtin-none"}}
        self.assertEqual(self.audit()["configuration_status"], "pass")
        self.containers[0]["NetworkSettings"]["Networks"]["external"] = {"NetworkID": "other"}
        self.assertFinding("fail", "unexpected_network_attachment")

    def test_network_id_is_valid_mode_alias(self):
        self.containers[0]["HostConfig"]["NetworkMode"] = "n-eval"
        self.assertEqual(self.audit()["configuration_status"], "pass")

    def test_host_and_container_network_namespaces_fail(self):
        for mode in ("host", "container:c-target", "container:unrelated"):
            with self.subTest(mode=mode):
                self.containers[0]["HostConfig"]["NetworkMode"] = mode
                self.assertFinding("fail", "shared_network_namespace")

    def test_host_pid_ipc_and_uts_fail(self):
        for key in ("PidMode", "IpcMode", "UTSMode"):
            for value in ("host", "container:c-target", "container:outsider"):
                with self.subTest(key=key, value=value):
                    containers, networks, policy = sample()
                    containers[0]["HostConfig"][key] = value
                    report = audit_containment(containers, networks, policy)
                    self.assertEqual(report["configuration_status"], "fail")
                    self.assertIn("shared_namespace", [row["code"] for row in report["findings"]])

    def test_unassessed_namespace_mode_is_unknown(self):
        self.containers[0]["HostConfig"]["IpcMode"] = "shareable"
        self.assertFinding("unknown", "unassessed_namespace_mode")

    def test_privileged_fails(self):
        self.containers[0]["HostConfig"]["Privileged"] = True
        self.assertFinding("fail", "privileged")

    def test_capability_additions_fail(self):
        for caps in (["SYS_ADMIN"], ["CAP_NET_ADMIN"], ["ALL"], ["IPC_LOCK"]):
            self.containers[0]["HostConfig"]["CapAdd"] = caps
            self.assertFinding("fail", "added_capabilities")

    def test_devices_fail(self):
        for key, value in (("Devices", [{"PathOnHost": "/dev/fake"}]),
                           ("DeviceRequests", [{"Capabilities": [["gpu"]]}]),
                           ("DeviceCgroupRules", ["c 1:3 rwm"])):
            with self.subTest(key=key):
                self.setUp()
                self.containers[0]["HostConfig"][key] = value
                self.assertFinding("fail", "device_passthrough")

    def test_published_ports_fail(self):
        self.containers[0]["HostConfig"]["PublishAllPorts"] = True
        self.assertFinding("fail", "published_ports")
        self.setUp()
        self.containers[0]["HostConfig"]["PortBindings"] = {"80/tcp": [{"HostPort": "8000"}]}
        self.assertFinding("fail", "published_ports")
        self.setUp()
        self.containers[0]["NetworkSettings"]["Ports"] = {"80/tcp": [{"HostPort": "8000"}]}
        self.assertFinding("fail", "published_ports")

    def test_empty_port_binding_entries_do_not_claim_published_ports(self):
        self.containers[0]["HostConfig"]["PortBindings"] = {"80/tcp": None, "90/tcp": []}
        self.assertEqual(self.audit()["configuration_status"], "pass")
        self.containers[0]["HostConfig"]["PortBindings"] = {"80/tcp": False}
        self.assertFinding("unknown", "missing_or_invalid_field")

    def test_exact_readonly_mount_passes(self):
        self.add_mount()
        self.assertEqual(self.audit()["configuration_status"], "pass")

    def test_readonly_volume_exact_source_passes(self):
        self.add_mount(source="/var/lib/docker/volumes/public/_data", kind="volume")
        self.assertEqual(self.audit()["configuration_status"], "pass")

    def test_writable_private_artifact_fails_even_if_listed(self):
        self.add_mount(destination="/logs/verifier", rw=True)
        self.assertFinding("fail", "writable_mount")

    def test_unlisted_mount_fails(self):
        self.add_mount()
        self.policy["allowed_readonly_mounts"] = []
        self.assertFinding("fail", "unlisted_mount")

    def test_mount_permission_is_scoped_to_container_and_exact_path(self):
        self.add_mount()
        self.containers[1]["Mounts"] = copy.deepcopy(self.containers[0]["Mounts"])
        self.assertFinding("fail", "unlisted_mount")
        self.containers[1]["Mounts"] = []
        self.containers[0]["Mounts"][0]["Source"] += "/child"
        self.assertFinding("fail", "unlisted_mount")

    def test_broad_readonly_binds_fail_despite_allowlist(self):
        for source in ("/", "/var/run", "/proc", "/sys", "/proc/sys", "/dev/mem", "/Users/anyone", "/home/anyone"):
            with self.subTest(source=source):
                self.setUp()
                self.add_mount(source=source)
                self.assertFinding("fail", "broad_host_bind")

    def test_runtime_sockets_fail_despite_allowlist(self):
        for basename in ("docker.sock", "containerd.sock", "podman.sock", "crio.sock"):
            with self.subTest(basename=basename):
                self.setUp()
                self.add_mount(source="/run/private/" + basename)
                report = self.assertFinding("fail", "runtime_socket_mount")
                self.assertNotIn("/run/private/", json.dumps(report))

    def test_socket_destination_fails(self):
        self.add_mount(destination="/run/docker.sock")
        self.assertFinding("fail", "runtime_socket_mount")

    def test_root_destination_fails(self):
        self.add_mount(destination="/")
        self.assertFinding("fail", "root_mount_destination")

    def test_extra_mount_surfaces_fail(self):
        for key, value in (("Tmpfs", {"/tests": "rw"}), ("VolumesFrom", ["outside"])):
            with self.subTest(key=key):
                self.setUp()
                self.containers[0]["HostConfig"][key] = value
                self.assertFinding("fail", "additional_mount_configuration")

    def test_consistent_requested_bind_declarations_pass(self):
        self.add_mount()
        self.containers[0]["HostConfig"]["Binds"] = ["/srv/eval/public:/task:ro"]
        self.containers[0]["HostConfig"]["Mounts"] = [{
            "Type": "bind", "Source": "/srv/eval/public", "Target": "/task", "ReadOnly": True,
        }]
        self.assertEqual(self.audit()["configuration_status"], "pass")

    def test_effective_inventory_cannot_hide_requested_runtime_socket(self):
        self.containers[0]["HostConfig"]["Binds"] = ["/run/private/docker.sock:/sock:ro"]
        report = self.assertFinding("fail", "runtime_socket_mount")
        self.assertIn("mount_declaration_conflict", [row["code"] for row in report["findings"]])

    def test_requested_and_effective_bind_disagreement_is_unknown(self):
        self.add_mount()
        self.containers[0]["HostConfig"]["Binds"] = ["/srv/eval/other:/task:ro"]
        self.assertFinding("unknown", "mount_declaration_conflict")

    def test_writable_requested_bind_fails(self):
        self.add_mount()
        self.containers[0]["HostConfig"]["Mounts"] = [{
            "Type": "bind", "Source": "/srv/eval/public", "Target": "/task", "ReadOnly": False,
        }]
        self.assertFinding("fail", "writable_mount_declaration")

    def test_extra_network_attachment_fails(self):
        self.containers[0]["NetworkSettings"]["Networks"]["bridge"] = {"NetworkID": "n-external"}
        self.assertFinding("fail", "unexpected_network_attachment")

    def test_external_network_member_fails_without_its_inspect_record(self):
        self.networks[0]["Containers"]["outsider"] = {"Name": "outside"}
        self.assertFinding("fail", "unexpected_network_member")

    def test_allowed_container_is_not_implicitly_allowed_on_every_network(self):
        self.policy["allowed_containers"][1]["network_ids"] = []
        self.containers[1]["HostConfig"]["NetworkMode"] = "none"
        self.containers[1]["NetworkSettings"]["Networks"] = {}
        self.assertFinding("fail", "unexpected_network_member")

    def test_noninternal_network_fails(self):
        self.networks[0]["Internal"] = False
        self.assertFinding("fail", "non_internal_network")

    def test_other_driver_and_scope_are_unknown(self):
        for key, value in (("Driver", "overlay"), ("Scope", "swarm")):
            with self.subTest(key=key):
                self.setUp()
                self.networks[0][key] = value
                self.assertFinding("unknown", "unassessed_network_kind")

    def test_missing_container_or_network_record_is_unknown(self):
        self.containers.pop()
        self.assertFinding("unknown", "missing_inspect_record")
        self.setUp()
        self.networks.clear()
        self.assertFinding("unknown", "missing_inspect_record")

    def test_incomplete_network_member_snapshot_is_unknown(self):
        del self.networks[0]["Containers"]["c-target"]
        self.assertFinding("unknown", "missing_network_member")
        del self.networks[0]["Containers"]
        self.assertFinding("unknown", "missing_network_member_inventory")

    def test_incomplete_container_membership_is_unknown(self):
        self.containers[0]["NetworkSettings"]["Networks"] = {}
        self.assertFinding("unknown", "missing_network_attachment")

    def test_identity_contradictions_fail(self):
        for mutate in (
            lambda: self.containers[0].update(Name="/target"),
            lambda: self.networks[0].update(Name="other"),
            lambda: self.networks[0]["Containers"]["c-agent"].update(Name="target"),
            lambda: self.containers[0]["NetworkSettings"].update(Networks={"other": {"NetworkID": "n-eval"}}),
        ):
            self.setUp()
            mutate()
            self.assertEqual(self.audit()["configuration_status"], "fail")

    def test_unexpected_records_fail_and_ids_are_not_prefix_matched(self):
        self.containers[0]["Id"] = "c-ag"
        result = self.assertFinding("fail", "unexpected_identity")
        self.assertIn("missing_inspect_record", [item["code"] for item in result["findings"]])

    def test_duplicate_record_is_unknown(self):
        self.containers.append(copy.deepcopy(self.containers[0]))
        self.assertFinding("unknown", "duplicate_identity")

    def test_boolean_fields_do_not_accept_integer_or_string(self):
        for key in ("Privileged", "PublishAllPorts"):
            for value in (0, 1, "false", None):
                self.setUp()
                self.containers[0]["HostConfig"][key] = value
                self.assertFinding("unknown", "missing_or_invalid_field")
        for value in (0, 1, "true", None):
            self.setUp()
            self.networks[0]["Internal"] = value
            self.assertFinding("unknown", "missing_or_invalid_field")
        self.setUp()
        self.add_mount()
        self.containers[0]["Mounts"][0]["RW"] = 0
        self.assertFinding("unknown", "missing_or_invalid_field")

    def test_missing_essential_fields_cannot_pass(self):
        for key in tuple(self.containers[0]["HostConfig"]):
            with self.subTest(key=key):
                self.setUp()
                del self.containers[0]["HostConfig"][key]
                self.assertEqual(self.audit()["configuration_status"], "unknown")
        for key in ("HostConfig", "NetworkSettings", "Mounts"):
            self.setUp()
            del self.containers[0][key]
            self.assertEqual(self.audit()["configuration_status"], "unknown")

    def test_malformed_collections_are_unknown(self):
        for key, value in (("CapAdd", [False]), ("Devices", [False]), ("DeviceRequests", {}), ("Tmpfs", [])):
            self.setUp()
            self.containers[0]["HostConfig"][key] = value
            self.assertFinding("unknown", "missing_or_invalid_field")

    def test_unknown_mount_type_or_fields_cannot_pass(self):
        self.containers[0]["Mounts"] = [{"Type": "future-kind", "RW": False}]
        self.assertFinding("unknown", "unassessed_mount")

    def test_failure_preserves_independent_evidence_gaps(self):
        self.containers[0]["HostConfig"]["Privileged"] = True
        self.networks[0].pop("Containers")
        result = self.assertFinding("fail", "privileged")
        self.assertIn("unknown", [item["status"] for item in result["findings"]])

    def test_policy_is_closed_and_strict(self):
        variants = []
        for key in self.policy:
            value = copy.deepcopy(self.policy)
            del value[key]
            variants.append(value)
        for key, value in (("schema_version", True), ("extra", 1), ("allowed_containers", [])):
            variant = copy.deepcopy(self.policy)
            variant[key] = value
            variants.append(variant)
        variant = copy.deepcopy(self.policy)
        variant["allowed_containers"][0]["name"] = None
        variants.append(variant)
        variant = copy.deepcopy(self.policy)
        variant["allowed_containers"][0]["network_ids"] = ["unknown"]
        variants.append(variant)
        for value in variants:
            self.policy = value
            self.assertFinding("unknown", "invalid_policy")

    def test_policy_paths_cannot_contain_aliases(self):
        for source in ("/srv/eval/../secret", "//", "/srv//eval", "/srv/eval/."):
            self.setUp()
            self.add_mount(source=source)
            self.assertFinding("unknown", "invalid_policy")

    def test_invalid_inspect_inputs_do_not_raise(self):
        for value in (None, {}, True, "text", 7, [None], [True], [[]]):
            self.assertEqual(audit_containment(value, self.networks, self.policy)["configuration_status"], "unknown")
            self.assertEqual(audit_containment(self.containers, value, self.policy)["configuration_status"], "unknown")


class CliTests(unittest.TestCase):
    def invoke(self, contents):
        return self.invoke_raw([json.dumps(value) for value in contents])

    def invoke_raw(self, contents):
        with tempfile.TemporaryDirectory() as directory:
            args = []
            for name, value in zip(("containers", "networks", "policy"), contents):
                path = Path(directory) / (name + ".json")
                path.write_text(value, encoding="utf-8")
                args.extend(("--" + name, str(path)))
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                status = main(args)
            return status, json.loads(stream.getvalue())

    def test_exit_codes(self):
        contents = sample()
        status, report = self.invoke(contents)
        self.assertEqual(status, 0)
        self.assertEqual(report["configuration_status"], "pass")
        contents[0][0]["HostConfig"]["Privileged"] = True
        self.assertEqual(self.invoke(contents)[0], 1)
        contents[0][0]["HostConfig"]["Privileged"] = None
        self.assertEqual(self.invoke(contents)[0], 2)

    def test_unreadable_file_reports_unknown_without_echoing_path(self):
        stream = io.StringIO()
        path = "/nonexistent/private-secret-marker.json"
        with contextlib.redirect_stdout(stream):
            status = main(["--containers", path, "--networks", path, "--policy", path])
        self.assertEqual(status, 2)
        report = json.loads(stream.getvalue())
        self.assertEqual(report["configuration_status"], "unknown")
        self.assertNotIn("private-secret-marker", stream.getvalue())

    def test_duplicate_keys_cannot_hide_contradictory_configuration(self):
        cases = (
            (0, '"Privileged": false', '"Privileged": true, "Privileged": false'),
            (1, '"Internal": true', '"Internal": false, "Internal": true'),
            (2, '"schema_version": 1', '"schema_version": 0, "schema_version": 1'),
        )
        for index, original, replacement in cases:
            with self.subTest(index=index):
                contents = [json.dumps(value) for value in sample()]
                self.assertIn(original, contents[index])
                contents[index] = contents[index].replace(original, replacement, 1)
                status, report = self.invoke_raw(contents)
                self.assertEqual(status, 2)
                self.assertEqual(report["configuration_status"], "unknown")
                self.assertEqual(report["findings"][0]["code"], "input_unreadable")

    def test_nonfinite_numbers_and_float_overflow_are_unknown(self):
        for literal in ("NaN", "Infinity", "-Infinity", "1e9999", "-1e9999"):
            with self.subTest(literal=literal):
                contents = sample()
                contents[0][0]["Config"]["IgnoredNumeric"] = "number-marker"
                serialized = [json.dumps(value) for value in contents]
                serialized[0] = serialized[0].replace('"number-marker"', literal)
                status, report = self.invoke_raw(serialized)
                self.assertEqual(status, 2)
                self.assertEqual(report["configuration_status"], "unknown")
                self.assertEqual(report["findings"][0]["code"], "input_unreadable")


if __name__ == "__main__":
    unittest.main()
