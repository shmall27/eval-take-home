"""Networking check for the Proxmox sandbox: two VMs on one SDN vnet.

Proves Proxmox SDN works end to end on vanilla: both guests get DHCP leases from
the per-vnet dnsmasq, reach each other, and are contained (no internet, no path
to the hypervisor). No model is used; a no-op solver drives the environment and a
custom scorer runs the probes.

Run ON vanilla (set the PROXMOX_* env as in smoke_proxmox.py), then:
    uv run inspect eval harness/net_check.py --model openrouter/z-ai/glm-5.3
"""
import asyncio

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, Target, accuracy, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox
from proxmoxsandbox.schema import (
    DhcpRange,
    ProxmoxSandboxEnvironmentConfig,
    SdnConfig,
    SubnetConfig,
    VmConfig,
    VmNicConfig,
    VmSourceConfig,
    VnetConfig,
)

SRC = VmSourceConfig(existing_vm_template_tag="inspect-debian13-qga")


def vm(name: str) -> VmConfig:
    return VmConfig(
        vm_source_config=SRC, name=name,
        nics=(VmNicConfig(vnet_alias="lan"),), ram_mb=1024, vcpus=1,
    )


PROXMOX = ProxmoxSandboxEnvironmentConfig(
    sdn_config=SdnConfig(
        vnet_configs=(
            VnetConfig(
                alias="lan",
                subnets=(
                    SubnetConfig(
                        cidr="10.88.0.0/24", gateway="10.88.0.1", snat=False,  # snat off = no egress
                        dhcp_ranges=(DhcpRange(start="10.88.0.100", end="10.88.0.200"),),
                    ),
                ),
            ),
        ),
    ),
    vms_config=(vm("default"), vm("target")),
)


async def lan_ip(name: str, tries: int = 20) -> str:
    """Wait for the VM's DHCP lease on the 10.88 subnet."""
    for _ in range(tries):
        r = await sandbox(name).exec(
            ["bash", "-lc", "ip -4 -o addr show | awk '/10[.]88[.]/{print $4}' | cut -d/ -f1 | head -1"]
        )
        ip = r.stdout.strip()
        if ip:
            return ip
        await asyncio.sleep(3)
    return ""


@solver
def noop():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        return state
    return solve


@scorer(metrics=[accuracy()])
def network_check():
    async def score(state: TaskState, target: Target) -> Score:
        d_ip = await lan_ip("default")
        t_ip = await lan_ip("target")
        async def probe(cmd: str) -> str:
            r = await sandbox("default").exec(["bash", "-lc", cmd])
            return r.stdout.strip()
        reach = await probe(f"ping -c1 -W2 {t_ip} >/dev/null 2>&1 && echo yes || echo no") if t_ip else "no"
        inet = await probe("ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo yes || echo no")
        node = await probe("timeout 4 bash -c 'exec 3<>/dev/tcp/10.77.0.10/8006' 2>/dev/null && echo yes || echo no")
        ok = (
            d_ip.startswith("10.88.") and t_ip.startswith("10.88.")
            and reach == "yes" and inet == "no" and node == "no"
        )
        return Score(
            value=CORRECT if ok else INCORRECT, answer=f"{d_ip},{t_ip}",
            explanation=(
                f"default_ip={d_ip} target_ip={t_ip} default->target={reach} "
                f"default->internet={inet} default->hypervisor={node}"
            ),
        )
    return score


@task
def net_check():
    return Task(
        dataset=[Sample(input="network check", target="ok")],
        solver=noop(), scorer=network_check(), sandbox=("proxmox", PROXMOX),
    )
