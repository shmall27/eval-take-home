"""Smoke eval: the one trivial CTF, run through Inspect Cyber's standard agent.

Proves the full loop: Inspect Cyber dataset -> basic_agent (bash+python in the
sandbox) -> includes() flag scorer, against GLM-5.3. Sandbox is selected by the
task's eval.yaml, so the same task runs on Docker or Proxmox unchanged.

    uv run inspect eval harness/smoke_eval.py --model openrouter/z-ai/glm-5.3
"""
from pathlib import Path

from inspect_ai import task
from inspect_cyber import cyber_task

TASK_ROOT = Path(__file__).resolve().parent.parent / "tasks" / "smoke"


@task
def smoke():
    return cyber_task(root_dir=str(TASK_ROOT))
