# Windows on the range

The range host carries a sysprepped **Windows Server 2022** template. Any
number of Windows machines can be linked-cloned from it through the Proxmox
API; each clone comes up with its own SID and hostname and is controllable
with no network path to it.

| | |
|---|---|
| Template | VM 9000, `tpl-win2022` |
| Edition | Windows Server 2022 Standard Evaluation, Desktop Experience |
| Licence | Microsoft evaluation image, 180 days from each clone's first boot |
| Disk / memory / cores | 64 GiB thin qcow2 / 8 GiB / 4 (override per clone) |
| Firmware | BIOS (SeaBIOS), q35 |
| Drivers | VirtIO SCSI, network, balloon; QEMU guest agent |
| Local admin | `Administrator`; password on the range host in `~/cathedral/win-template-admin-password` |
| Patch level | As shipped in the image (March 2022). The range has no route to Windows Update. |

The template is otherwise stock: default firewall, Defender on, WinRM in its
server default state, RDP off. Scenario-specific configuration (domain
controller promotion, joins, users, planted weaknesses) belongs to whatever
provisions a range, not to the template.

## Using it

Clones are driven through the QEMU guest agent, which works over a virtual
serial channel. That matters here because range guests sit on an isolated
bridge that the harness cannot route to.

```
POST /nodes/cathedral-pve/qemu/9000/clone          newid=<id> name=<name>     # linked clone
POST /nodes/cathedral-pve/qemu/<id>/config         net0=virtio,bridge=vmbr1
POST /nodes/cathedral-pve/qemu/<id>/status/start
POST /nodes/cathedral-pve/qemu/<id>/agent/ping                                 # until it answers
POST /nodes/cathedral-pve/qemu/<id>/agent/exec     command=powershell.exe ...  # then agent/exec-status?pid=
```

`verify_clone.py` does exactly this end to end and is the reference for the
call sequence. `../range-host/pve.py` has the small client it uses.

Clones get no address automatically: the isolated bridge has no DHCP. Set one
through the guest agent (`New-NetIPAddress …`) or put a DHCP server in the
range.

## Verified

`verify_clone.py` passes end to end, including after a reboot of the Proxmox
node. Measured on the nested setup, two clones booting at once:

| Step | Time |
|---|---|
| Template build, ISO to sealed template | 9 min |
| Linked clone | 2 s |
| Start | under 1 s |
| First boot until the guest agent answers | about 30 s |
| First boot until Windows setup has finished | 2 to 3 min |
| Snapshot with RAM | 1.5 to 3.5 s |
| Rollback to that snapshot | 1.5 s, guest usable immediately |

What the run checks:

- Each clone has its own hostname and machine SID, and the VirtIO network
  adapter and guest agent are working.
- The answer file holding the admin password is gone from the clone.
- Two clones on `vmbr1` reach each other (ARP and TCP 5985).
- A clone cannot reach the Proxmox API or SSH, the egress proxy, or the
  internet, and gets no ARP answer for either management address.
- A file changed after a snapshot is restored by rollback.

Things to design around:

- **First boot is the slow part.** A fresh clone needs minutes; a rollback
  needs seconds. Build a range once, snapshot it, and reset by rollback.
- **The agent answers before Windows is ready.** It comes up during setup and
  the guest reboots under it. Wait for `HKLM\SYSTEM\Setup` to show setup
  finished, as the script does.
- **Agent calls time out under load.** Proxmox gives guest-agent calls a short
  timeout and a busy Windows guest misses it now and then. Retry.
- **Lifecycle calls after a live rollback** hit a lock for about 30 s; see the
  range-host README.

## Files

| File | Purpose |
|---|---|
| `build_template.sh` | Runs on the Proxmox node. Builds the answer CD, creates the VM, waits for sysprep to power it off, seals it as a template. |
| `autounattend.xml.tmpl` | Unattended install: loads VirtIO drivers in setup, partitions, installs, logs in once. |
| `setup.ps1` | First logon: installs guest tools, stages clone-time files, runs sysprep. |
| `clone-unattend.xml.tmpl` | Applied on each clone's first boot: skips first-run prompts, sets the admin password. |
| `SetupComplete.cmd` | Runs on each clone: deletes the answer file that holds the password. |
| `verify_clone.py` | Runs on the range host. Clone, boot, exec, containment probe, snapshot, rollback, destroy. |
| `screenshot.sh` | Runs on the Proxmox node. PNG of a VM's display, for watching an install. |

Passwords are substituted at build time from a file that lives only on the
range host. The answer CD that carries the rendered password is deleted when
the build finishes.

## Rebuilding or adding another version

```
# on the range host
lxc exec cathedral-pve -- bash -c 'cd /root/win && VMID=9001 NAME=tpl-win2025 \
  WIN_ISO=<iso> DRIVER_OS=2k25 ./build_template.sh'
```

Any new download host must first be added to the egress allowlist. A desktop
edition (Windows 10 or 11) has not been built. It needs an Enterprise
evaluation image and, for Windows 11, UEFI with a virtual TPM, which this
script does not set up.
