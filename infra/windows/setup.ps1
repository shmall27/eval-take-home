# Runs once, at first logon during the template build (from the answer CD).
# Installs VirtIO drivers and the QEMU guest agent, stages the clone-time
# files, then generalizes the machine with sysprep and shuts it down.
# The build script treats "VM powered off" as success, so any failure here
# leaves the VM running at the desktop with a log to read.
$ErrorActionPreference = 'Stop'
Start-Transcript -Path C:\Windows\Temp\range-template-setup.log -Force

$answer = Split-Path -Parent $MyInvocation.MyCommand.Path
$virtio = Get-PSDrive -PSProvider FileSystem |
    Where-Object { Test-Path (Join-Path $_.Root 'virtio-win-guest-tools.exe') } |
    Select-Object -First 1
if (-not $virtio) { throw 'VirtIO driver CD not found' }

$p = Start-Process -FilePath (Join-Path $virtio.Root 'virtio-win-guest-tools.exe') `
    -ArgumentList '/install', '/passive', '/norestart' -Wait -PassThru
Write-Host "guest tools installer exit code: $($p.ExitCode)"
if ($p.ExitCode -notin 0, 3010) { throw "guest tools install failed: $($p.ExitCode)" }

# The harness controls guests through the QEMU guest agent, so make sure it
# is present and starts on boot before this image is sealed.
$svc = Get-Service -Name 'QEMU-GA' -ErrorAction Stop
Set-Service -Name 'QEMU-GA' -StartupType Automatic
Write-Host "QEMU guest agent service: $($svc.Status)"

New-Item -ItemType Directory -Force -Path C:\Windows\Setup\Scripts | Out-Null
Copy-Item (Join-Path $answer 'SetupComplete.cmd') C:\Windows\Setup\Scripts\SetupComplete.cmd -Force
Copy-Item (Join-Path $answer 'clone-unattend.xml') C:\Windows\System32\Sysprep\clone-unattend.xml -Force

Stop-Transcript
& C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /quiet `
    /unattend:C:\Windows\System32\Sysprep\clone-unattend.xml
