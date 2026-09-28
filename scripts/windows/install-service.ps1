# Install ReMgr as a Windows service-ish task and open its ports.
#
#     # from an elevated PowerShell, in the repository root
#     powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\install-service.ps1
#
# What it does, and why each piece is here:
#
#   * copies my own file next to itself (there is no MSI; this is one static
#     binary) into C:\Program Files\ReMgr;
#   * creates the data directory, C:\ProgramData\ReMgr — the Windows layout that
#     remgr/src/platform.rs defines (config.toml, ssl, lib, log, run);
#   * starts it once in the foreground to bootstrap config.toml, the console
#     password and the first P-384 certificate, then stops it, so the service that
#     starts later is the same install an operator would have produced by hand;
#   * registers a Scheduled Task that runs it as SYSTEM at boot and restarts it
#     every minute if it exits — the Windows counterpart of the Linux unit's
#     Restart=always and of scripts/remgr-watchdog.sh on OpenBSD;
#   * opens exactly the ports the modules listen on (and only those), including a
#     deliberately narrowed TURN relay range: the default is 49152-65535, which no
#     NAT device will forward for you, so the effective range is written into the
#     config on request.
#
# Ports opened: 9443/tcp console, 3478/udp STUN/TURN, 5349/tcp TURN over TLS,
# 7000/tcp frps, 21115-21119/tcp RustDesk, and the relay range (49200-49300/udp by
# default). If the machine sits behind NAT, the same list has to be forwarded on
# the router — this script cannot do that, and says so at the end.
#
# Stop/start:  Stop-ScheduledTask -TaskName ReMgr   (the daemon then runs its
#              graceful shutdown only if it is asked to: either a console control
#              event, which the task cannot send, or the `stop` file — see the
#              README's Windows section)
param(
    [string]$Source = (Join-Path $PSScriptRoot '..\..\target\release\remgr.exe'),
    [string]$InstallDir = 'C:\Program Files\ReMgr',
    [string]$DataDir = 'C:\ProgramData\ReMgr',
    [switch]$SkipFirewall,
    [switch]$SkipTask,
    [string]$PublicIp
)

$ErrorActionPreference = 'Stop'
$exe = Join-Path $InstallDir 'remgr.exe'

function Step($m) { Write-Host "==> $m" }

Step "preparing $DataDir"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'run') | Out-Null
if (-not (Test-Path $Source)) { throw "no binary at $Source (build it first: the CI artifacts and the GitHub release both contain remgr-windows-x86_64.exe)" }

# Windows refuses to overwrite a running image just as unix does ("The file is in
# use by another process" vs ETXTBSY), so an upgrade stops the running instance
# first — and stops it *gracefully*, through the same stop file the service
# answers, rather than killing it. Then the old binary is renamed aside before the
# new one is copied into place: a rename is allowed while the image is mapped, a
# delete is not.
$proc = Get-Process remgr -ErrorAction SilentlyContinue
if ($proc) {
    Step "stopping the running instance (pid $($proc.Id)) the polite way"
    New-Item -ItemType File -Force -Path (Join-Path $DataDir 'run\stop') | Out-Null
    for ($i = 0; $i -lt 30 -and ($null -ne (Get-Process remgr -ErrorAction SilentlyContinue)); $i++) {
        Start-Sleep -Milliseconds 500
    }
    if (Get-Process remgr -ErrorAction SilentlyContinue) {
        Write-Host '    it did not stop within 15s (an older build may not answer the stop file); stopping the task'
        Stop-ScheduledTask -TaskName 'ReMgr' -ErrorAction SilentlyContinue
        Get-Process remgr -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
    } else { Write-Host '    it stopped by itself' }
}

Step "installing the binary into $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$aside = "$exe.old"
Remove-Item $aside -Force -ErrorAction SilentlyContinue
if (Test-Path $exe) { Move-Item -Force $exe $aside }
Copy-Item $Source $exe -Force
Remove-Item $aside -Force -ErrorAction SilentlyContinue   # fails silently while the old image is still mapped
Write-Host ("    {0} ({1} MiB)" -f $exe, [math]::Round((Get-Item $exe).Length / 1MB))

if ((Get-Process remgr -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $DataDir 'config.toml'))) {
    Step 'already installed (a running instance or an existing config.toml) — skipping the bootstrap start'
} else {
Step 'first start, to bootstrap the config, the password and a certificate'
$out = Join-Path $env:TEMP 'remgr-first-run.log'
$p = Start-Process $exe -PassThru -RedirectStandardOutput $out -RedirectStandardError "$out.err"
Start-Sleep -Seconds 12
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force; Write-Host '    started and stopped (as intended)' }
else { Write-Host "    exited early ($($p.ExitCode)); see $out.err"; Get-Content "$out.err" | Select-Object -Last 10 }
Get-ChildItem $DataDir | Select-Object -ExpandProperty Name | ForEach-Object { Write-Host "    $_" }
}

if ($PublicIp) {
    Step "pointing the NAT-facing settings at $PublicIp"
    $cfg = Join-Path $DataDir 'config.toml'
    $text = Get-Content -Raw $cfg
    $text = $text -replace '(?m)^external_ip = .*$', "external_ip = `"$PublicIp`""
    $text = $text -replace '(?m)^domain = .*$', "domain = `"$PublicIp`""
    $text = $text -replace '(?m)^relay_min_port = .*$', 'relay_min_port = 49200'
    $text = $text -replace '(?m)^relay_max_port = .*$', 'relay_max_port = 49300'
    Set-Content -Path $cfg -Value $text -Encoding UTF8
    Write-Host "    external_ip/domain = $PublicIp, TURN relay range 49200-49300 (forward these on the router)"
    Write-Host '    also set [stun_turn].users: it ships empty, and RFC 5766 rejects every request without credentials'
}

if (-not $SkipFirewall) {
    Step 'opening the ports (inbound, only what the modules use)'
    $rules = @(
        @{ n = 'ReMgr console (HTTPS)'; p = '9443'; proto = 'TCP' },
        @{ n = 'ReMgr STUN/TURN (UDP)'; p = '3478'; proto = 'UDP' },
        @{ n = 'ReMgr TURN over TLS'; p = '5349'; proto = 'TCP' },
        @{ n = 'ReMgr frps'; p = '7000'; proto = 'TCP' },
        @{ n = 'ReMgr RustDesk'; p = '21115-21119'; proto = 'TCP' },
        @{ n = 'ReMgr TURN relay range'; p = '49200-49300'; proto = 'UDP' }
    )
    foreach ($r in $rules) {
        if (Get-NetFirewallRule -DisplayName $r.n -ErrorAction SilentlyContinue) {
            Write-Host "    exists: $($r.n)"
        } else {
            New-NetFirewallRule -DisplayName $r.n -Direction Inbound -Action Allow -Protocol $r.proto -LocalPort $r.p | Out-Null
            Write-Host "    added:  $($r.n) ($($r.proto) $($r.p))"
        }
    }
    $broad = Get-NetFirewallRule -DisplayName 'remgr' -ErrorAction SilentlyContinue
    if ($broad) {
        Write-Host '    NOTE: a rule named "remgr" already exists that allows TCP and UDP on ANY port.'
        Write-Host '          The rules above are port-specific; consider removing that one:'
        Write-Host '          Remove-NetFirewallRule -DisplayName remgr'
    }
}

if (-not $SkipTask) {
    Step 'registering the startup task (SYSTEM, at boot, restart on exit)'
    $action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $InstallDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'ReMgr' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'ReMgr'
    Start-Sleep -Seconds 12
    Get-ScheduledTask -TaskName 'ReMgr' | Select-Object TaskName, State | Format-Table -AutoSize
    Get-Process remgr -ErrorAction SilentlyContinue | Select-Object Id, StartTime | Format-Table -AutoSize
}

Step 'leaving the service running'
$task = Get-ScheduledTask -TaskName 'ReMgr' -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName 'ReMgr' -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'ReMgr'
} elseif (-not (Get-Process remgr -ErrorAction SilentlyContinue)) {
    Start-Process $exe -WorkingDirectory $InstallDir
}
Start-Sleep -Seconds 10
Get-Process remgr -ErrorAction SilentlyContinue | Select-Object Id, StartTime | Format-Table -AutoSize

Write-Host ''
Write-Host 'Console:      https://127.0.0.1:9443/   (the first password is "admin"; change it in the console)'
Write-Host "Data:         $DataDir"
Write-Host 'Stop/start:   Stop-ScheduledTask -TaskName ReMgr / Start-ScheduledTask -TaskName ReMgr'
Write-Host 'Graceful stop without a console event: write an empty file to ' -NoNewline
Write-Host (Join-Path $DataDir 'run\stop')
Write-Host ''
Write-Host 'Behind NAT? The ports above must be forwarded to this machine on the router.'
Write-Host 'The EasyTier node additionally needs the wintun driver and Npcap; everything'
Write-Host 'else runs without them ([easytier] node_enabled can stay false).'