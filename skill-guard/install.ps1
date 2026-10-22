<#
.SYNOPSIS
  Installs Skill Guard for the current Windows user.

.DESCRIPTION
  1. Creates %USERPROFILE%\.skill-guard with a private Python venv.
  2. Installs Cisco's open-source skill scanner (cisco-ai-skill-scanner) into it.
  3. Adds Skill Guard hooks and deny rules to %USERPROFILE%\.claude\settings.json
     (a timestamped backup is written first).
  4. Creates the claude.ai gate folders in %USERPROFILE%\SkillGate.
  5. Registers two scheduled tasks for this user only (no admin rights needed):
       SkillGuard-Daily  full rescan every day at -DailyAt (default 09:00)
       SkillGuard-Gate   watches SkillGate\inbox, starts at logon
  6. Runs a first full scan of everything already installed.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
[CmdletBinding()]
param(
    [string]$DailyAt = "09:00",
    [switch]$NoDenyRules
)
$ErrorActionPreference = "Stop"

$GuardDir = Join-Path $env:USERPROFILE ".skill-guard"
$VenvDir  = Join-Path $GuardDir "venv"
$Py       = Join-Path $VenvDir "Scripts\python.exe"
$PyW      = Join-Path $VenvDir "Scripts\pythonw.exe"
$GuardPy  = Join-Path $GuardDir "guard.py"

function Find-Python {
    # The scanner supports Python 3.11 to 3.14.
    foreach ($v in "3.13", "3.12", "3.11", "3.14") {
        try {
            $exe = & py "-$v" -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $exe) { return $exe.Trim() }
        } catch { }
    }
    foreach ($name in "python", "python3") {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            $ok = & $cmd.Source -c "import sys; print(int((3,11) <= sys.version_info[:2] < (3,15)))" 2>$null
            if ($ok -eq "1") { return $cmd.Source }
        }
    }
    return $null
}

Write-Host "== Skill Guard installer ==" -ForegroundColor Cyan

$BasePy = Find-Python
if (-not $BasePy) {
    Write-Host "Python 3.11-3.14 was not found." -ForegroundColor Red
    Write-Host "Install it with:  winget install Python.Python.3.13   then run this script again."
    exit 1
}
Write-Host "Using Python: $BasePy"

New-Item -ItemType Directory -Force -Path $GuardDir | Out-Null
Copy-Item -Force (Join-Path $PSScriptRoot "guard.py") $GuardPy

if (-not (Test-Path $Py)) {
    Write-Host "Creating virtual environment..."
    & $BasePy -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
}
Write-Host "Installing Cisco skill-scanner (this can take a few minutes)..."
& $Py -m pip install --quiet --upgrade pip
& $Py -m pip install --quiet --upgrade cisco-ai-skill-scanner
if ($LASTEXITCODE -ne 0) { throw "pip install cisco-ai-skill-scanner failed" }

Write-Host "Adding hooks to Claude Code settings..."
$hookArgs = @($GuardPy, "install-hooks")
if ($NoDenyRules) { $hookArgs += "--no-deny-rules" }
& $Py @hookArgs
if ($LASTEXITCODE -ne 0) { throw "install-hooks failed" }

Write-Host "Registering scheduled tasks..."
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

$dailyAction  = New-ScheduledTaskAction -Execute $PyW -Argument "`"$GuardPy`" daily" -WorkingDirectory $GuardDir
$dailyTrigger = New-ScheduledTaskTrigger -Daily -At $DailyAt
Register-ScheduledTask -TaskName "SkillGuard-Daily" -Action $dailyAction -Trigger $dailyTrigger `
    -Settings $settings -Principal $principal -Description "Skill Guard: daily rescan of Claude skills" -Force | Out-Null

$gateSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)
$gateAction  = New-ScheduledTaskAction -Execute $PyW -Argument "`"$GuardPy`" watch-gate" -WorkingDirectory $GuardDir
$gateTrigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
Register-ScheduledTask -TaskName "SkillGuard-Gate" -Action $gateAction -Trigger $gateTrigger `
    -Settings $gateSettings -Principal $principal -Description "Skill Guard: scans skills dropped into SkillGate\inbox" -Force | Out-Null
Start-ScheduledTask -TaskName "SkillGuard-Gate"

Write-Host "Running first full scan of installed skills..."
& $Py $GuardPy scan-all
$scanExit = $LASTEXITCODE

$Gate = Join-Path $env:USERPROFILE "SkillGate"
Write-Host ""
Write-Host "== Installed ==" -ForegroundColor Green
Write-Host "Claude Code hooks : active from the next Claude Code session (restart open sessions)"
Write-Host "Daily full scan   : every day at $DailyAt"
Write-Host "claude.ai gate    : drop skill .zip files into $Gate\inbox"
Write-Host "Log               : $GuardDir\guard.log"
if ($scanExit -ne 0) {
    Write-Host "The first scan found dangerous skills and quarantined them. See the output above." -ForegroundColor Yellow
}
