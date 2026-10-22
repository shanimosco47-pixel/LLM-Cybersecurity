<#
.SYNOPSIS
  Removes Skill Guard hooks and scheduled tasks for the current user.
  Use -DeleteData to also delete %USERPROFILE%\.skill-guard (logs, reports, quarantine).
#>
[CmdletBinding()]
param([switch]$DeleteData)
$ErrorActionPreference = "Stop"

$GuardDir = Join-Path $env:USERPROFILE ".skill-guard"
$Py       = Join-Path $GuardDir "venv\Scripts\python.exe"
$GuardPy  = Join-Path $GuardDir "guard.py"

foreach ($t in "SkillGuard-Daily", "SkillGuard-Gate") {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $t -Confirm:$false
        Write-Host "Removed scheduled task $t"
    }
}

if ((Test-Path $Py) -and (Test-Path $GuardPy)) {
    & $Py $GuardPy uninstall-hooks
}

if ($DeleteData) {
    Remove-Item -Recurse -Force $GuardDir
    Write-Host "Deleted $GuardDir"
} else {
    Write-Host "Kept $GuardDir (quarantined skills and reports). Use -DeleteData to remove it."
}
Write-Host "SkillGate folder was left in place: $(Join-Path $env:USERPROFILE 'SkillGate')"
