# Windows wrapper for jenkins/scripts/run-pipeline-test.sh
$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$bash = Get-Command bash -ErrorAction SilentlyContinue
if (-not $bash) {
    Write-Error "bash not found. Install Git for Windows or run from WSL."
}
& bash "$scriptDir/run-pipeline-test.sh" @args
