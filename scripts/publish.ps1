Param(
    [ValidateSet("testpypi", "pypi")]
    [string]$Repository = "testpypi",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = "C:/Program Files/Python312/python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}

$args = @("scripts/release.py", "--repository", $Repository)
if ($SkipBuild) {
    $args += "--skip-build"
}

& $python @args
