$ErrorActionPreference = 'Stop'
$netless = (Resolve-Path 'build/netless.exe').Path
$probe = (Resolve-Path 'build/netless-probe.exe').Path

# AppContainer intentionally cannot read arbitrary user files. Grant access only
# to this disposable test workspace so the probe and its child can be executed.
& icacls.exe (Resolve-Path 'build').Path /grant '*S-1-15-2-1:(OI)(CI)RX' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not grant AppContainer read/execute access to test binaries.' }

& $netless -- $probe
if ($LASTEXITCODE -ne 0) {
    throw "AppContainer network probe failed (exit code $LASTEXITCODE)."
}
Write-Host 'Windows AppContainer network and descendant probes passed.'
