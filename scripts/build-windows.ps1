$ErrorActionPreference = 'Stop'

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    throw 'cl.exe was not found. Run this script from a Visual Studio Developer PowerShell.'
}

New-Item -ItemType Directory -Force -Path build | Out-Null
& cl.exe /nologo /O2 /W4 /WX /D_CRT_SECURE_NO_WARNINGS /D_WIN32_WINNT=0x0602 `
    /Febuild/netless.exe src/netless_windows.c `
    userenv.lib advapi32.lib shell32.lib ws2_32.lib
if ($LASTEXITCODE -ne 0) { throw "netless build failed with exit code $LASTEXITCODE" }

& cl.exe /nologo /O2 /W4 /WX /D_CRT_SECURE_NO_WARNINGS `
    /Febuild/netless-probe.exe tests/windows_probe.c ws2_32.lib
if ($LASTEXITCODE -ne 0) { throw "network probe build failed with exit code $LASTEXITCODE" }
