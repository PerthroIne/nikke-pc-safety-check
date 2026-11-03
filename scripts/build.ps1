# 단일 실행 파일을 만들고 SHA-256을 기록한다. 깨끗한 개발 환경에서 실행하세요.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$out = Join-Path $root 'artifacts/publish'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
dotnet publish src/NikkeSafetyCheck.App/NikkeSafetyCheck.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o $out
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Get-ChildItem $out -Exclude 'NikkeSafetyCheck.exe' | Remove-Item -Force -Recurse
$hash = (Get-FileHash (Join-Path $out 'NikkeSafetyCheck.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  NikkeSafetyCheck.exe" | Set-Content -Encoding ascii (Join-Path $out 'SHA256SUMS.txt')
Write-Host "SHA-256: $hash"
Write-Host ("크기: {0:N1} MB" -f ((Get-Item (Join-Path $out 'NikkeSafetyCheck.exe')).Length / 1MB))
