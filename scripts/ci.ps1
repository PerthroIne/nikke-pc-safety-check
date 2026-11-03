# 빌드, 테스트, 게시를 순서대로 실행한다. 결과는 artifacts/ci에 남긴다.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$ci = Join-Path $root 'artifacts/ci'
New-Item -ItemType Directory -Force $ci | Out-Null
$failed = $false

function Step($name, [scriptblock]$body) {
    Write-Host "== $name"
    & $body 2>&1 | Tee-Object -FilePath (Join-Path $ci "$name.log") -Append
    if ($LASTEXITCODE -ne 0) { Write-Host "실패: $name (exit $LASTEXITCODE)"; $script:failed = $true }
    $global:LASTEXITCODE = 0
}

Step 'env' { dotnet --info; [Environment]::OSVersion | Out-String; whoami /groups | Select-String 'Mandatory' }
Step 'build-app' { ./scripts/build.ps1 }
Step 'core-tests' { dotnet run -c Release --project tests/NikkeSafetyCheck.Tests }
$exe = Join-Path $root 'artifacts/publish/NikkeSafetyCheck.exe'
if (Test-Path $exe) {
    Step 'windows-tests' {
        $env:DOTNET_gcServer = '0'
        dotnet run -c Release --project tests/NikkeSafetyCheck.WinTests -- --out (Join-Path $ci 'screens') --app $exe --e2e
    }
} else { $failed = $true; Write-Host '게시 파일 없음' }
if ($failed) { exit 1 }
