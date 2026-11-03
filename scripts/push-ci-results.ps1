# 테스트 로그와 화면을 ci-results 브랜치에 남겨 누구나 볼 수 있게 한다. 러너의 사용자 정보는 포함하지 않는다.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$ci = Join-Path $root 'artifacts/ci'
if (-not (Test-Path $ci)) { exit 0 }
$w = Join-Path $env:RUNNER_TEMP 'ci-results'
New-Item -ItemType Directory -Force $w | Out-Null
Copy-Item -Recurse -Force "$ci/*" $w
Set-Location $w
git init -q
git config user.name 'github-actions'
git config user.email 'github-actions@users.noreply.github.com'
git checkout -q -b ci-results
"commit: $env:GITHUB_SHA`nrun: $env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID" | Set-Content RUN.txt
git add -A
git commit -q -m "CI results for $env:GITHUB_SHA"
$token = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("x-access-token:$env:GITHUB_TOKEN_FOR_PUSH"))
git -c "http.extraheader=AUTHORIZATION: basic $token" push -f "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY.git" ci-results
