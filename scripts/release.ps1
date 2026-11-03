# 태그 빌드의 실행 파일과 해시로 GitHub 릴리스를 만든다.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$tag = $env:GITHUB_REF_NAME
$pub = 'artifacts/publish'
gh release create $tag "$pub/NikkeSafetyCheck.exe" "$pub/SHA256SUMS.txt" --title "NIKKE PC 안전 점검 도우미 $tag (비공식)" --notes-file docs/RELEASE_NOTES.md
