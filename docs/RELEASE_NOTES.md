**비공식 도구입니다. SHIFT UP, Level Infinite와 관련이 없습니다.** 알려진 지표와 비교한 결과이며 안전을 보장하지 않습니다.

## v0.1.1에서 달라진 점
공지 경로를 직접 확인한 이용자가 항목이 왜 안 보이는지 알 수 없다는 제보를 반영했습니다. 점검 판정 규칙은 바뀌지 않았습니다.
- 다시 점검하면 이 PC에서 이전에 실행한 조치 내역을 보여 줍니다. 이 기능은 v0.1.1로 실행한 조치부터 기록합니다.
- 조치 실행 전에 공지 경로에서 어떤 항목이 사라지는지 알려 줍니다.
- 조치 결과 화면에 수동 확인 방법과 기록 폴더 위치를 안내합니다.

## 사용법
`NikkeSafetyCheck.exe`를 받아 더블클릭하고 **지금 점검하기**를 누르세요. 점검은 PC를 바꾸지 않습니다. 니케 PC 런처는 열지 마세요. 자세한 내용은 [README](https://github.com/PerthroIne/nikke-pc-safety-check#readme)를 보세요.

## 받기 전에 확인
- 이 페이지에서만 받으세요. 재업로드 파일을 쓰지 마세요.
- `SHA256SUMS.txt`와 `Get-FileHash` 결과를 비교하세요.
- **코드 서명이 없습니다.** SmartScreen이나 백신이 경고할 수 있습니다. 보안 기능을 끄지 마세요.

## 검증 상태
GitHub Actions Windows Server 2025 x64 일회용 VM에서 무해한 가짜 파일로 자동 테스트했습니다. 실제 악성코드로 테스트하지 않았습니다. **일반 Windows 11 PC와 실제 UAC 창, 실제 니케 설치본에서는 검증하지 못했습니다.** 자세한 내용은 [테스트 결과](https://github.com/PerthroIne/nikke-pc-safety-check/blob/main/docs/TEST_RESULTS.md)를 보세요.

규칙 버전: 2026.11.04-2 (MotherSphere 2026-11-03 20:40 GMT 수정본 기준, WormW 2026-11-04 공개본)
