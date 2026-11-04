**비공식 도구입니다. SHIFT UP, Level Infinite와 관련이 없습니다.** 알려진 지표와 비교한 결과이며 안전을 보장하지 않습니다.

## v0.2.0에서 달라진 점
**확인된 피해는 여전히 니케 PC 런처입니다.** 다른 게임의 피해 근거는 확인하지 못했지만, 안전하다고 볼 수도 없어 점검 범위를 넓혔습니다.
- 같은 구조(`intl_service`, `tbs_cache`)의 다른 런처 폴더를 같은 지표로 찾아봅니다. 게임 이름이나 설치 여부로 판정하지 않으며, 니케 외 폴더는 자동으로 정리하지 않습니다.
- 니케 HMT판 폴더(`nikke_launcher_hmt`)를 검사하고 정리합니다. 이전 버전은 이 폴더를 보지 않았습니다.
- 런처가 기록한 설치 경로를 더 읽고, 더 깊은 폴더까지 찾습니다.
- 런처 로그의 `insightjs` 언급, 접속 기록 파일의 공격 도메인, DLL 없는 64자리 해시 폴더를 의심으로 알립니다.

**v0.1.x로 '미발견'이 나온 HMT판 이용자나 설치 폴더를 찾지 못했던 분은 다시 점검하세요.**

## 사용법
`NikkeSafetyCheck.exe`를 받아 더블클릭하고 **지금 점검하기**를 누르세요. 점검은 PC를 바꾸지 않습니다. 니케 PC 런처는 열지 마세요. 자세한 내용은 [README](https://github.com/PerthroIne/nikke-pc-safety-check#readme)를 보세요.

## 받기 전에 확인
- 이 페이지에서만 받으세요. 재업로드 파일을 쓰지 마세요.
- `SHA256SUMS.txt`와 `Get-FileHash` 결과를 비교하세요.
- **코드 서명이 없습니다.** SmartScreen이나 백신이 경고할 수 있습니다. 보안 기능을 끄지 마세요.

## 검증 상태
GitHub Actions Windows Server 2025 x64 일회용 VM에서 무해한 가짜 파일로 자동 테스트했습니다. 실제 악성코드로 테스트하지 않았습니다. **일반 Windows 11 PC, 실제 UAC 창, 실제 니케 설치본, 니케 외 실제 런처에서는 검증하지 못했습니다.** 자세한 내용은 [테스트 결과](https://github.com/PerthroIne/nikke-pc-safety-check/blob/main/docs/TEST_RESULTS.md)를 보세요.

규칙 버전: 2026.11.04-3 (MotherSphere 보고서 2026-11-03 20:40 GMT 수정본과 점검 도구 문서, WormW 2026-11-04 공개본 기준)
