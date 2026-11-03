# NIKKE PC 안전 점검 도우미 (비공식)

니케 PC 런처 공급망 사고의 **알려진 흔적**을 내 PC에서 찾아 주고, 결과를 쉬운 말로 설명하며, 필요한 조치를 한 화면에서 고를 수 있게 돕는 Windows 프로그램입니다.

> **이 프로그램은 SHIFT UP, Level Infinite와 관련이 없는 커뮤니티 도구입니다.** 공개된 개인 분석을 바탕으로 만들었고, 운영사의 공식 확정 발표가 아닙니다. 결과는 안전을 보장하지 않습니다.

## 다운로드

**[⬇ NikkeSafetyCheck.exe 받기](https://github.com/PerthroIne/nikke-pc-safety-check/releases/latest/download/NikkeSafetyCheck.exe)** · [해시 파일](https://github.com/PerthroIne/nikke-pc-safety-check/releases/latest/download/SHA256SUMS.txt) · [모든 릴리스](https://github.com/PerthroIne/nikke-pc-safety-check/releases)

설치가 필요 없습니다. Windows 10/11 x64에서 더블클릭으로 실행합니다. 파일이 크고(약 70MB) 처음 뜨는 데 몇 초 걸릴 수 있습니다.

### 받은 파일이 진짜인지 확인하기

이 사고를 빌미로 가짜 "치료 프로그램"이 돌 수 있습니다. **이 저장소의 릴리스에서만 받으세요.** 재업로드된 파일은 쓰지 마세요. PowerShell(관리자 아님)에서 아래를 실행해 나온 값이 [릴리스 페이지](https://github.com/PerthroIne/nikke-pc-safety-check/releases/latest)의 `SHA256SUMS.txt`와 같은지 비교합니다.

```powershell
Get-FileHash "$HOME\Downloads\NikkeSafetyCheck.exe" -Algorithm SHA256
```

**코드 서명이 없습니다.** 그래서 Windows SmartScreen이나 백신이 경고할 수 있습니다. 보안 기능을 끄지 마세요. 해시가 같은지 확인한 뒤 실행 여부를 스스로 판단하거나, 믿기 어려우면 아래 "직접 빌드"를 쓰거나 다른 공개 점검 방법을 쓰세요. 이 저장소는 관리자 PowerShell에 명령을 붙여넣으라고 안내하지 않습니다.

## 3분 사용법

1. **니케 PC 런처는 열지 말고** 프로그램을 실행합니다. 관리자 권한으로 실행할 필요가 없습니다.
2. **지금 점검하기**를 누릅니다. 읽기만 하며 PC를 바꾸지 않고 인터넷도 쓰지 않습니다.
3. 결과 카드의 등급을 읽습니다(아래 표).
4. 필요하면 **권장 조치 실행**을 누릅니다. 실제 변경 목록을 먼저 보여 주고, 체크한 항목만 실행합니다.
5. 고위험이나 의심이면 **휴대전화 같은 다른 기기에서** **계정 보호 안내**를 따릅니다.
6. PC를 직접 재시작하고, 런처를 열지 말고, **다시 점검**합니다.

## 결과 읽는 법

| 표시 | 뜻 | 할 일 |
|---|---|---|
| ⛔ **고위험** | 공식 설치 위치의 실행 로그, 런처 저장소의 에이전트 상태, 알려진 악성 해시, DLL과 사용자 COM 결합 같은 강한 증거. 실제 유출이 끝났다는 증명은 아닙니다. | 권장 조치 실행, 다른 기기에서 계정 보호, Windows 재설치 검토 |
| ⚠ **의심** | 다운로드 기록, 캐시 주소, 단독 파일처럼 불충분한 흔적. 자동 제거 대상이 아닙니다. | 항목 읽기, 백신 전체 검사, 중요 계정 점검 |
| ⓘ **알려진 흔적 미발견** | 정의된 범위를 끝까지 봤지만 일치 없음. **감염 없음이 아닙니다.** 로그가 지워졌거나 변종이면 못 찾습니다. | 공식 공지 전까지 런처 사용 자제, 9월 27일 이후 실행했다면 2단계 인증 점검 |
| ❔ **점검 불완전** | 경로를 못 찾음, 권한, 잠금, 취소 등으로 충분히 못 봄. **'문제없음'이 아닙니다.** | 안내대로 폴더 선택이나 런처 종료 후 다시 점검 |

고위험과 "일부 미검사"는 동시에 표시될 수 있습니다. 다른 검사가 실패해도 찾은 증거의 등급을 낮추지 않습니다.

- **과거 흔적**: 로그, 저장소 기록. 그때 실행되었다는 뜻이고 지금 실행 중이라는 뜻은 아닙니다. 조치 후에도 고위험으로 남는 것이 정상입니다. 일부러 지우지 마세요.
- **현재 상태**: DLL, 레지스트리 등록, 메모리에 불러온 모듈. 지금 남아 있는 장치입니다.

자세한 설명은 [사용자 안내서](docs/USER_GUIDE.md), 판정 기준과 설계는 [설계 문서](docs/DESIGN.md)를 보세요.

## 점검 항목

| 항목 | 위치 | 비고 |
|---|---|---|
| 에이전트 실행 기록 | `<설치 위치>\Launcher\intl_service\debug.log` | 콘솔 로그 줄 형식일 때만 실행 증거로 인정 |
| 다운로드 기록 | `Launcher\log\tinyget\` | 의심 등급 |
| 에이전트 상태 | `%APPDATA%\nikke_launcher\tbs_cache\Local Storage\leveldb\` | `k2f.agent.state`는 고위험, 값은 읽어 기록하지 않음 |
| 로더 캐시 | `tbs_cache\Code Cache\js`, `Cache\Cache_Data` | 의심 등급 |
| 지속 실행 DLL | `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<64자리>\platform_experience_helper.dll` | 해시만 계산, 불러오지 않음 |
| 사용자 COM 등록 | `HKU\<SID>_Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32` | HKLM의 같은 CLSID는 정상 |
| 임시 파일 이름 | `%TEMP%\k2f-bcreds-*`, `k2f_screen_*` | 이름만 확인, 열지 않음 |
| 실행 중 모듈, 연결, DNS 캐시 | 선택 항목 | 보조 지표 |

## 하는 조치, 하지 않는 일

체크한 항목만 실행합니다. 실행 직전에 경로, SID, 값, 파일 ID, 해시를 다시 확인하고 다르면 그 항목을 멈춥니다.

- 사용자 COM 항목 삭제(변경 전 값 기록), 의심 DLL을 실행 불가 격리 폴더로 이동
- 런처 전용 캐시 정리(증거 먼저 복사, 치료가 아니라 재사용 방지)
- 알려진 IP 방화벽 차단, 알려진 도메인 hosts 차단, 검증된 런처 파일의 통신 차단(되돌리기 가능)
- Microsoft Defender 검사 시작(다른 백신을 쓰면 안내만)

**하지 않습니다:** 자동 재부팅, 브라우저 강제 종료, 게임 삭제, HKLM과 Windows 구성 변경, `PlatformExperienceHelper` 폴더 삭제, 비밀번호나 복구 문구 입력받기, 브라우저 비밀번호·쿠키·Claude 인증 파일·SSH 키 열기, DLL 실행, 외부 전송, 텔레메트리, 자동 업데이트, 악성 항목 복구.

'완치'라고 표시하지 않습니다. 에이전트가 실행되었다면 공격자가 임의 명령을 실행할 수 있었고, 그 기록은 로그에 남지 않습니다.

## 데이터 위치

`%LOCALAPPDATA%\NikkeSafetyCheck` 폴더에 조치 기록, 증거 복사본, 격리 파일을 둡니다. 현재 사용자만 접근하도록 제한합니다. 런처 저장소 복사본에는 로그인 정보가 있을 수 있으니 이 폴더를 공유하지 마세요. **공유는 '결과 저장'으로 만든 파일만** 쓰세요. 사용자 이름, PC 이름, SID, 경로 일부, 토큰을 가립니다. 프로그램을 지우려면 exe와 이 폴더를 지우면 됩니다. 추가한 차단은 먼저 '예방 설정 되돌리기'로 해제하세요.

## 지원 범위와 검증 상태

| 환경 | 상태 |
|---|---|
| Windows 11 x64 | 지원 대상. **실제 Windows 11 PC 검증 결과는 [테스트 결과](docs/TEST_RESULTS.md)를 확인하세요** |
| Windows 10 x64 | 동작 예상, 미검증. Windows 10은 2025년 10월 일반 지원이 끝났습니다 |
| Windows Server 2025 x64 | GitHub Actions 일회용 VM에서 자동 테스트 |
| ARM64 Windows, Linux, Steam Deck(Proton) | 지원 제외 |

## 근거

- [MotherSphere 공개 보고서](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5), [WormW 샘플 분석](https://github.com/WormW/nikke_malware_analysis), [whykusanagi 탐지·대응 키트](https://github.com/whykusanagi/nikke_malware)
- 모두 개인 분석입니다. [출처별 차이와 조사 한계](docs/SOURCES.md)를 함께 보세요. 2026-11-04 기준 공식 확정·복구 공지는 확인하지 못했습니다.
- 같은 사고를 다루는 다른 도구: [whykusanagi/nikke_malware](https://github.com/whykusanagi/nikke_malware)(PowerShell), [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner)(읽기 전용). 이 저장소가 품질을 보증하지는 않습니다.

## 직접 빌드

깨끗한 Windows 개발 환경에서 [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)를 설치한 뒤:

```powershell
./scripts/build.ps1                                   # artifacts/publish 에 exe와 해시 생성
dotnet run -c Release --project tests/NikkeSafetyCheck.Tests   # 회귀 테스트
```

`tests/NikkeSafetyCheck.WinTests`는 방화벽과 hosts를 실제로 건드리므로 **일회용 VM에서만** 실행하세요. 감염이 의심되는 PC에서 개발 도구를 실행하지 마세요. 외부 NuGet 패키지를 쓰지 않습니다. 실행 파일에는 Microsoft .NET 런타임과 WPF가 포함됩니다.

## 오탐과 새로운 정보 알리기

[Issues](https://github.com/PerthroIne/nikke-pc-safety-check/issues)에 남겨 주세요. **로그 원문, 사용자 이름, 토큰, DLL 파일을 올리지 마세요.** '결과 저장'으로 만든 파일을 읽어 본 뒤 필요한 부분만 공유하세요.

새 지표는 `src/NikkeSafetyCheck.Core/Data/iocs.json`에 선언적으로 반영하고 새 버전으로 배포합니다. 자동 업데이트는 없습니다.

[MIT License](LICENSE)
