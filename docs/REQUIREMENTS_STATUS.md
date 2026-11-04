# 요구사항 구현 현황

최종 통합 프롬프트 기준입니다. **반영됨** = 처음부터 구현, **수정함** = 검토나 후속 요구로 고침, **미구현** = 없음, **검증 불가** = 구현했지만 실제 환경에서 확인 못 함. 테스트 번호는 [테스트 결과](TEST_RESULTS.md)를 보세요.

| 요구사항 | 상태 | 코드 | 근거 |
|---|---|---|---|
| 비공식 표시, 운영사 브랜딩 없음 | 반영됨 | `UI/MainWindow.cs` | 화면 |
| Windows x64 단일 EXE, SDK 불필요 | 반영됨 | `App/*.csproj`, `scripts/build.ps1` | W12 |
| Windows 11 데스크톱 동작 | 검증 불가 | | Server 2025만 실행 |
| ARM64 안내, Linux/Proton 제외 | 반영됨 | `App/Program.cs` | ARM64 실행은 검증 불가 |
| 일반 권한 읽기 전용, 관리자 취소 후 계속 | 반영됨 | `app.manifest`, `ElevatedRunner` | W02b. 실제 UAC 취소는 검증 불가 |
| 첫 화면과 결과 화면 4개 버튼 | 반영됨 | `MainWindow.cs` | W11, W12 |
| 자동 재부팅, 강제 종료, 게임 삭제 없음 | 반영됨 | 해당 코드 없음 | 코드 검토 |
| 결과 공통 필드 | 반영됨 | `Core/Models.cs` `Finding` | 12 |
| 위험도와 완료 여부 분리 | 반영됨 | `Verdict` | 06b |
| 증거 단계 분리 | 수정함 | `EvidenceStage`, `ScanEngine.cs` | 29, 32 |
| 설치 위치 탐색, 실행하지 않음 | 수정함 | `InstallLocator.cs`, `WindowsInstallHints` | 08, 14. 실제 니케 설치본은 검증 불가 |
| 폴더 선택, 드래그앤드롭, 수동 로그 | 반영됨 | `MainWindow.cs`, `ScanManual` | 05c. 화면 조작은 검증 불가 |
| 로그 스트리밍, 인코딩, 잠금 | 반영됨 | `LogScanner.cs` | 06e, 08b |
| 인용문을 실행 증거로 승격 금지 | 반영됨 | `LogScanner.Classify` | 05b |
| 요청과 다운로드 성공 구분 | 수정함 | `ScanTinyget` | 29 |
| LevelDB 내부 검색, 값 제외 | 수정함 | `BinaryScanner`, `ScanLocalStorage` | 05d, 30 |
| DLL 해시만 계산, 로드 금지 | 반영됨 | `Sha256File`, `WindowsSignatureChecker` | W05 |
| 정상 EXE, 부모 폴더로 판정 금지 | 반영됨 | `EvaluatePersistence` | 01 |
| SID 기준 검사, 실제 하이브 | 반영됨 | `TargetUserResolver`, `ReadComEntries` | 07, W02 |
| 다른 사용자 범위 선택 검사 | 미구현 | | 현재 사용자만. 프롬프트상 선택 기능 |
| 프로세스 모듈, 연결, DNS 보조 지표 | 수정함 | `ScanModules`, `ScanNetwork`, `ScanDns` | 13, 19, 32 |
| 비밀 저장소 열지 않음 | 반영됨 | 해당 코드 없음 | 코드 검토. 단 조치 시 런처 LevelDB를 증거로 복사 |
| 4가지 상태와 판정 등급 | 수정함 | `Verdict` | 01~06, 22~25 |
| 불변 계획, DryRun, 직전 재확인 | 반영됨 | `Remediation.cs` | 03, 09, 09d |
| reparse, UNC, `..` 거부 | 반영됨 | `PathSafety.cs` | 09, 09b, 14, W04 |
| 관리자 보조 허용 목록 | 수정함 | `ElevatedHelper` | W07, W08, W12 |
| 방화벽, hosts, 런처 차단, 복구 | 수정함 | `NetworkBlock.cs`, `HostsEditor.cs` | 10, W09, W12. 런처 차단 실제 적용은 검증 불가 |
| 방화벽 꺼짐, 정책 시 실패 표시 | 반영됨 | `EffectiveProblem` | 검증 불가 |
| 사용자 COM 제거, DLL 격리 | 수정함 | `RemoveCom`, `QuarantineDll` | 03, 09c, 27, W02 |
| 잠금 시 재부팅 후 처리 | 수정함 | `Journal`, `QuarantineDll` | 11, 28. 실제 재부팅은 검증 불가 |
| 지정 프로세스를 골라 종료하는 기능 | 미구현 | | 어떤 프로세스도 종료하지 않고 재부팅을 안내 |
| 캐시 정리, 증거 먼저 보존 | 반영됨 | `ClearCache`, `PreserveLogs` | 11b, W02 |
| Defender 연결, 타사 백신 안내 | 반영됨 | `WindowsDefenderService` | 13, W10, W12(시작). 완료, 오프라인, 타사 백신은 검증 불가 |
| 저널, 부분 실패 분리 | 수정함 | `Journal`, `ExecuteAsync` | 11 |
| 관련 런처 구조 기반 점검, 조치 제외 (v0.2.0, 사용자 요청) | 수정함 | `InstallLocator`, `DiscoverOtherCacheDirs`, `MarkOther` | 35~38, 40~42. 실제 다른 런처는 검증 불가 |
| HMT판, 런처 기록 경로, 빈 해시 폴더, 접속 기록 (v0.2.0) | 수정함 | `NikkeCacheDirs`, `WindowsInstallHints`, `ScanOneCache` | 37, 39 |
| 조치 내역 표시, 수동 확인 안내 (v0.1.1, 이용자 피드백) | 수정함 | `HistoryStore.LoadActions`, `Guidance.ManualCheckNote`, `PastActionsCard` | 33, 34, W12 |
| 악성 항목 복구 없음, .reg 없음 | 반영됨 | 해당 코드 없음 | 코드 검토 |
| 계정 보호 안내 | 반영됨 | `Guidance.cs` | 화면 |
| 보고서 마스킹, HTML 이스케이프 | 수정함 | `Report.cs` | 12, 26, 30 |
| 텔레메트리, 자동 전송, IOC 접속 없음 | 반영됨 | 네트워크 전송 코드 없음 | 코드 검토 |
| 선언적 IOC, 스키마 검증 | 수정함 | `IocData.cs`, `Data/iocs.json` | 14, 15 |
| 출처 등급, 수정 시각과 규칙 버전 표시 | 수정함 | `SourceRevision`, [SOURCES.md](SOURCES.md) | 화면, 보고서 |
| 다른 게임 주장, onominan, 원인 미확인 | 수정함 | `CauseNote` | 31, 32 |
| 영상 D, E와 자료 F, G 직접 확인 | 검증 불가 | | 접근 실패. [SOURCES.md](SOURCES.md) |
| 소스, 빌드, SHA-256, 변경 기록 공개 | 반영됨 | `scripts/`, `.github/` | CI. 코드 서명은 **없음** |
| Windows VM 검증 | 수정함 | `tests/NikkeSafetyCheck.WinTests` | Actions |
