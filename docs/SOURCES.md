# 출처, 변경점, 조사 한계

조사 시점: 2026-11-04 약 06:30 KST. 모두 개인 분석이며 운영사 발표가 아닙니다.

## 읽은 자료

| 자료 | 상태 | 비고 |
|---|---|---|
| [A. MotherSphere 보고서](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5) | 읽음 | 가져온 사본은 19:10 GMT 본문이었고, 검색 결과로 20:40 GMT 수정본(변조 파일 4개, 3개 교체, FeedList 잔존)의 요지를 확인. **20:40 본문 전체를 직접 읽지는 못함** |
| [B. WormW 분석](https://github.com/WormW/nikke_malware_analysis) | 읽음 | 저장소 복제. 최신 커밋 2026-11-04 03:26 +08:00 |
| [whykusanagi 키트](https://github.com/whykusanagi/nikke_malware) | 읽음 | 프롬프트에 없던 자료. 커밋 1개, 독립 검증 없음. 스크립트는 읽기만 하고 실행 안 함 |
| [Sheisback 스캐너](https://github.com/Sheisback/nikke_malware_scanner) | 일부 읽음 | 경로 탐색 참고. 실행 안 함 |
| [C. 공식 공지(한국](https://nikke-kr.com/news.html), [글로벌)](https://nikke-en.com/news.html) | **못 읽음** | 이 환경에서 페이지 접근 불가. 검색으로도 사고 공지를 찾지 못함. 공지가 없다는 뜻은 아님 |
| [D. 영어 영상](https://youtu.be/sfB9tlsKRII) | **못 읽음** | 프롬프트의 화면 분석 요약만 사용. 음성 미확인 |
| [E. 한국어 영상](https://youtu.be/9T7amEtFiZ0) | **검증 대기** | 본문, 자막 확보 실패. 이 자료에서 어떤 주장도 가져오지 않음 |
| nikke.gg 안내, 아카라이브 글 | 검색 요약만 | 본문 접근 실패. 구현 근거로 쓰지 않음 |
| Microsoft 문서 | 재확인 못 함 | `Start-MpScan`, `Start-MpWDOScan` 등 잘 알려진 사용법을 사용. Windows 테스트로 호출 확인 |

## 프롬프트 작성 이후 달라졌거나 추가된 점

| 내용 | 출처 | 반영 |
|---|---|---|
| 변조 파일에 `vue-bucket.min.js` 포함, 시작 시점 2026-09-27 06:41 GMT | A | 안내문 |
| 로그 지표 추가: `agent started as`, `adopted`, `resuming`, `lua downloaded to log\tinyget\`, 소스 빈 `startup already in progress` | A, whykusanagi | 규칙 |
| 저장소 지표는 정확히 `k2f.agent.state`, 출처 `nikkelauncher.com` | A, B | 규칙 |
| 로더 캐시 `Code Cache\js`의 `insightjs.com/l.js` | A | 규칙 |
| 임시 파일 `k2f-bcreds-*`, `k2f_screen_*` | A, B | 규칙(이름만) |
| 다른 DLL 해시 `350e262b…` 보고 | A 코멘트 | 알려진 해시로 추가, 보고 수준 표시 |
| DLL은 **피해자별로 다르고** 폴더 이름이 자기 SHA-256 | whykusanagi, NGA 요약 | 구조 규칙 추가, 해시 불일치를 정상 근거로 쓰지 않음 |
| 추가 IP `89.126.250.172` | A 코멘트(미검증) | 조회만, 차단 제외 |
| `www.insightjs.com` | whykusanagi | hosts 차단 추가 |
| `insightjs.org`는 제3자 경고 페이지가 됨 | A, B | 차단은 유지(A 권고), 접속 금지 |
| 수집 범위: 브라우저 6종, AI·개발 도구 약 1,790개 경로, 지갑 28종, 19개 원격 명령 | A, B | 계정 안내 |
| 공격 서버 `89.127.233.127`이 11-03 18:31 GMT부터 응답 없음 | A | 그래도 차단 유지. 지표가 바뀔 수 있음 |

## 자료 간 불일치와 판단

| 쟁점 | 내용 | 판단 |
|---|---|---|
| 변조 파일 수 | 수정 전 3개, A 수정본 4개, B와 whykusanagi README는 2~3개 | 수정본 4개로 안내하되 탐지에는 쓰지 않음 |
| 실행 시작일 | 초기 11-01, A 코멘트 10-24 | "늦어도 10월 24일 보고"로 표기, 로그는 날짜로 거르지 않음 |
| 다른 브라우저 DLL | whykusanagi는 Edge/Brave 등 언급, A는 Chrome 전용이고 Brave PC에는 DLL 없음, 영상 안내 작성자는 경로 모름 | 동일 지속성으로 구현하지 않음. 같은 구조 파일은 의심으로만 알리고 COM 연결이 있을 때만 고위험 |
| tinyget 다운로드 | whykusanagi는 INFECTED, 프롬프트는 일반 다운로드 흔적 | 실행 증거가 아니므로 의심. 문구로 강하게 경고 |
| `k2f.agent` 캐시 문자열 | 프롬프트는 의심 예시, A와 B는 에이전트 상태 키이고 계정에서 실행된 증거 | **`k2f.agent.state`는 고위험, `k2f.agent` 단독은 의심**. 프롬프트와 다른 판단. 런처 저장소에 다른 경로로 들어갈 가능성이 낮기 때문 |
| 공식 입장 | 커뮤니티 글은 교체 사실을 근거로 조치됐다고 보기도 함 | 교체는 관찰 사실일 뿐 공식 복구 공지가 아니라고 안내 |

## 사용하지 않은 것

영상과 커뮤니티 글의 이용자 이름, 연락처, 로그 원문. 악성 샘플. 공격 서버 접속. 운영사 로고나 게임 이미지.
