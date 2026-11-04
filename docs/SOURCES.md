# 출처, 변경점, 조사 한계

최초 조사 2026-11-04 약 06:30 KST, 범위 재조사 약 12:30 KST. 모두 개인 분석이며 운영사 발표가 아닙니다.

## 범위 재조사 (v0.2.0)

"레벨 인피니트의 모든 PC 게임에 같은 공작이 들어갔다"는 주장을 확인했지만 **근거를 찾지 못했습니다.** 그래서 확정 사실로 쓰지 않고, 게임 목록 없이 같은 구조의 폴더를 같은 지표로 찾는 방식으로 넓혔습니다.

| 자료 | 내용 | 상태 |
|---|---|---|
| [인벤](https://www.inven.co.kr/webzine/news/?news=322963) (11-04 12:19) | 확인된 피해는 니케뿐. 변조 파일 4개 중 2개는 공용 폴더. 접근 범위 미지수. 에이전트는 니케 런처에 맞춘 흔적 | 읽음 |
| [MTN](https://news.mtn.co.kr/article/2026110410574629035) (11-04 11:00) | 다른 게임 점검 필요성 제기. 게임루프 동일 피해 정황은 미확인 | 읽음 |
| [AUTOMATON](https://automaton-media.com/en/news/goddess-of-victory-nikke-pc-launcher-reportedly-compromised-in-supply-chain-attack-no-official-confirmation-from-developers-yet/) (11-04 10:18) | 공식 확인 없음 | 읽음 |
| [MotherSphere 점검 도구](https://github.com/MotherSphere/NIKKE-Launcher-Check) | HMT 폴더, 설치 경로 기록 위치, 빈 해시 폴더, 접속 기록 파일, 10월 23일 시점 | 문서와 코드 일부 읽음. GPL이라 코드를 복사하지 않고 사실만 참고 |
| ResetEra 스레드 | 다른 게임 "확인" 주장 | **못 읽음.** 검색 요약만 봄. 근거로 쓰지 않음 |
| Grok의 X 답변 | 다른 타이틀 '가능성' 언급 | AI 답변이라 근거로 쓰지 않음 |
| 공식 공지 | | **여전히 직접 못 읽음** |

## 출처 등급

| 등급 | 자료 | 독립성 |
|---|---|---|
| 공식 발표 | 확인하지 못함 | |
| 직접 분석 | A MotherSphere(감염 PC 1대와 다른 피해자 제보), B WormW(샘플 기능 분석) | **서로 독립적인 사건 전체 검증이 아닙니다.** B는 과거 CDN 변조 상태를 재현하지 않았고 전달 경로 앞부분은 A를 인용합니다 |
| 제보 | A의 코멘트(추가 해시, IP, 10월 24일 사례) | 미검증 표시 유지 |
| 2차 요약 | F 디시인사이드 총정리, nikke.gg, 커뮤니티 공지, whykusanagi의 사고 설명 부분 | 주로 A를 인용하므로 독립 검증 건수에 넣지 않습니다. whykusanagi의 DLL 구조 관찰은 자체 관찰로 표시되어 있으나 독립 검증되지 않았습니다 |
| 미확인 추측 | G 4chan 게시글의 다른 게임 목록 | 게임별 증거 없음 |

과거 조사자가 확인했다고 프롬프트에 적은 사실과, 이번 작업에서 직접 확인한 사실은 아래 표의 '상태'로 구분합니다. 적용한 출처 시각과 규칙 버전은 화면과 보고서에 표시합니다.

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
| [F. 디시인사이드 총정리](https://m.dcinside.com/board/gov/6439046) | **못 읽음** | 접근 불가. 프롬프트에 적힌 조사자 대조 내용만 반영 |
| [G. 4chan 게시글](https://boards.4chan.org/vg/thread/586619615/nikg-nikke-general-5408#p586627539) | **못 읽음** | 접근 불가. 프롬프트에 적힌 조사자 설명만 반영 |
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
| 추가 IP `89.126.250.172` | A 코멘트, 도구 문서(피해자 보고) | 조회만, 차단 제외. 지금 다른 용도일 수 있음 |
| `www.insightjs.com` | whykusanagi | hosts 차단 추가 |
| `insightjs.org`는 제3자 경고 페이지가 됨 | A, B | 차단은 유지(A 권고), 접속 금지 |
| 수집 범위: 브라우저 6종, AI·개발 도구 약 1,790개 경로, 지갑 28종, 19개 원격 명령 | A, B | 계정 안내 |
| 공격 서버 `89.127.233.127`이 11-03 18:31 GMT부터 응답 없음 | A | 그래도 차단 유지. 지표가 바뀔 수 있음 |

## 자료 간 불일치와 판단

| 쟁점 | 내용 | 판단 |
|---|---|---|
| 변조 파일 수 | 수정 전 3개, A 수정본 4개, B와 whykusanagi README는 2~3개 | 수정본 4개로 안내하되 탐지에는 쓰지 않음 |
| 실행 시작일 | 초기 11-01, A 코멘트 10-24, MotherSphere 도구 문서 10-23 | "늦어도 10월 23일 보고"로 표기, 로그는 날짜로 거르지 않음 |
| 다른 브라우저 DLL | whykusanagi는 Edge/Brave 등 언급, A는 Chrome 전용이고 Brave PC에는 DLL 없음, 영상 안내 작성자는 경로 모름 | 동일 지속성으로 구현하지 않음. 같은 구조 파일은 의심으로만 알리고 COM 연결이 있을 때만 고위험 |
| tinyget 다운로드 | whykusanagi는 INFECTED, 프롬프트는 일반 다운로드 흔적 | 실행 증거가 아니므로 의심. 문구로 강하게 경고 |
| `k2f.agent` 캐시 문자열 | 프롬프트는 의심 예시, A와 B는 에이전트 상태 키이고 계정에서 실행된 증거 | **`k2f.agent.state`는 고위험, `k2f.agent` 단독은 의심**. 프롬프트와 다른 판단. 런처 저장소에 다른 경로로 들어갈 가능성이 낮기 때문 |
| 공식 입장 | 커뮤니티 글은 교체 사실을 근거로 조치됐다고 보기도 함 | 교체는 관찰 사실일 뿐 공식 복구 공지가 아니라고 안내 |

## F와 G에서 반영한 주의점

| 주장 | 이 프로그램의 처리 |
|---|---|
| 특정 날짜 이후 실행자는 전부 감염 | 쓰지 않습니다. 실행 이력은 점검이 필요한 이유일 뿐이고 판정은 증거로 합니다. 날짜로 판정하지 않습니다 |
| `k2f.agent`라는 파일을 찾으면 된다 | 파일 이름을 찾지 않습니다. LevelDB 파일 내부 바이트를 제한적으로 검색하고 값은 저장하지 않습니다 |
| 수집 대상이면 유출 완료 | 수집 기능과 실제 유출을 구분합니다 |
| 서버가 멈췄으니 끝났다 | 공격 종료나 복구의 증명으로 쓰지 않습니다 |
| `insightjs.org`는 악성 또는 안전 | 공격 당시의 대체 도메인과 조사 시점의 제3자 경고 페이지를 구분해 설명합니다. 예방 차단은 선택이고 접속해 확인하지 않습니다 |
| PUBG MOBILE, Delta Force, Honor of Kings, Arena Breakout, Dune: Awakening, Age of Empires Mobile, Undawn 피해 | 확정 목록으로 쓰지 않습니다. 설치만으로 판정, 삭제, 차단하지 않습니다. 안전 보장도, 가짜 확정도 아닙니다 |
| 같은 유통사, SDK, CDN | 조사 단서일 뿐입니다. 공통 흔적을 찾아도 원인이 없으면 '감염 원인 미확인'으로 표시합니다 |
| 모바일로 확대 | Windows PC 런처 사건을 Android, iOS 감염으로 확대하지 않습니다 |
| `onominan.tmp` | 초기 설명이 철회되어 탐지와 삭제 조건에서 뺐습니다 |

## 사용하지 않은 것

영상과 커뮤니티 글의 이용자 이름, 연락처, 로그 원문. 악성 샘플. 공격 서버 접속. 운영사 로고나 게임 이미지.
