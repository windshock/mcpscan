# MCP 기반 AI 공급망 취약점과 `mcp-guard` 운영 가이드

이 문서는 다음 질문에 답하기 위해 작성되었다.

- MCP 기반 AI 도구가 왜 공급망 관점의 보안 리스크가 되는가
- 실제 운영에서 어떤 형태로 노출과 실행이 이어지는가
- 이 저장소의 `mcp-guard`와 테스트 랩으로 무엇을 검증할 수 있는가
- 실무자가 지금 바로 어떤 순서로 점검하면 되는가

## 1. 핵심 요약

MCP(Model Context Protocol)는 AI와 외부 시스템을 연결하는 표준이지만, 보안 관점에서는 단순 API 연동이 아니라 "외부 입력이 내부 실행 경로에 연결되는 구조"로 봐야 한다.

위험의 본질은 아래 한 줄로 정리된다.

`신뢰할 수 없는 입력 -> MCP 설정/도구 호출 -> 로컬 또는 서버 실행`

이 구조가 성립하면 다음이 가능해진다.

- 명령 실행
- 로컬 파일 읽기/쓰기
- 내부 서비스 접근
- 비밀정보 노출
- AI가 추천한 설정을 사용자가 승인하면서 발생하는 zero-click 또는 near-zero-click 실행

## 2. 왜 기존 취약점과 결이 다른가

| 구분 | 전통적 취약점 | MCP/AI 실행 경로 리스크 |
| --- | --- | --- |
| 출발점 | 코드 버그 | 설계 및 운영 경로 |
| 위험 경계 | 입력 검증 실패 | 입력이 실행 설정으로 승격 |
| 사용자 인식 | "명령 실행"이라고 인식 | "설정 변경" 또는 "연결 추가"로 오인 |
| 운영 확장 | 단일 앱 내부 | IDE, Agent, Tunnel, Connector 전체로 확장 |

즉 MCP는 기능 추가 수단이 아니라, 잘못 연결되면 실행 경로 자체가 공격면이 된다.

## 3. 자주 나오는 공격 경로

### 3.1 설정 기반 실행

가장 대표적인 패턴은 `mcpServers.command`, `args`, `transport`가 외부 입력 또는 사용자 승인 흐름과 연결되는 경우다.

- 악성 README나 블로그 글에서 MCP 설정 복사
- UI에서 MCP 서버 추가 시 command/args를 그대로 반영
- 에이전트가 설정 파일 변경을 제안하고 사용자가 승인

결과적으로 설정 데이터가 subprocess 실행으로 이어질 수 있다.

### 3.2 숨은 백엔드 경로

겉으로는 안전한 tool 목록만 보여도, 실제 서버에는 다음과 같은 숨은 관리 경로가 있을 수 있다.

- `/api/transport`
- `/api/config`
- `/api/connectors`
- 숨겨진 stdio transport 등록 API

이 경우 UI에 보이는 도구만 보고는 안전 여부를 판단할 수 없다.

### 3.3 외부 노출 확장

로컬 개발 서버라도 아래 조합이 붙으면 공격면이 외부로 확장된다.

- ngrok
- Cloudflare Tunnel
- 외부 HTTPS reverse proxy
- Docker published port

개발 편의를 위한 공개가 실제 공격 가능한 자산으로 바뀌는 지점이다.

### 3.4 AI-mediated 변경

프롬프트 인젝션과 MCP 리스크가 만나는 지점이다.

- 원격 문서나 저장소를 읽은 AI가 설정 변경을 제안
- 사용자는 "추천 설정"으로 받아들여 승인
- 결과적으로 외부 입력이 로컬 실행 설정으로 승격

이 경우 공격자는 직접 명령을 치지 않아도 된다.

## 4. 운영 관점에서 특히 위험한 환경

아래 환경은 우선 점검 대상이다.

- Cursor, Windsurf, Claude, Copilot 같은 AI IDE
- LangChain, LiteLLM, Flowise, LangFlow 같은 AI orchestration 계열
- 내부 Agent 플랫폼과 Connector UI
- 로컬 개발용 MCP 서버
- Docker로 띄운 MCP 서버
- Tunnel로 공개한 테스트 서버

## 5. 이 저장소가 하는 일

이 저장소는 두 가지 역할을 가진다.

### 5.1 MCP 보안 랩

취약한 MCP 서버와 정상 서버를 함께 두고, 탐지기의 true positive / false positive / false negative를 비교한다.

- 정상 서버 3종
- 취약 서버 8종
- 노출 시뮬레이션 3종

대표 패턴은 다음을 포함한다.

- direct command execution
- authless endpoint
- unrestricted file read/write
- secret exposure
- SSRF
- allowlist bypass
- hidden transport
- config-to-execution
- AI-mediated config injection

### 5.2 `mcp-guard`

`mcp-guard`는 MCP 서버 코드, MCP config, live endpoint를 검사해서 정책 verdict를 내리는 guardrail CLI다.

기본 verdict는 아래 세 단계다.

- `ALLOW`: 즉시 사용 가능
- `CONDITIONAL`: 제한 조건 하에 허용
- `BLOCK`: 사용 금지 또는 수정 필요

## 6. `mcp-guard`가 지금 지원하는 스캔 모드

### 6.1 명시적 스캔

사용자가 대상을 직접 지정하는 방식이다.

```bash
mcp-guard scan --path ./servers/vuln-exec
mcp-guard scan --config ./mcp.json
mcp-guard scan --endpoint http://127.0.0.1:3101/sse
```

### 6.2 자동 discovery 기반 스캔

macOS에서는 사용자가 폴더나 포트를 직접 지정하지 않아도 후보를 찾아준다.

```bash
mcp-guard discover
mcp-guard discover --output json
mcp-guard scan
mcp-guard scan --auto
```

자동 discovery는 아래 신호를 조합한다.

- `lsof`, `ps` 기반 host process / open port 탐지
- Docker container, published port, bind mount, Compose metadata 탐지
- localhost endpoint probing
- ngrok public URL 추적
- cloudflared public URL 추적

### 6.3 자동 선택의 현재 원칙

`scan --auto`는 아무 서비스나 선택하지 않는다.

자동 선택 대상은 "강한 MCP 신호"가 있는 후보로 제한된다.

예시:

- MCP tool list 획득 성공
- `fastmcp`, `modelcontextprotocol`, `mcp.tool` 같은 코드 흔적
- `mcp.json` 같은 설정 파일
- command line 또는 metadata에서 MCP가 명확하게 드러나는 경우

즉 일반 웹 서비스나 단순 Docker 컨테이너는 discovery 목록에는 보일 수 있어도, 기본적으로 `--auto` 대상에서는 제외된다.

## 7. Docker / Tunnel 환경에서 무엇이 달라졌나

기존에는 사용자가 수동으로 포트나 폴더를 입력해야 했다. 지금은 아래가 가능하다.

### 7.1 Docker

- published port가 있으면 endpoint 후보로 등록
- bind mount나 Compose build context가 있으면 host path 후보로 등록
- 컨테이너 이름, 서비스명, 이미지명, host path를 함께 보여줌

### 7.2 ngrok / Cloudflare Tunnel

- 로컬 public tunnel URL을 찾는다
- 해당 URL이 어떤 localhost upstream에 연결되는지 매핑한다
- public URL은 메타데이터로 보여주고, 실제 스캔은 가능한 한 로컬 upstream을 우선 사용한다

이렇게 하면 "외부에 공개된 테스트 MCP"와 "실제 로컬 실행 대상"을 같이 볼 수 있다.

## 8. 검증 데이터는 어떻게 보강했나

이 저장소의 검증은 두 층으로 구성된다.

### 8.1 랩 서버 회귀 테스트

저장소 안의 정상/취약 샘플 서버를 계속 스캔해 회귀를 확인한다.

### 8.2 공개 연구 기반 fixture

`guard/tests/fixtures/ox_research_cases.json`에는 OX Security가 공개한 MCP 관련 연구에서 문제로 지적된 제품군 이름과 공격 payload shape를 반영한 회귀 케이스가 들어 있다.

중요한 점은 이 fixture가 각 제품 원본 코드를 vendor한 것은 아니라는 점이다.

이 fixture의 목적은 다음과 같다.

- 공개 연구에서 반복적으로 나타난 위험 패턴을 regression test로 고정
- config-to-execution, allowlist-bypass 같은 핵심 패턴이 다시 놓치지 않도록 보장
- 제품별 마케팅 문구가 아니라 "공격 구조" 기준으로 재현

## 9. 독자 관점에서 이 도구를 어떻게 써야 하나

실무에서는 아래 순서를 권장한다.

1. `mcp-guard discover`로 현재 Mac에서 의심 후보를 본다.
2. Docker, ngrok, cloudflared가 보이면 public URL과 local upstream을 같이 확인한다.
3. 자동 선택이 가능하면 `mcp-guard scan --auto`를 사용한다.
4. 자동 선택이 불가능하면 discovery 결과를 보고 `--path`, `--config`, `--endpoint`로 명시 지정한다.
5. `BLOCK`이 나오면 즉시 원인 패턴과 recommendation을 확인한다.

## 10. 바로 점검해야 할 체크리스트

- 외부에서 접근 가능한 MCP endpoint가 있는가
- Docker published port로 MCP 서버가 노출되어 있는가
- ngrok / Cloudflare Tunnel이 localhost MCP를 외부에 공개하고 있는가
- `mcp.json` 또는 MCP config에서 `command`, `args`, `env`가 위험하게 구성되어 있는가
- tool description 안에 숨은 instruction이나 prompt poisoning 문자열이 있는가
- localhost 서비스가 인증 없이 중요한 기능을 수행하는가
- 설정 변경이 AI 추천 또는 반자동 승인 흐름과 연결되어 있는가

## 11. 이 도구가 보장하지 않는 것

이 도구는 유용하지만 만능은 아니다.

- runtime-only backdoor는 정적 스캔만으로 놓칠 수 있다
- 인증이 필요한 private endpoint는 endpoint probe만으로 분석이 제한될 수 있다
- 일반 웹 서비스와 MCP 비슷한 포트가 함께 뜬 환경에서는 discovery 결과를 사람이 한 번 검토해야 한다
- 공개 연구 fixture는 "공격 구조 회귀"를 위한 것이지, 각 상용 제품의 최신 취약 상태를 실시간 보장하지 않는다

## 12. 결론

MCP 보안의 핵심은 "어떤 도구를 쓰느냐"보다 "입력이 실행으로 승격되는 경로를 어디까지 허용하느냐"에 있다.

`mcp-guard`의 discovery, Docker, tunnel 추적 기능은 이 경로를 더 빨리 찾기 위한 장치다.  
실제 운영에서는 다음 질문 하나로 판단하면 된다.

> 외부 입력이 설정 또는 도구 호출을 거쳐 내부 실행으로 이어질 수 있는가?

답이 `YES`라면, 그 순간 이미 고위험 구간에 들어와 있다.
