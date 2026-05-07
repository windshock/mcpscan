# LinkedIn post copy

## 옵션 A — 기술 중심 (한국어)

🛡️ **mcp-guard** — MCP 서버 보안 점검을 한 줄 명령으로

대규모 언어 모델이 외부 도구를 호출하는 MCP(Model Context Protocol) 생태계가 빠르게 커지면서, "이 MCP 서버 안전한가?"를 코드 푸시 전에 검사할 도구가 필요해졌습니다.

mcp-guard는 두 가지 위협 모델을 한 명령으로 다룹니다:

🔍 **능력 기반 취약점** (개발자 본인의 MCP 감사)
- 인증 미강제, 무제한 파일/환경 접근, allowlist 우회, hidden admin 엔드포인트, 런타임 트리거

🚨 **악성 의도 검출** (공급망 검수, optional `--with-cisco`)
- Cisco mcp-scanner의 yara/behavioral/llm 분석기와 통합

✨ v0.2.0 신규
- `--auto` / `--auto-all`: host에서 떠있는 MCP 자동 탐지
- `Target details` 블록: 듣고 있는 PID, Docker 컨테이너, compose service까지 한눈에
- `-v`/`-vv` verbose: 검출 억제 결정까지 표시 (예: "suppressing command_exec: runtime-only family fired")

랩 벤치마크: 11 vulnerable MCP 서버에 대해 24/24 (100% recall, 100% precision).

```
pip install https://github.com/windshock/mcpscan/releases/download/v0.2.0/mcp_guard-0.2.0-py3-none-any.whl
docker pull ghcr.io/windshock/mcp-guard:0.2.0
```

🔗 https://github.com/windshock/mcpscan

#MCP #AISecurity #SupplyChainSecurity #DevSecOps #OpenSource

---

## 옵션 B — 짧고 캐주얼 (한국어)

MCP 서버 하나 띄우고 mcp-guard scan --endpoint 한 번 → 0.5초 만에 도구 능력, 인증 상태, Docker 컨테이너까지 다 토해냅니다.

내가 만드는 MCP 안전한지 / 남이 만든 MCP 깔아도 되는지, 둘 다 한 도구로.

v0.2.0 출시. pip install 한 줄.

🔗 github.com/windshock/mcpscan

#MCP #AISecurity #OpenSource

---

## 옵션 C — 영문 짧음

Built mcp-guard: scans MCP servers for capability gaps (auth, unrestricted access, allowlist bypass) and optionally fuses with Cisco's mcp-scanner for malicious-intent detection.

The new --auto-all walks every running candidate on your host and emits one report per target, complete with PID + Docker container info.

100% recall on our 11-server benchmark.

```
pip install ...mcp_guard-0.2.0-py3-none-any.whl
```

🔗 github.com/windshock/mcpscan

#MCP #AISecurity #DevSecOps

---

## 업로드 체크리스트

1. ✅ 영상 파일: `demo/mcp-guard.mp4` (1080×1920, 36.6s, 560KB)
2. □ LinkedIn 우측 상단 "+" → "Post"
3. □ 사진/비디오 추가 → mcp-guard.mp4 선택
4. □ 본문 붙여넣기 (옵션 A/B/C 중 선택)
5. □ 자막(captions) 자동 생성 켜기 — LinkedIn은 영상 업로드 후 captions toggle 제공
6. □ 게시 전 미리보기에서 모바일 화면으로 확인 (Preview → Mobile)

## 보너스: 인트로/아웃트로 추가하고 싶다면

iMovie / CapCut으로:
- **인트로 (3초)**: "mcp-guard v0.2.0" 텍스트 + 흰 배경
- **본문**: `demo/mcp-guard.mp4` 그대로 붙여넣기
- **아웃트로 (3초)**: GitHub URL + QR 코드

총 ~45초가 LinkedIn 쇼츠 알고리즘에 가장 잘 맞습니다.
