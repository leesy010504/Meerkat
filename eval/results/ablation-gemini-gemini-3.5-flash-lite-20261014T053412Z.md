# Ablation — provider `gemini`, model `gemini-3.5-flash-lite`, scenarios: ua_spoofed_dirbust, slow_port_scan

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 2/2 | 2 | 1.00 | 1.00 | 0.00 | 1.000 | 0.57 | 8 | 4 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| full | ua_spoofed_dirbust | O | O | O | X | web-attack | 4 | 2 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 18080 (msg: "ET WEB_SPECIFIC_APPS Directory Brute Force Attempt"; flow: established, to_server; http.method; content: "` |
| full | slow_port_scan | O | O | O | X | scanning | 4 | 2 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Potential Port Scan Detected"; flow:stateless; flags:S; detection_filter:track by_src, count 150, seconds 300` |
