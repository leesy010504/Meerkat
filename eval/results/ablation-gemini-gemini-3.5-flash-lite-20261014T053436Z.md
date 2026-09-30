# Ablation — provider `gemini`, model `gemini-3.5-flash-lite`, scenarios: ua_spoofed_dirbust, slow_port_scan

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 2/2 | 1 | 1.00 | 0.50 | 0.00 | 0.750 | 0.33 | 7 | 3 | 1 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| full | ua_spoofed_dirbust | O | O | O | X | web-attack | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 18080 (msg: "SURICATA Directory Bruteforce Attempt"; flow: established, to_server; http.method; content: "GET"; thresho` |
| full | slow_port_scan | X | X | X | X | - | 5 | 3 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Potential Port Scan Detected"; flow:to_server; flags:S; detection_filter:track by_src, count 50, seconds 60; ` |
