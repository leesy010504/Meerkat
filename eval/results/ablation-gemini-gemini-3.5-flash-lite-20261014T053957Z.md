# Ablation — provider `gemini`, model `gemini-3.5-flash-lite`, scenarios: ua_spoofed_dirbust, slow_port_scan

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 2/2 | 2 | 1.00 | 1.00 | 0.00 | 1.000 | 0.57 | 6 | 2 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| full | ua_spoofed_dirbust | O | O | O | X | web-attack | 4 | 2 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 18080 (msg:"ET WEB-SPECIFIC Directory Brute Force / Scanning Activity Detected"; flow:established,to_server; http.metho` |
| full | slow_port_scan | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Potential Port Scan Detected"; flags: S; threshold: type threshold, track by_src, count 220, seconds 300; cla` |
