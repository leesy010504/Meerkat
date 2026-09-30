# Ablation — provider `gemini`, model `gemini-3.1-flash-lite`, scenarios: port_scan, dir_bruteforce

| 검증 조건 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|
| none | 2 | 1.00 | 0.50 | 0.50 | 0.500 | 0.73 | 4 | 0 | 0 |
| full | 2 | 1.00 | 1.00 | 0.00 | 1.000 | 0.73 | 7 | 3 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | port_scan | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential Port Scan Detected"; detection_filter:track by_src, count 60, seconds 300; classtype:networ` |
| none | dir_bruteforce | O | O | X | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Gobuster Directory Brute Force User-Agent"; flow:established,to_server; http.user_agent` |
| full | port_scan | O | O | O | X | scanning | 3 | 1 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential Port Scan Detected"; flags:S,12; detection_filter:track by_src, count 60, seconds 300; clas` |
| full | dir_bruteforce | O | O | O | X | web-attack | 4 | 2 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Gobuster Directory Brute Force Attempt"; flow:established,to_server; http.user_agent; c` |
