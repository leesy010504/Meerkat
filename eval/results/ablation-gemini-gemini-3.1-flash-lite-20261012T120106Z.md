# Ablation — provider `gemini`, model `gemini-3.1-flash-lite`, scenarios: port_scan, ssh_bruteforce, dir_bruteforce, dns_query_burst

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 4/4 | 4 | 1.00 | 1.00 | 0.00 | 1.000 | 0.81 | 11 | 3 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| full | port_scan | O | O | O | X | scanning | 3 | 1 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential TCP Port Scan"; flow:stateless; flags:S,12; detection_filter:track by_src, count 140, secon` |
| full | ssh_bruteforce | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg:"ET SCAN Potential SSH Brute Force Attempt"; flow:to_server,established; detection_filter:track by_src,count ` |
| full | dir_bruteforce | O | O | O | X | web-attack | 4 | 2 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Gobuster Directory Brute Force Attempt"; flow:established,to_server; http.user_agent; c` |
| full | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"ET DOS DNS Query Flood from Single Source"; dns.query; content:".flood-test.example"; nocase; threshold:type t` |
