# Ablation — provider `gemini`, model `gemini-3.1-flash-lite`, scenarios: port_scan, ssh_bruteforce, dir_bruteforce, dns_query_burst

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| syntax | 4/4 | 4 | 1.00 | 0.75 | 0.50 | 0.625 | 0.77 | 8 | 0 | 0 |
| syntax_attack | 4/4 | 4 | 1.00 | 1.00 | 0.50 | 0.750 | 0.86 | 10 | 2 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| syntax | port_scan | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential Port Scan Detected"; flow:stateless; detection_filter:track by_src, count 60, seconds 300; ` |
| syntax | ssh_bruteforce | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg: "ET SCAN SSH Brute Force Attempt"; flow: to_server, established; detection_filter: track by_src, count 10, s` |
| syntax | dir_bruteforce | O | O | X | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Gobuster Directory Brute Force Attempt"; flow:established,to_server; http.user_agent; c` |
| syntax | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"ET DOS Potential DNS Query Flood from Single Source"; dns.query; content:".flood-test.example"; nocase; thresh` |
| syntax_attack | port_scan | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential Port Scan Detected"; flow:to_server; detection_filter:track by_src, count 60, seconds 300; ` |
| syntax_attack | ssh_bruteforce | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg:"ET SCAN Potential SSH Brute Force Attempt"; flow:to_server,established; detection_filter:track by_src,count ` |
| syntax_attack | dir_bruteforce | O | O | O | X | web-attack | 4 | 2 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB-ATTACK Gobuster Directory Brute Force User-Agent"; http.user_agent; content:"gobuster"; nocase; thres` |
| syntax_attack | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"ET DOS Potential DNS Query Flood from Single Source"; dns.query; content:".flood-test.example"; nocase; thresh` |
