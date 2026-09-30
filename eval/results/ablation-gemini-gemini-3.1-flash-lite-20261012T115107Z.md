# Ablation — provider `gemini`, model `gemini-3.1-flash-lite`, scenarios: port_scan, ssh_bruteforce, dir_bruteforce, dns_query_burst

| 검증 조건 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|
| none | 4 | 1.00 | 0.75 | 0.50 | 0.625 | 0.77 | 8 | 0 | 0 |
| full | 4 | 1.00 | 1.00 | 0.00 | 1.000 | 0.82 | 10 | 2 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | port_scan | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential Port Scan Detected"; flow:stateless; detection_filter:track by_src, count 60, seconds 300; ` |
| none | ssh_bruteforce | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg: "ET SCAN SSH Brute Force Attempt"; flow: to_server, established; detection_filter: track by_src, count 10, s` |
| none | dir_bruteforce | O | O | X | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB-ATTACK Gobuster Directory Brute Force User-Agent"; flow:established,to_server; http.user_agent; conte` |
| none | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"ET DOS DNS Query Flood from Single Source"; dns.query; content:".flood-test.example"; nocase; threshold:type t` |
| full | port_scan | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential Port Scan Detected"; flow:to_server; detection_filter:track by_src, count 1680, seconds 300` |
| full | ssh_bruteforce | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg: "ET SCAN Potential SSH Brute Force Attempt"; flow: to_server, established; detection_filter: track by_src, c` |
| full | dir_bruteforce | O | O | O | X | web-attack | 4 | 2 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB-ATTACK Gobuster Directory Brute Force User-Agent"; flow:established,to_server; http.user_agent; conte` |
| full | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg: "ET DOS Potential DNS Flood Attack (flood-test.example)"; dns.query; content: ".flood-test.example"; nocase; t` |
