# Ablation — provider `gemini`, model `gemini-3.8-flash`, scenarios: port_scan, ssh_bruteforce, dir_bruteforce, dns_query_burst

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| none | 4/4 | 4 | 1.00 | 0.75 | 0.25 | 0.750 | 0.86 | 9 | 0 | 0 |
| full | 4/4 | 4 | 1.00 | 1.00 | 0.00 | 1.000 | 0.86 | 10 | 2 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | port_scan | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential TCP Port Scan"; flags:S; threshold:type threshold, track by_src, count 60, seconds 300; cla` |
| none | ssh_bruteforce | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg:"Potential SSH Brute Force / Scanning Attempt"; flow:to_server; flags:S; threshold: type threshold, track by_` |
| none | dir_bruteforce | O | O | X | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN Gobuster Directory Brute Force Tool Detected"; flow:to_server,established; http.user_agent; content:"go` |
| none | dns_query_burst | O | O | O | X | dns-flood | 3 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"ET DOS Inbound DNS Query Flood (flood-test.example)"; dns.query; content:"flood-test.example"; nocase; thresho` |
| full | port_scan | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN TCP SYN Port Scan Detected"; flags:S; threshold: type both, track by_src, count 141, seconds 300; classt` |
| full | ssh_bruteforce | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg:"Potential SSH Brute Force Inbound"; flow:to_server; flags:S; threshold: type both, track by_src, count 10, s` |
| full | dir_bruteforce | O | O | O | X | web-attack | 4 | 2 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN Gobuster Web Directory Brute Force Tool Detected"; flow:established,to_server; http.user_agent; content` |
| full | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"DOS High Volume Inbound DNS Query Flood"; threshold: type both, track by_src, count 100, seconds 60; classtype` |
