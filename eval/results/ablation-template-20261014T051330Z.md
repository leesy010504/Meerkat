# Ablation — provider `template`, model `n/a`, scenarios: port_scan, ssh_bruteforce, dir_bruteforce, dns_query_burst, ua_spoofed_dirbust, slow_port_scan

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| none | 6/6 | 6 | 1.00 | 0.83 | 0.17 | 0.833 | 0.85 | 13 | 0 | 0 |
| full | 6/6 | 5 | 1.00 | 0.83 | 0.00 | 0.917 | 0.86 | 15 | 3 | 1 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | port_scan | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
| none | ssh_bruteforce | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg:"LOCAL Connection Flood from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, track by_s` |
| none | dir_bruteforce | O | O | O | X | web-attack | 3 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Scanner User-Agent gobuster"; flow:to_server; http.user_agent; content:"gobuster"; nocase; classtype:w` |
| none | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"LOCAL DNS Query Flood from Single Source"; threshold:type threshold, track by_src, count 100, seconds 60; clas` |
| none | ua_spoofed_dirbust | O | O | O | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET 18080 (msg:"LOCAL Directory Enumeration from Single Source"; flow:to_server; http.method; content:"GET"; threshold:typ` |
| none | slow_port_scan | O | O | X | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
| full | port_scan | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
| full | ssh_bruteforce | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg:"LOCAL Connection Flood from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, track by_s` |
| full | dir_bruteforce | O | O | O | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Scanner User-Agent gobuster"; flow:to_server; http.user_agent; content:"gobuster"; nocase; classtype:w` |
| full | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"LOCAL DNS Query Flood from Single Source"; threshold:type threshold, track by_src, count 100, seconds 60; clas` |
| full | ua_spoofed_dirbust | O | O | O | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET 18080 (msg:"LOCAL Directory Enumeration from Single Source"; flow:to_server; http.method; content:"GET"; threshold:typ` |
| full | slow_port_scan | X | X | X | X | - | 5 | 3 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
