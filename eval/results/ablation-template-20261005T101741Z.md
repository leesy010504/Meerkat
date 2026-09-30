# Ablation — provider `template`, scenarios: port_scan, ssh_bruteforce, dir_bruteforce

| 검증 조건 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|
| none | 3 | 1.00 | 1.00 | 0.33 | 0.833 | 0.93 | 7 | 0 | 0 |
| syntax | 3 | 1.00 | 1.00 | 0.33 | 0.833 | 0.93 | 7 | 0 | 0 |
| syntax_attack | 3 | 1.00 | 1.00 | 0.00 | 1.000 | 0.93 | 6 | 0 | 0 |
| full | 2 | 1.00 | 0.67 | 0.00 | 0.833 | 1.00 | 9 | 3 | 1 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | port_scan | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
| none | ssh_bruteforce | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Connection Flood from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, track by_sr` |
| none | dir_bruteforce | O | O | O | X | web-attack | 3 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Scanner User-Agent gobuster"; flow:to_server; http.user_agent; content:"gobuster"; nocase; classtype:w` |
| syntax | port_scan | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
| syntax | ssh_bruteforce | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Connection Flood from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, track by_sr` |
| syntax | dir_bruteforce | O | O | O | X | web-attack | 3 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Scanner User-Agent gobuster"; flow:to_server; http.user_agent; content:"gobuster"; nocase; classtype:w` |
| syntax_attack | port_scan | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
| syntax_attack | ssh_bruteforce | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg:"LOCAL Connection Flood from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, track by_s` |
| syntax_attack | dir_bruteforce | O | O | O | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Scanner User-Agent gobuster"; flow:to_server; http.user_agent; content:"gobuster"; nocase; classtype:w` |
| full | port_scan | O | O | O | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
| full | ssh_bruteforce | X | X | X | X | - | 5 | 3 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Connection Flood from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, track by_sr` |
| full | dir_bruteforce | O | O | O | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Scanner User-Agent gobuster"; flow:to_server; http.user_agent; content:"gobuster"; nocase; classtype:w` |
