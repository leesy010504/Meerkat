# Ablation — provider `gemini`, model `gemini-3.6-flash`, scenarios: port_scan, ssh_bruteforce, dir_bruteforce, dns_query_burst

| 검증 조건 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|
| none | 4 | 1.00 | 0.75 | 0.50 | 0.625 | 0.86 | 9 | 1 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | port_scan | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible TCP Port Scan Detected"; threshold: type threshold, track by_src, count 60, seconds 300; classtype:n` |
| none | ssh_bruteforce | O | O | O | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (msg:"Possible SSH Brute Force Attempt"; flow:to_server; threshold: type threshold, track by_src, count 10, second` |
| none | dir_bruteforce | O | O | X | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ATTACK-RESPONSES Gobuster Web Directory Bruteforce"; flow:established,to_server; http.user_agent; content:"g` |
| none | dns_query_burst | O | O | O | X | dns-flood | 3 | 1 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"DNS Query Flood targeting flood-test.example"; dns.query; content:"flood-test.example"; threshold:type thresho` |
