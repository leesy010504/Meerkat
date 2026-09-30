# Ablation — provider `template`, model `n/a`, scenarios: ua_spoofed_dirbust, slow_port_scan

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| none | 2/2 | 2 | 1.00 | 0.50 | 0.00 | 0.750 | 0.65 | 4 | 0 | 0 |
| full | 2/2 | 1 | 1.00 | 0.50 | 0.00 | 0.750 | 0.50 | 7 | 3 | 1 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | ua_spoofed_dirbust | O | O | O | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET 18080 (msg:"LOCAL Directory Enumeration from Single Source"; flow:to_server; http.method; content:"GET"; threshold:typ` |
| none | slow_port_scan | O | O | X | X | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
| full | ua_spoofed_dirbust | O | O | O | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET 18080 (msg:"LOCAL Directory Enumeration from Single Source"; flow:to_server; http.method; content:"GET"; threshold:typ` |
| full | slow_port_scan | X | X | X | X | - | 5 | 3 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Port Scan - Multiple Ports from Single Source"; flow:to_server; flags:S,12; threshold:type threshold, t` |
