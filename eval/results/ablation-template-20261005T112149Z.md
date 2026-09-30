# Ablation — provider `template`, model `n/a`, scenarios: dns_query_burst

| 검증 조건 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|
| none | 1 | 1.00 | 1.00 | 0.00 | 1.000 | 1.00 | 2 | 0 | 0 |
| syntax | 1 | 1.00 | 1.00 | 0.00 | 1.000 | 1.00 | 2 | 0 | 0 |
| syntax_attack | 1 | 1.00 | 1.00 | 0.00 | 1.000 | 1.00 | 2 | 0 | 0 |
| full | 1 | 1.00 | 1.00 | 0.00 | 1.000 | 1.00 | 2 | 0 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"LOCAL DNS Query Flood from Single Source"; threshold:type threshold, track by_src, count 100, seconds 60; clas` |
| syntax | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"LOCAL DNS Query Flood from Single Source"; threshold:type threshold, track by_src, count 100, seconds 60; clas` |
| syntax_attack | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"LOCAL DNS Query Flood from Single Source"; threshold:type threshold, track by_src, count 100, seconds 60; clas` |
| full | dns_query_burst | O | O | O | X | dns-flood | 2 | 0 | `alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"LOCAL DNS Query Flood from Single Source"; threshold:type threshold, track by_src, count 100, seconds 60; clas` |
