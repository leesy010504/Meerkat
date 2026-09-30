# Ablation — provider `gemini`, model `gemini-3.1-flash-lite`, scenarios: slow_port_scan

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 1/1 | 1 | 1.00 | 1.00 | 0.00 | 1.000 | 0.80 | 5 | 3 | 0 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| full | slow_port_scan | O | O | O | X | scanning | 5 | 3 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential Port Scan Detected"; flow:stateless; flags:S; detection_filter:track by_src, count 200, sec` |
