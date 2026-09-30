# Ablation — provider `gemini`, model `gemini-3.6-flash`, scenarios: ua_spoofed_dirbust, slow_port_scan

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| none | 2/2 | 2 | 1.00 | 0.00 | 0.50 | 0.250 | 0.65 | 4 | 0 | 0 |
| full | 2/2 | 0 | 0.00 | 0.00 | 0.00 | 0.500 | - | 4 | 1 | 2 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | ua_spoofed_dirbust | O | O | X | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Possible Web Directory Enumeration or Brute Force Scan"; flow:established,to_server; threshold:type ` |
| none | slow_port_scan | O | O | X | O | scanning | 2 | 0 | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"TCP Port Scan Detected"; threshold: type threshold, track by_src, count 210, seconds 60; classtype:attempted-` |
| full | ua_spoofed_dirbust | X | X | X | X | - | 1 | 0 | `error: 503 UNAVAILABLE. {'error': {'code': 503, 'message': 'This model is currently experiencing high demand. Spikes in demand are usually temporary. Please try` |
| full | slow_port_scan | X | X | X | X | - | 3 | 1 | `error: 503 UNAVAILABLE. {'error': {'code': 503, 'message': 'This model is currently experiencing high demand. Spikes in demand are usually temporary. Please try` |
