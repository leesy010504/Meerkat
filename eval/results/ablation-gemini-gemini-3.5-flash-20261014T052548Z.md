# Ablation — provider `gemini`, model `gemini-3.5-flash`, scenarios: ua_spoofed_dirbust, slow_port_scan

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| none | 2/2 | 0 | 0.00 | 0.00 | 0.00 | 0.500 | - | 2 | 0 | 2 |
| full | 2/2 | 1 | 1.00 | 0.50 | 0.00 | 0.750 | 0.67 | 3 | 0 | 1 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | ua_spoofed_dirbust | X | X | X | X | - | 1 | 0 | `error: 503 UNAVAILABLE. {'error': {'code': 503, 'message': 'This model is currently experiencing high demand. Spikes in demand are usually temporary. Please try` |
| none | slow_port_scan | X | X | X | X | - | 1 | 0 | `error: traffic already covered by existing rule sid=1000000` |
| full | ua_spoofed_dirbust | O | O | O | X | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible Web Directory Scanning or Brute Force Attempt"; http.method; content:"GET"; threshold: type thresho` |
| full | slow_port_scan | X | X | X | X | - | 1 | 0 | `error: 503 UNAVAILABLE. {'error': {'code': 503, 'message': 'This model is currently experiencing high demand. Spikes in demand are usually temporary. Please try` |
