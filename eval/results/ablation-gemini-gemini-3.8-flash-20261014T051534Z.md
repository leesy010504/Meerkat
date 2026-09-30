# Ablation — provider `gemini`, model `gemini-3.8-flash`, scenarios: ua_spoofed_dirbust, slow_port_scan

| 검증 조건 | 시나리오 | 룰 수 | SA | DR | FPR | SE | SS | LLM 호출 | 수리 | 실패 |
|---|---|---|---|---|---|---|---|---|---|---|
| none | 2/2 | 1 | 1.00 | 0.50 | 1.00 | 0.250 | 0.67 | 3 | 0 | 1 |

## 룰별 결과

| 조건 | 시나리오 | 생성 | 문법 | 트리거 | 오탐 | 그룹 | LLM | 수리 | 룰 |
|---|---|---|---|---|---|---|---|---|---|
| none | ua_spoofed_dirbust | O | O | O | O | web-attack | 2 | 0 | `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Potential HTTP Directory Busting / Web Application Scan Detected"; flow:to_server,established; threshold: ty` |
| none | slow_port_scan | X | X | X | X | - | 1 | 0 | `error: 503 UNAVAILABLE. {'error': {'code': 503, 'message': 'This model is currently experiencing high demand. Spikes in demand are usually temporary. Please try` |
