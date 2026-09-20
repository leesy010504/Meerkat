"""검증(문법 검사·리플레이)용 Suricata 실행 환경 설정.

운영 Suricata(deploy/k8s)는 suricata.yaml의 HOME_NET이 클러스터 CIDR로 잡혀 있지만,
검증용 pcap은 대부분 로컬 재현(127.0.0.1 / ::1)으로 캡처된다. 기본 HOME_NET(RFC1918)
기준으로는 루프백 트래픽이 $HOME_NET에도 $EXTERNAL_NET에도 속하지 않아서,
`$EXTERNAL_NET any -> $HOME_NET any` 같은 정상적인 inbound 룰이 재현 트래픽에서
절대 트리거되지 않는다 — 그러면 LLM은 "no_trigger" 피드백을 받고 방향을 any/any로
뭉개는 쪽으로 수리하게 된다.

그래서 검증 때만 HOME_NET에 루프백을 더하고 EXTERNAL_NET을 any로 둔다
(ET Open 권고 배포 설정과 같은 방식). 룰 텍스트 자체는 바뀌지 않으므로 운영
suricata.yaml의 변수 정의가 그대로 적용된다.
"""

VERIFY_ADDRESS_GROUPS: dict[str, str] = {
    "HOME_NET": "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8,::1/128]",
    "EXTERNAL_NET": "any",
}


def suricata_set_args(address_groups: dict[str, str] | None = None) -> list[str]:
    """`suricata --set vars.address-groups.X=Y ...` 인자 목록을 만든다."""
    groups = VERIFY_ADDRESS_GROUPS if address_groups is None else address_groups
    args: list[str] = []
    for name, value in groups.items():
        args += ["--set", f"vars.address-groups.{name}={value}"]
    return args
