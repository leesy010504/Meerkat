"""Suricata 파서 에러 메시지를 실패 유형별 수리 지침으로 매핑한다."""

import re

from pydantic import BaseModel


class ErrorClass(BaseModel):
    name: str
    match_pattern: str
    repair_guidance: str
    auto_fixable: bool


ERROR_CLASSES: list[ErrorClass] = [
    ErrorClass(
        name="legacy_http_modifier",
        match_pattern=r"deprecated.*http_(uri|client_body|header|method|user_agent|host)",
        repair_guidance="레거시 http_* modifier를 http.* 스티키 버퍼 문법으로 바꿔라.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="unknown_keyword",
        match_pattern=r"unknown (rule )?keyword",
        repair_guidance="존재하지 않는 키워드다. Suricata 8.x 키워드 목록에 있는 이름으로 교체하라.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="duplicate_sid",
        match_pattern=r"duplicate.*sid|sid.*already.*(used|exists)",
        repair_guidance="sid가 이미 사용 중이다. rule_memory에 없는 새 sid를 로컬 범위에서 할당하라.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="missing_sid",
        match_pattern=r"missing.*sid|sid.*required",
        repair_guidance="모든 룰은 sid를 가져야 한다. 로컬 범위(1000000-1999999)에서 할당하라.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="unbalanced_parentheses",
        match_pattern=r"unbalanced parenthes|no closing.*\)",
        repair_guidance="옵션 블록의 괄호가 안 맞는다. 룰 전체를 다시 생성하라.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="invalid_ip_variable",
        match_pattern=r"unknown.*(var|variable).*HOME_NET|unknown.*(var|variable).*EXTERNAL_NET",
        repair_guidance="$HOME_NET / $EXTERNAL_NET만 쓰고 임의 IP 리터럴 변수명을 만들지 마라.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="malformed_pcre",
        match_pattern=r"pcre parse error|invalid pcre",
        repair_guidance="PCRE 문법이 깨졌다. 슬래시 구분자와 플래그 순서를 확인해 다시 작성하라.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="pcre_relative_without_prior_match",
        match_pattern=r"pcre.*relative.*without.*prior|'R' flag.*without",
        repair_guidance="PCRE에 /R(상대 매치) 플래그가 있는데 그 앞에 상대 기준이 될 콘텐츠 매치가 없다.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="fast_pattern_without_content",
        match_pattern=r"fast_pattern.*without.*content|fast_pattern.*needs.*content",
        repair_guidance="fast_pattern은 반드시 content 다음에만 쓸 수 있다.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="nocase_without_content",
        match_pattern=r"nocase.*without.*content|nocase.*needs.*content",
        repair_guidance="nocase는 content 옵션 바로 뒤에만 붙는다.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="bsize_mismatch",
        match_pattern=r"bsize.*mismatch|bsize.*invalid",
        repair_guidance="bsize 값이 실제 content 바이트 길이와 다르다. 길이를 다시 계산해 맞춰라.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="invalid_flow_direction",
        match_pattern=r"invalid.*flow.*direction|flow.*keyword.*conflict",
        repair_guidance="flow:to_server / to_client와 헤더의 $HOME_NET/$EXTERNAL_NET 배치가 맞아야 한다.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="unknown_app_layer_protocol",
        match_pattern=r"unknown.*app.*layer.*protocol|unknown protocol",
        repair_guidance="tcp/udp/icmp 또는 지원되는 app-layer 프로토콜(http, dns, tls, smb 등)만 쓸 수 있다.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="sticky_buffer_without_keyword",
        match_pattern=r"sticky buffer.*without.*(content|keyword)",
        repair_guidance="스티키 버퍼(http.uri; 등) 선언 뒤에는 반드시 content/pcre 같은 매치 키워드가 와야 한다.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="duplicate_sticky_buffer",
        match_pattern=r"duplicate.*sticky.*buffer|redundant buffer",
        repair_guidance="같은 스티키 버퍼가 연달아 중복 선언됐다. 하나로 합쳐라.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="response_buffer_with_to_server",
        match_pattern=r"response.*buffer.*to_server|server.*only.*buffer.*to_server",
        repair_guidance="응답 전용 버퍼(http.stat_code 등)는 flow:to_client에서만 쓸 수 있다.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="tls_cert_field_wrong_direction",
        match_pattern=r"tls.*cert.*to_server|tls certificate.*direction",
        repair_guidance="TLS 인증서 필드는 서버→클라이언트 데이터이므로 flow:to_client여야 한다.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="get_method_with_request_body",
        match_pattern=r"GET.*request_body|request_body.*GET",
        repair_guidance="GET 요청은 통상 바디가 없다. http.request_body 버퍼를 제거하라.",
        auto_fixable=True,
    ),
    ErrorClass(
        name="invalid_threshold_syntax",
        match_pattern=r"invalid threshold|threshold.*parse error",
        repair_guidance=(
            "threshold 절 문법이 잘못됐다. "
            "'threshold:type threshold, track by_src, count N, seconds N;' 형태를 지켜라. "
            "count/seconds는 baseline suggested_threshold 값을 그대로 써야 한다."
        ),
        auto_fixable=True,
    ),
    ErrorClass(
        name="invalid_classtype",
        match_pattern=r"unknown classtype|invalid classtype",
        repair_guidance="classification.config에 정의된 classtype만 쓸 수 있다.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="invalid_priority",
        match_pattern=r"invalid priority|priority.*not.*integer",
        repair_guidance="priority는 1~4 사이 정수여야 한다.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="flowbits_isset_without_set",
        match_pattern=r"flowbits.*isset.*without.*set|flowbits.*never set",
        repair_guidance="flowbits:isset이 참조하는 플래그를 set하는 룰이 룰셋에 없다.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="content_too_short",
        match_pattern=r"content.*too short|content.*minimum length",
        repair_guidance="content가 너무 짧아 광범위 매칭이 된다. 더 긴/구체적인 시그니처로 바꿔라.",
        auto_fixable=False,
    ),
    ErrorClass(
        name="smb_ascii_content_mismatch",
        match_pattern=r"smb.*ascii|smb.*utf-?16",
        repair_guidance="SMB 필드는 UTF-16LE로 인코딩된다. ASCII content를 UTF-16LE hex로 변환하라.",
        auto_fixable=True,
    ),
]


def classify_error(raw_output: str) -> ErrorClass | None:
    for error_class in ERROR_CLASSES:
        if re.search(error_class.match_pattern, raw_output, re.IGNORECASE):
            return error_class
    return None
