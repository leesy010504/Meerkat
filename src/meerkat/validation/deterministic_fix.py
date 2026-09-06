import re
from typing import Callable

from pydantic import BaseModel

HEADER_RE = re.compile(
    r"^(?P<action>\S+)\s+(?P<proto>\S+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"(?P<arrow>->|<>)\s+(?P<dst>\S+)\s+(?P<dport>\S+)\s*$"
)

LEGACY_HTTP_MODIFIERS = {
    "http_uri": "http.uri",
    "http_raw_uri": "http.uri.raw",
    "http_client_body": "http.request_body",
    "http_header": "http.header",
    "http_method": "http.method",
    "http_user_agent": "http.user_agent",
    "http_host": "http.host",
    "http_stat_code": "http.stat_code",
}

TSHARK_FIELD_MAP = {
    "http.request.method": "http.method",
    "http.request.uri": "http.uri",
    "http.response.code": "http.stat_code",
    "dns.qry.name": "dns.query",
}

RESPONSE_ONLY_BUFFERS = ["http.stat_code", "http.stat_msg", "http.response_line"]
TLS_CERT_BUFFERS = ["tls.cert_subject", "tls.cert_issuer", "tls.cert_serial", "tls.certs"]


class DeterministicFixResult(BaseModel):
    rule_text: str
    applied_fixes: list[str]


def apply_deterministic_fixes(rule_text: str) -> DeterministicFixResult:
    applied: list[str] = []
    text = rule_text

    for name, fn in _PIPELINE:
        new_text = fn(text)
        if new_text != text:
            applied.append(name)
            text = new_text

    return DeterministicFixResult(rule_text=text, applied_fixes=applied)


def check_sid_conflict(rule_text: str, existing_sids: set[int]) -> bool:
    """rule_memory의 기존 sid 집합과 대조해 충돌 여부를 확인한다."""
    match = re.search(r"\bsid:\s*(\d+)\s*;", rule_text)
    if match is None:
        return False
    return int(match.group(1)) in existing_sids


# ---- 패턴별 구현 --------------------------------------------------------


def fix_legacy_http_modifier(text: str) -> str:
    header, options = _split_rule(text)
    if header is None:
        return text

    changed = False
    new_options: list[str] = []
    i = 0
    while i < len(options):
        opt = options[i]
        content_match = re.match(r'content:\s*"(.*)"\s*$', opt.strip())
        if content_match and i + 1 < len(options):
            modifier = options[i + 1].strip()
            if modifier in LEGACY_HTTP_MODIFIERS:
                buffer_name = LEGACY_HTTP_MODIFIERS[modifier]
                new_options.append(f"{buffer_name}; content:\"{content_match.group(1)}\"")
                changed = True
                i += 2
                continue
        new_options.append(opt)
        i += 1

    if not changed:
        return text
    return _join_rule(header, new_options)


def fix_tshark_field_names(text: str) -> str:
    changed_text = text
    for tshark_name, suricata_name in TSHARK_FIELD_MAP.items():
        pattern = re.compile(rf"\b{re.escape(tshark_name)}\b")
        changed_text = pattern.sub(suricata_name, changed_text)
    return changed_text


def fix_direction_conflict(text: str) -> str:
    header, options = _split_rule(text)
    if header is None:
        return text

    m = HEADER_RE.match(header.strip())
    if m is None:
        return text

    flow_dir = _flow_direction(options)
    if flow_dir is None:
        return text

    src, dst = m.group("src"), m.group("dst")
    src_is_external = "EXTERNAL_NET" in src
    dst_is_external = "EXTERNAL_NET" in dst

    needs_swap = False
    if flow_dir == "to_server" and not src_is_external and dst_is_external:
        # 클라이언트가 출발지여야 하는데 반대로 되어 있음
        needs_swap = True
    elif flow_dir == "to_client" and src_is_external and not dst_is_external:
        needs_swap = True

    if not needs_swap:
        return text

    new_header = (
        f"{m.group('action')} {m.group('proto')} "
        f"{m.group('dst')} {m.group('dport')} {m.group('arrow')} "
        f"{m.group('src')} {m.group('sport')}"
    )
    return _join_rule(new_header, options)


def fix_dns_pcre_relative_flag(text: str) -> str:
    if "dns" not in text.lower():
        return text

    pattern = re.compile(r'pcre:"(?P<pattern>/.*/)(?P<flags>[A-Za-z]*)"')

    def _sub(m: re.Match) -> str:
        flags = m.group("flags")
        if "R" not in flags:
            return m.group(0)
        return f'pcre:"{m.group("pattern")}{flags.replace("R", "")}"'

    return pattern.sub(_sub, text)


def fix_http_uri_endswith(text: str) -> str:
    if "http.uri" not in text:
        return text
    return re.sub(r"\s*endswith;", ";", text)


def fix_fast_pattern_without_content(text: str) -> str:
    if "content:" in text:
        return text
    return re.sub(r"\s*fast_pattern;", ";", text)


def fix_bsize_mismatch(text: str) -> str:
    header, options = _split_rule(text)
    if header is None:
        return text

    changed = False
    new_options: list[str] = []
    pending_len: int | None = None
    for opt in options:
        stripped = opt.strip()
        content_match = re.match(r'content:\s*"(.*)"\s*$', stripped)
        if content_match:
            pending_len = _content_byte_length(content_match.group(1))
            new_options.append(opt)
            continue

        bsize_match = re.match(r"bsize:\s*(\d+)\s*$", stripped)
        if bsize_match and pending_len is not None:
            declared = int(bsize_match.group(1))
            if declared != pending_len:
                new_options.append(f"bsize:{pending_len}")
                changed = True
                pending_len = None
                continue

        new_options.append(opt)

    if not changed:
        return text
    return _join_rule(header, new_options)


def fix_nocase_without_content(text: str) -> str:
    if "content:" in text:
        return text
    return re.sub(r"\s*nocase;", ";", text)


def fix_sticky_buffer_dup(text: str) -> str:
    return re.sub(r"\b([a-z_]+\.[a-z_]+;)\s*\1", r"\1", text)


def fix_excessive_dns_pcre_anchor(text: str) -> str:
    if "dns.query" not in text and "dns_query" not in text:
        return text

    def relax(m: re.Match) -> str:
        pattern = m.group("pattern")
        relaxed = pattern
        if relaxed.startswith("/^"):
            relaxed = "/" + relaxed[2:]
        if relaxed.endswith("$/"):
            relaxed = relaxed[:-2] + "/"
        return f'pcre:"{relaxed}{m.group("flags")}"'

    pattern = re.compile(r'pcre:"(?P<pattern>/[^"]*/)(?P<flags>[A-Za-z]*)"')
    return pattern.sub(relax, text)


def fix_get_with_request_body(text: str) -> str:
    if '"GET"' not in text and "http.method" not in text:
        return text
    header, options = _split_rule(text)
    if header is None:
        return text

    new_options = [
        opt for opt in options if "http.request_body" not in opt and "http_client_body" not in opt
    ]
    if len(new_options) == len(options):
        return text
    return _join_rule(header, new_options)


def fix_to_server_with_response_buffer(text: str) -> str:
    return _flip_flow_if_buffer_present(text, RESPONSE_ONLY_BUFFERS)


def fix_tls_cert_field_with_client_direction(text: str) -> str:
    return _flip_flow_if_buffer_present(text, TLS_CERT_BUFFERS)


def fix_smb_ascii_match(text: str) -> str:
    if "smb" not in text.lower():
        return text

    header, options = _split_rule(text)
    if header is None:
        return text

    changed = False
    new_options: list[str] = []
    for opt in options:
        stripped = opt.strip()
        m = re.match(r'content:\s*"([^|][^"]*)"\s*$', stripped)
        if m and "smb" in text.lower():
            hex_bytes = _ascii_to_utf16le_hex(m.group(1))
            new_options.append(f'content:"|{hex_bytes}|"')
            changed = True
            continue
        new_options.append(opt)

    if not changed:
        return text
    return _join_rule(header, new_options)


def fix_invalid_threshold_syntax(text: str) -> str:
    header, options = _split_rule(text)
    if header is None:
        return text

    changed = False
    new_options: list[str] = []
    valid_re = re.compile(
        r"^threshold:\s*type\s+(threshold|limit|both)\s*,\s*"
        r"track\s+(by_src|by_dst)\s*,\s*count\s+\d+\s*,\s*seconds\s+\d+\s*$"
    )
    for opt in options:
        stripped = opt.strip()
        if stripped.startswith("threshold:") and not valid_re.match(stripped):
            changed = True
            continue
        new_options.append(opt)

    if not changed:
        return text
    return _join_rule(header, new_options)


_PIPELINE: list[tuple[str, Callable[[str], str]]] = [
    ("legacy_http_modifier", fix_legacy_http_modifier),
    ("tshark_field_misuse", fix_tshark_field_names),
    ("direction_conflict", fix_direction_conflict),
    ("dns_pcre_relative_flag", fix_dns_pcre_relative_flag),
    ("http_uri_endswith", fix_http_uri_endswith),
    ("fast_pattern_without_content", fix_fast_pattern_without_content),
    ("bsize_mismatch", fix_bsize_mismatch),
    ("nocase_without_content", fix_nocase_without_content),
    ("sticky_buffer_dup", fix_sticky_buffer_dup),
    ("excessive_dns_pcre_anchor", fix_excessive_dns_pcre_anchor),
    ("get_with_request_body", fix_get_with_request_body),
    ("to_server_with_response_buffer", fix_to_server_with_response_buffer),
    ("tls_cert_field_with_client_direction", fix_tls_cert_field_with_client_direction),
    ("smb_ascii_match", fix_smb_ascii_match),
    ("invalid_threshold_syntax", fix_invalid_threshold_syntax),
]


# ---- 공용 헬퍼 ------------------------------------------------------------


def _split_rule(text: str) -> tuple[str | None, list[str]]:
    open_idx = text.find("(")
    close_idx = text.rfind(")")
    if open_idx == -1 or close_idx == -1 or close_idx < open_idx:
        return None, []

    header = text[:open_idx].strip()
    body = text[open_idx + 1 : close_idx]
    return header, _split_options(body)


def _join_rule(header: str, options: list[str]) -> str:
    body = " ".join(f"{opt.strip()};" for opt in options if opt.strip())
    return f"{header} ({body})"


def _split_options(body: str) -> list[str]:
    options: list[str] = []
    current = ""
    in_quotes = False
    for ch in body:
        if ch == '"':
            in_quotes = not in_quotes
        if ch == ";" and not in_quotes:
            options.append(current.strip())
            current = ""
            continue
        current += ch
    if current.strip():
        options.append(current.strip())
    return options


def _flow_direction(options: list[str]) -> str | None:
    for opt in options:
        if "to_server" in opt:
            return "to_server"
        if "to_client" in opt:
            return "to_client"
    return None


def _content_byte_length(content: str) -> int:
    length = 0
    i = 0
    while i < len(content):
        if content[i] == "|":
            end = content.find("|", i + 1)
            if end == -1:
                break
            hex_part = content[i + 1 : end].replace(" ", "")
            length += len(hex_part) // 2
            i = end + 1
        else:
            length += 1
            i += 1
    return length


def _flip_flow_if_buffer_present(text: str, buffers: list[str]) -> str:
    if not any(buf in text for buf in buffers):
        return text
    if "to_server" not in text:
        return text
    return text.replace("to_server", "to_client")


def _ascii_to_utf16le_hex(s: str) -> str:
    raw = s.encode("utf-16-le")
    return " ".join(f"{b:02X}" for b in raw)
