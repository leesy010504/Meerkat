"""rate 기반 룰(threshold / detection_filter)의 count를 재생으로 결정적으로 보정한다.

baseline p99×margin으로 나온 count가 정상(또는 다른 그룹 공격) pcap에서 알럿을 내면, 지금까지는
LLM 오탐 수리를 불렀다. 그런데 "count를 얼마로 올려야 조용해지는가"는 재생해보면 정확히 알 수 있는
문제라 LLM이 할 일이 아니다(원칙 1). 여기서는 count를 올려가며(배수 탐색 → 이분 탐색) negative pcap이
전부 조용해지는 최소 count를 찾고, 그 count에서 공격 pcap이 여전히 트리거되는지 확인한다.

count는 올리기만 한다 — baseline에서 나온 값보다 내리면 "임계값은 baseline에서 도출"(§14-7) 원칙이
깨진다. 보정 결과는 rationale/감사 로그에 "재생 보정으로 X→Y"로 남겨 사람이 알 수 있게 한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from meerkat.validation.replay import replay_rule

_COUNT_RE = re.compile(r"((?:threshold|detection_filter)\s*:[^;]*?\bcount\s+)(\d+)")
# baseline count의 8배까지만 올린다. 실측(10/12, gemini-3.1-flash-lite): SYN만 세야 할 포트스캔 룰이 모든
# 패킷을 셌는데 보정이 count를 60→1680(28배)으로 올려 통과시켰다. 그만큼 올려야 조용해진다면 count가
# 문제가 아니라 룰이 세는 대상이 틀린 것이다 — 그때는 보정을 포기하고 LLM 수리(flags:S 추가 등)로 넘긴다.
MAX_MULTIPLIER = 8
MIN_ABSOLUTE_CAP = 64  # baseline count가 아주 작을 때(5 등)는 배수 상한이 너무 낮아지므로 절대 상한을 둔다


@dataclass
class CalibrationResult:
    rule_text: str
    original_count: int
    calibrated_count: int
    replays: int

    @property
    def changed(self) -> bool:
        return self.calibrated_count != self.original_count


def extract_threshold_count(rule_text: str) -> int | None:
    match = _COUNT_RE.search(rule_text)
    return int(match.group(2)) if match else None


def set_threshold_count(rule_text: str, count: int) -> str:
    return _COUNT_RE.sub(lambda m: f"{m.group(1)}{count}", rule_text, count=1)


def calibrate_threshold(
    rule_text: str,
    attack_pcaps: list[str],
    negative_pcaps: list[str],
    suricata_binary: str = "suricata",
    max_multiplier: int = MAX_MULTIPLIER,
) -> CalibrationResult | None:
    """negative가 조용해지는 최소 count로 올린 룰을 돌려준다. rate 룰이 아니거나 보정 불가면 None.

    보정 불가 = 상한까지 올려도 negative가 울리거나, 조용해진 count에서 공격이 더는 트리거되지 않음.
    """
    original = extract_threshold_count(rule_text)
    if original is None or original <= 0:
        return None

    replays = 0

    def quiet(count: int) -> bool:
        nonlocal replays
        replays += 1
        return replay_rule(set_threshold_count(rule_text, count), "benign", negative_pcaps, suricata_binary).ok

    def fires(count: int) -> bool:
        nonlocal replays
        replays += 1
        return replay_rule(set_threshold_count(rule_text, count), "attack", attack_pcaps, suricata_binary).ok

    if quiet(original):
        return CalibrationResult(rule_text, original, original, replays)  # 보정 불필요

    # 1) 배수 탐색: 조용해지는 첫 count를 찾는다
    cap = max(original * max_multiplier, MIN_ABSOLUTE_CAP)
    low, high = original, original * 2
    while not quiet(high):
        low = high
        high *= 2
        if high > cap:
            return None
    # 2) 이분 탐색: (low: 울림, high: 조용) 사이에서 최소 조용 count
    while high - low > 1:
        mid = (low + high) // 2
        if quiet(mid):
            high = mid
        else:
            low = mid
    if not fires(high):
        return None  # 조용해질 만큼 올리면 공격도 놓친다 — rate 룰로는 분리 불가
    return CalibrationResult(set_threshold_count(rule_text, high), original, high, replays)


# ── 창(seconds)까지 바꾸는 분리 탐색 ────────────────────────────────────────────────────────────
#
# 위 calibrate_threshold는 오탐 쪽(count를 올리기만)만 다룬다. 저속 스캔 실험(10/14)에서 소형 모델이 실패한
# 경로는 반대쪽이었다: 제안 임계값(210/60s)이 분당 60개인 공격을 못 잡아 no_trigger → LLM이 count를 내리면
# 정상 브라우징(분당 140)에서 오탐 → 다시 올리면 미탐... 을 K회 반복. 하지만 60초 창에서는 애초에 가를 수 있는
# count가 없고(공격 60 < 정상 140), 300초 창에서는 공격 299 > 정상 140이라 그 사이 아무 값이나 된다.
# 이건 재생으로 정확히 풀리는 탐색 문제다.
#
# 원칙 유지: 고른 count는 항상 negative가 울리는 최대 count보다 크다 — 관측된 정상 수준 위에 둔다
# (§14-7 "임계값은 baseline에서 도출"의 실행 버전). 공격 최대치와의 중간값을 써서 양쪽에 여유를 둔다.

_SECONDS_RE = re.compile(r"((?:threshold|detection_filter)\s*:[^;]*?\bseconds\s+)(\d+)")
SEPARATION_WINDOWS = (60, 300)  # 원래 창 다음에 시도할 창. 5분보다 긴 창은 상태 테이블 부담이 커서 쓰지 않는다.
MAX_SEARCH_COUNT = 1 << 16


@dataclass
class SeparationResult:
    rule_text: str
    original_count: int
    original_seconds: int
    count: int
    seconds: int
    attack_max: int    # 이 창에서 공격이 울리는 최대 count
    negative_max: int  # 이 창에서 negative 중 하나라도 울리는 최대 count (0 = 전부 조용)
    replays: int


def extract_threshold_seconds(rule_text: str) -> int | None:
    match = _SECONDS_RE.search(rule_text)
    return int(match.group(2)) if match else None


def set_threshold_seconds(rule_text: str, seconds: int) -> str:
    return _SECONDS_RE.sub(lambda m: f"{m.group(1)}{seconds}", rule_text, count=1)


def _largest_firing_count(fires, start: int = 1) -> int:
    """fires(count)가 참인 최대 count (count에 대해 단조 감소라고 가정). fires(start)가 거짓이면 start-1."""
    if not fires(start):
        return start - 1
    low, high = start, start * 2
    while high <= MAX_SEARCH_COUNT and fires(high):
        low, high = high, high * 2
    if high > MAX_SEARCH_COUNT:
        return low
    while high - low > 1:
        mid = (low + high) // 2
        if fires(mid):
            low = mid
        else:
            high = mid
    return low


def find_separating_threshold(
    rule_text: str,
    attack_pcaps: list[str],
    negative_pcaps: list[str],
    suricata_binary: str = "suricata",
    windows: tuple[int, ...] = SEPARATION_WINDOWS,
) -> SeparationResult | None:
    """공격은 울리고 negative는 전부 조용한 (count, seconds)를 재생으로 찾는다. 없으면 None.

    count 1에서도 공격이 안 울리면 임계값이 아니라 매칭 조건(content/flags/방향)이 문제라 None —
    그건 LLM 수리 몫이다.
    """
    original_count = extract_threshold_count(rule_text)
    original_seconds = extract_threshold_seconds(rule_text)
    if not original_count or not original_seconds:
        return None

    replays = 0

    def attack_fires(text: str):
        def _f(count: int) -> bool:
            nonlocal replays
            replays += 1
            return replay_rule(set_threshold_count(text, count), "attack", attack_pcaps, suricata_binary).ok
        return _f

    def negative_fires(text: str):
        def _f(count: int) -> bool:
            nonlocal replays
            replays += 1
            return not replay_rule(set_threshold_count(text, count), "benign", negative_pcaps, suricata_binary).ok
        return _f

    candidates = [original_seconds] + [w for w in windows if w > original_seconds]
    for seconds in dict.fromkeys(candidates):
        text = set_threshold_seconds(rule_text, seconds)
        attack_max = _largest_firing_count(attack_fires(text))
        if attack_max == 0:
            return None  # count 1로도 안 울림 → 임계값 문제가 아님
        negative_max = _largest_firing_count(negative_fires(text))
        if attack_max <= negative_max:
            continue  # 이 창에선 공격이 정상보다 많지 않다 — 더 긴 창을 본다
        count = negative_max + max(1, (attack_max - negative_max + 1) // 2)
        return SeparationResult(
            rule_text=set_threshold_count(text, count), original_count=original_count,
            original_seconds=original_seconds, count=count, seconds=seconds,
            attack_max=attack_max, negative_max=negative_max, replays=replays,
        )
    return None
