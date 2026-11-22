"""오염 분석이 다루는 값의 표현.

식 하나의 값은 조각(Part)을 왼쪽에서 오른쪽으로 늘어놓은 것이다.
`if/else`처럼 길이 갈리면 값이 여러 개일 수 있어서, 식을 계산한 결과는 "값들의 묶음"이다.
"""
import enum
from dataclasses import dataclass, replace
from itertools import product

MAX_ALTERNATIVES = 16
SANITIZED = "sanitized"  # 정화 함수를 거친 값에 붙는 표시


class Kind(enum.Enum):
    STATIC = "정적"  # 문자열 리터럴 (스펙 3.4)
    CHOICE = "고정 선택"  # 정해 둔 상수 중 하나
    UNKNOWN = "모름"  # DB에서 꺼낸 값, 출처를 모르는 값
    PARAM = "매개변수"  # 라우트 URL 변수가 아닌 함수 매개변수
    TAINTED = "오염"  # 출발점(사용자 입력)에서 온 값


@dataclass(frozen=True)
class Part:
    kind: Kind
    text: str = ""  # STATIC일 때의 글자
    trail: tuple = ()  # 이 조각이 거쳐 온 줄 번호 (path용)
    tags: frozenset = frozenset()  # CHOICE의 종류, 또는 취약점 모듈이 붙인 표시


def static(text):
    return ((Part(Kind.STATIC, text=text),),)


def single(kind, line=None, tags=()):
    """조각 하나짜리 값 하나."""
    trail = () if line is None else (line,)
    return ((Part(kind, trail=trail, tags=frozenset(tags)),),)


def merge(*groups):
    """갈 수 있는 길의 값들을 모두 모은다."""
    return _limit(value for group in groups for value in group)


def concat(*groups):
    """값들을 이어 붙인다. 길이 갈려 있으면 모든 조합을 만든다."""
    result = static("")
    for group in groups:
        result = _limit(_tidy(left + right) for left, right in product(result, group))
    return result


def collapse(groups, line, keep=frozenset()):
    """여러 값이 섞여 만들어진 결과: 오염된 값이 하나라도 섞였으면 오염, 아니면 모름.

    어느 쪽이든 바탕이 된 값이 거쳐 온 줄과, 표시 가운데 keep에 든 것은 이어받는다.
    """
    merged = merge(*groups)
    origin = first_part(merged, Kind.TAINTED)
    kind = Kind.TAINTED
    if origin is None:
        kind = Kind.UNKNOWN
        origin = next((part for value in merged for part in value if part.kind is not Kind.STATIC), None)
    trail = origin.trail if origin is not None else ()
    tags = origin.tags & keep if origin is not None else frozenset()
    return add_line(((Part(kind, trail=trail, tags=tags),),), line)


def add_line(group, line):
    """값이 이 줄을 거쳐 갔다고 적는다. 리터럴 조각에는 적지 않는다."""
    return tuple(tuple(_visited(part, line) for part in value) for value in group)


def first_part(group, kind):
    for value in group:
        for part in value:
            if part.kind is kind:
                return part
    return None


def is_all_static(group):
    return all(part.kind is Kind.STATIC for value in group for part in value)


def static_text(group):
    """값이 하나뿐이고 전부 리터럴이면 그 글자, 아니면 None."""
    if len(group) == 1 and is_all_static(group):
        return "".join(part.text for part in group[0])
    return None


def _visited(part, line):
    if line is None or part.kind is Kind.STATIC or line in part.trail:
        return part
    return replace(part, trail=part.trail + (line,))


def _tidy(value):
    """이웃한 리터럴 조각을 하나로 합치고, 빈 리터럴은 뺀다."""
    parts = []
    for part in value:
        if part.kind is Kind.STATIC and not part.text:
            continue
        if part.kind is Kind.STATIC and parts and parts[-1].kind is Kind.STATIC:
            parts[-1] = Part(Kind.STATIC, text=parts[-1].text + part.text)
        else:
            parts.append(part)
    return tuple(parts) if parts else (Part(Kind.STATIC),)


def _limit(values):
    """같은 값은 한 번만 남기고, 너무 많이 갈리면 가장 나쁜 경우 하나로 뭉친다."""
    unique = tuple(dict.fromkeys(values))
    if len(unique) <= MAX_ALTERNATIVES:
        return unique
    parts = [part for value in unique for part in value]
    tainted = [part for part in parts if part.kind is Kind.TAINTED]
    if tainted:
        tags = frozenset.intersection(*(part.tags for part in tainted))
        return ((Part(Kind.TAINTED, trail=tainted[0].trail, tags=tags),),)
    if all(part.kind is Kind.STATIC for part in parts):
        return ((Part(Kind.STATIC),),)  # 정적이지만 글자는 알 수 없다
    return ((Part(Kind.UNKNOWN),),)
