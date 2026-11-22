"""4.1 SQL 삽입 (sql_injection): SQL-1, SQL-2, SQL-3."""
import re

from ..result import Finding
from ..taint import Kind, Sink, TaintSpec, find_sink_hits, register

VULN_ID = "sql_injection"

# 도착점: .execute(), .executemany(), .executescript()의 1번째 인자(쿼리)
SPEC = register(
    TaintSpec(
        vuln_id=VULN_ID,
        sinks=tuple(
            Sink(method=method, arg=0, keywords=("query", "sql", "operation"))
            for method in ("execute", "executemany", "executescript")
        ),
    )
)

# 정렬 예외로 인정하는 값: 상수 dict 매핑, 상수 목록 검사 (스펙 3.6).
# 참/거짓 → 고정 문자열(`"ASC" if … else "DESC"`)은 정적이라 여기까지 오지 않는다 (스펙 3.4).
ORDER_BY_CHOICES = frozenset({"dict_get", "dict_subscript", "guard"})

_ORDER_BY = re.compile(r"\border\s+by\b", re.IGNORECASE)
# ORDER BY 뒤에 이 낱말이 나오면 정렬 절은 끝난 것이다. LIMIT 등 정렬 외 위치의 조립은 예외 없이 위험하다.
_CLAUSE_END = re.compile(
    r"\b(limit|offset|fetch|union|intersect|except|select|from|where|group|having|into|values|set)\b|;",
    re.IGNORECASE,
)


def check(source):
    findings = []
    for hit in find_sink_hits(source, SPEC):
        if hit.call_line is not None and not hit.exact:
            continue  # 매개변수를 섞어 조립하는 헬퍼는 그 함수 안에서 SQL-3으로 판정한다
        findings.extend(_judge(hit))
    return findings


def _judge(hit):
    """쿼리 자리에 올 수 있는 값들을 보고 규칙을 정한다."""
    paths = {}  # rule_id → 처음 찾은 조각의 path
    for value in hit.values:
        prefix = ""  # 지금 조각보다 앞에 있는 리터럴 글자
        for part in value:
            if part.kind is Kind.STATIC:
                prefix += part.text
                continue
            sorting = _in_order_by(prefix)
            if part.kind is Kind.TAINTED:
                rule_id = "SQL-2" if sorting else "SQL-1"
            elif part.kind is Kind.CHOICE and sorting and part.tags & ORDER_BY_CHOICES:
                continue  # 정렬 예외
            else:
                rule_id = "SQL-3"  # 사용자 입력은 아니지만 쿼리가 동적이다
            paths.setdefault(rule_id, hit.path(part))
    if len(paths) > 1:
        paths.pop("SQL-3", None)  # 사용자 입력이 섞였으면 SQL-1·SQL-2로 보고한다
    return [Finding(hit.report_line, rule_id, path) for rule_id, path in paths.items()]


def _in_order_by(prefix):
    """prefix 바로 다음 자리가 ORDER BY 절 안인지."""
    matches = list(_ORDER_BY.finditer(prefix))
    return bool(matches) and not _CLAUSE_END.search(prefix, matches[-1].end())
