"""4.2 서버사이드 템플릿 삽입 (ssti): SSTI-1, SSTI-2, SSTI-3, SSTI-4."""
from ..result import Finding
from ..taint import Kind, Sink, TaintSpec, find_sink_hits, register

VULN_ID = "ssti"

SOURCE = "source"  # 템플릿 원본 문자열을 받는 도착점
NAME = "name"  # 템플릿 파일 이름을 받는 도착점
FILTERED = "template_filter"  # 템플릿 문법을 지우는 필터를 거쳤다는 표시


def _tag_syntax_filter(call):
    """`{{`, `{%` 같은 템플릿 문법을 지우는 호출이면 표시를 붙인다. 필터는 정화로 인정하지 않는다."""
    if call.method == "replace" or call.name == "re.sub":
        pattern = call.texts[0] if call.texts else None
        if pattern and ("{" in pattern or "}" in pattern):
            return frozenset({FILTERED})
    return frozenset()


SPEC = register(
    TaintSpec(
        vuln_id=VULN_ID,
        sinks=(
            Sink(function="flask.render_template_string", arg=0, keywords=("source",), role=SOURCE),
            Sink(function="jinja2.Template", arg=0, keywords=("source",), role=SOURCE),
            Sink(function="flask.render_template", arg=0, keywords=("template_name_or_list",), role=NAME),
        ),
        tagger=_tag_syntax_filter,
    )
)


def check(source):
    findings = []
    for hit in find_sink_hits(source, SPEC):
        if hit.role == SOURCE and hit.call_line is not None and not hit.exact:
            continue  # 매개변수를 섞어 만든 원본은 그 함수 안에서 SSTI-4로 판정한다
        paths = {}  # rule_id → 처음 찾은 조각의 path
        for value in hit.values:
            for part in value:
                rule_id = _rule(hit.role, part)
                if rule_id:
                    paths.setdefault(rule_id, hit.path(part))
        if len(paths) > 1:
            paths.pop("SSTI-4", None)  # 사용자 입력이 섞였으면 SSTI-1·SSTI-3으로 보고한다
        findings.extend(Finding(hit.report_line, rule_id, path) for rule_id, path in paths.items())
    return findings


def _rule(role, part):
    if part.kind is Kind.STATIC:
        return None
    if role == NAME:
        # 사용자 입력으로 템플릿 이름을 고르면 위험하다.
        # 상수 dict 매핑이나 상수 목록 검사(스펙 3.6)를 거친 값은 '고정 선택'이라 제외된다.
        return "SSTI-2" if part.kind is Kind.TAINTED else None
    if part.kind is Kind.TAINTED:
        return "SSTI-3" if FILTERED in part.tags else "SSTI-1"
    return "SSTI-4"  # 사용자 입력은 아니지만 템플릿 원본이 동적이다
