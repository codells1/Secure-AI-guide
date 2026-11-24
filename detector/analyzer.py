"""탐지 모듈 진입점 (스펙 5장, 6장)."""
from .result import vuln_result
from .rules import RULES
from .source import SourceSyntaxError, parse_source


def analyze(code: str, user_input: dict | None = None) -> dict:
    """Flask 소스 문자열을 읽어 취약점 10종의 판정을 돌려준다. 코드는 실행하지 않는다.

    - 1차 호출 `analyze(code)`: 학생에게 물어야 판정할 수 있는 항목은 `verdict: None`과 질문을 돌려준다.
    - 2차 호출 `analyze(code, user_input)`: 응답을 받아 판정한다.
    """
    try:
        source = parse_source(code)
    except SourceSyntaxError as error:
        return {"ok": False, "error": {"line": error.line, "message": error.message}}
    answers = user_input if isinstance(user_input, dict) else {}
    return {"ok": True, "results": [_result(rule, source, answers) for rule in RULES]}


def _result(rule, source, answers):
    if hasattr(rule, "evaluate"):
        findings, needs_user_input = rule.evaluate(source, answers)
    else:
        findings, needs_user_input = rule.check(source), None
    # 확인 표시는 판정을 바꾸지 않는다. 위험일 때만 붙인다.
    is_acknowledged = getattr(rule, "is_acknowledged", None)
    acknowledged = bool(findings) and is_acknowledged is not None and is_acknowledged(answers)
    return vuln_result(rule.VULN_ID, findings, acknowledged, needs_user_input)
