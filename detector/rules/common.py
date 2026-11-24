"""규칙들이 같이 쓰는 도우미."""
import ast

from ..result import Finding
from ..values import EXTERNAL


def externals(value, deep=True):
    """값에 든 외부 입력값 조각들 (출발 순서대로)."""
    if value is None:
        return []
    return sorted((taint for taint in value.taints(deep) if taint.has(EXTERNAL)), key=lambda t: (t.origin, t.part))


def covered(taint, facts, kinds=("allow",)):
    """그 지점에서 통과한 검사(허용 목록·형식)가 이 값을 덮는지 (스펙 3.2).

    값 전체를 검사했다면 거기서 떼어 낸 조각도 덮지만, 조각만 검사했다면 값 전체는 덮지 않는다.
    """
    parts = {taint.part, ""}
    if taint.part in ("ext", "stem"):
        parts.add("filename")
    return any(("v", kind, taint.origin, part) in facts for kind in kinds for part in parts)


def flow_finding(program, event, taint, rule_id):
    line = program.report_line(event, taint)
    return Finding(line, rule_id, program.path(taint, line))


def is_builtin_call(event, name):
    """`open(...)`처럼 import 없이 쓰는 내장 함수 호출인지."""
    func = event.node.func
    return event.name is None and isinstance(func, ast.Name) and func.id == name
