"""수정 묶음 만들기와 target_range 계산 (fix_spec 2.1, 6.2).

학생 코드는 ast로 읽기만 하고 실행하지 않는다.
"""
import ast
from dataclasses import dataclass

from detector.result import VULNERABLE

MODULE = "<module>"
# 주석에서 나오는 규칙. 주석은 AST에 없으므로 범위는 그 줄 하나다.
COMMENT_RULES = frozenset({"KEY-4"})
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass(frozen=True)
class Group:
    """한 번에 고칠 finding 묶음: 같은 vuln_id + 같은 target_range."""

    group_id: str  # "vuln_id:시작-끝"
    vuln_id: str
    rule_ids: tuple
    findings: tuple  # analyze()가 준 finding 그대로 (rule_id, line, path, message)
    target_range: tuple  # (시작 줄, 끝 줄). 1부터 세고 양 끝을 포함한다
    function_name: str  # 함수 밖이면 "<module>"

    def to_dict(self):
        return {
            "group_id": self.group_id,
            "vuln_id": self.vuln_id,
            "rule_ids": list(self.rule_ids),
            "findings": [dict(finding) for finding in self.findings],
            "target_range": list(self.target_range),
            "function_name": self.function_name,
        }


def normalize(code):
    """탐지 모듈(detector.source.parse_source)과 같은 방식으로 줄바꿈을 맞춘다.

    이렇게 읽어야 줄 번호가 analyze()가 돌려준 줄 번호와 같다.
    """
    return code.removeprefix("﻿").replace("\r\n", "\n").replace("\r", "\n")


def split_lines(code):
    return normalize(code).split("\n")


def range_text(code, span):
    """코드에서 (시작 줄, 끝 줄) 범위의 원문. 줄 번호는 붙이지 않는다. 빈 범위면 빈 문자열."""
    start, end = span
    return "\n".join(split_lines(code)[start - 1:end])


def parse(code):
    try:
        return ast.parse(normalize(code))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # 오류 내용에는 학생 코드가 섞일 수 있으므로 이어 붙이지 않는다.
        raise ValueError("코드를 해석할 수 없습니다.") from None


def target_range(code, line, rule_id):
    """finding 한 줄을 고칠 때 바꿔 쓸 범위 (시작 줄, 끝 줄).

    - 그 줄을 포함하는 가장 안쪽 함수. 데코레이터가 있으면 첫 데코레이터 줄부터다.
    - 함수 밖이면 그 줄을 포함하는 최상위 문장 전체.
    - 주석 규칙(KEY-4)은 그 줄 하나.
    """
    return _target_range(parse(code), len(split_lines(code)), line, rule_id)


def function_name(code, line):
    """그 줄을 포함하는 가장 안쪽 함수의 이름. 함수 밖이면 "<module>"."""
    return _function_name(parse(code), line)


def make_groups(analyze_result, code):
    """analyze() 결과의 "위험" finding을 수정 묶음으로 묶는다. 같은 입력이면 같은 순서다."""
    if not analyze_result.get("ok"):
        return []
    tree = parse(code)
    line_count = len(split_lines(code))
    members = {}  # (vuln_id, target_range) → finding 목록. 넣은 순서가 유지된다
    for result in analyze_result["results"]:
        if result["verdict"] != VULNERABLE:
            continue
        for finding in result["findings"]:
            span = _target_range(tree, line_count, finding["line"], finding["rule_id"])
            members.setdefault((result["vuln_id"], span), []).append(finding)
    groups = [_group(tree, vuln_id, span, findings) for (vuln_id, span), findings in members.items()]
    # 시작 줄 순서. 범위가 같으면 analyze()의 취약점 순서 그대로다 (sorted는 순서를 유지한다).
    return sorted(groups, key=lambda group: group.target_range)


def _group(tree, vuln_id, span, findings):
    ordered = sorted(findings, key=lambda finding: (finding["line"], finding["rule_id"]))
    return Group(
        group_id=f"{vuln_id}:{span[0]}-{span[1]}",
        vuln_id=vuln_id,
        rule_ids=tuple(dict.fromkeys(finding["rule_id"] for finding in ordered)),
        findings=tuple(ordered),
        target_range=span,
        function_name=_function_name(tree, ordered[0]["line"]),
    )


def _target_range(tree, line_count, line, rule_id):
    if type(line) is not int or not 1 <= line <= line_count:
        raise ValueError("finding 줄 번호가 코드 범위를 벗어났습니다.")
    if rule_id in COMMENT_RULES:
        return line, line
    function = _innermost_function(tree, line)
    if function is not None:
        return _first_line(function), function.end_lineno
    for statement in tree.body:
        if _first_line(statement) <= line <= statement.end_lineno:
            return _first_line(statement), statement.end_lineno
    return line, line


def _function_name(tree, line):
    function = _innermost_function(tree, line)
    return function.name if function is not None else MODULE


def _innermost_function(tree, line):
    best = None
    for node in ast.walk(tree):
        if isinstance(node, _FUNCTIONS) and _first_line(node) <= line <= node.end_lineno:
            if best is None or _length(node) < _length(best):
                best = node
    return best


def _first_line(node):
    """데코레이터가 붙어 있으면 첫 데코레이터 줄, 아니면 문장이 시작하는 줄."""
    return min([node.lineno] + [decorator.lineno for decorator in getattr(node, "decorator_list", [])])


def _length(node):
    return node.end_lineno - _first_line(node)
