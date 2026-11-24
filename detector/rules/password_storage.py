"""4.9 평문·약한 해시 비밀번호 저장 (password_storage): PW-1 ~ PW-5.

비밀번호 값이 저장 자리에 도착할 때까지 어떤 처리를 거쳤는지 본다. 처리 결과는 models.py가 값에 적어 둔다.
"""
import ast
import re

from ..result import Finding
from ..values import PASSWORD
from ..words import is_password_name

VULN_ID = "password_storage"

EXECUTE_METHODS = frozenset({"execute", "executemany"})
PARAMETER_KEYWORDS = ("parameters", "params", "args", "seq_of_parameters")
_STORING = re.compile(r"\s*(?:insert|update|replace)\b", re.IGNORECASE)


def check(source):
    program = source.flow
    findings = []
    for event in program.calls:
        if event.method in EXECUTE_METHODS and event.args:
            query = event.args[0]
            if not any(_STORING.match(prefix) for prefix in query.static_prefix()):
                continue  # 저장하는 문장(INSERT·UPDATE·REPLACE)이 아니다
            stored = [query]
            if len(event.args) > 1:
                stored.append(event.args[1])
            stored += [event.kwargs[keyword] for keyword in PARAMETER_KEYWORDS if keyword in event.kwargs]
            for value in stored:
                for taint in _passwords(value):
                    line = program.report_line(event, taint)
                    findings.append(Finding(line, _rule(taint), program.path(taint, line)))
        elif event.method is None and event.instance and event.instance.startswith("<local>."):
            # 같은 파일에 정의된 클래스의 생성 인자: User(password=pw)
            for name, value in event.kwargs.items():
                if is_password_name(name):
                    findings.extend(_stored(program, event, value))
    for event in program.assigns:
        target = event.target
        if isinstance(target, ast.Attribute):
            if is_password_name(target.attr):
                findings.extend(_stored(program, event, event.value))  # user.password = pw
        elif _is_global_store(program, target):
            findings.extend(_stored(program, event, event.value))  # users[name] = {"password": pw}
    return findings


def _passwords(value):
    return sorted((taint for taint in value.taints() if taint.has(PASSWORD)), key=lambda t: (t.origin, t.state))


def _stored(program, event, value):
    findings = []
    for taint in _passwords(value):
        line = program.report_line(event, taint)
        findings.append(Finding(line, _rule(taint), program.path(taint, line)))
    return findings


def _rule(taint):
    """해시를 거치며 적힌 규칙이 있으면 그 규칙, 없으면 해시 없이 저장한 것이다."""
    return taint.state or "PW-1"


def _is_global_store(program, target):
    """모듈 최상위에 두고 내용을 바꿔 쓰는 dict·list에 넣는 자리인지."""
    node = target.value if isinstance(target, ast.Subscript) else target
    return isinstance(node, ast.Name) and node.id in program.mutated and node.id in program.module_names
