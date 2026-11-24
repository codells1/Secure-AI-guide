"""4.5 부적절한 인가 / IDOR (idor): IDOR-1 ~ IDOR-4.

라우트 함수가 URL 변수나 id류 요청값으로 DB의 대상을 골라 조회·수정·삭제하는데 권한 확인이 없으면,
먼저 학생에게 본인만 봐야 하는 페이지인지 묻고(스펙 5.1), 그렇다고 답한 라우트만 위험으로 판정한다.
"""
import ast
import re

from ..result import Finding
from ..values import EXTERNAL
from ..words import is_id_key, is_identity_key, is_password_name

VULN_ID = "idor"
QUESTION = "이 페이지에 나오는 정보는 로그인한 본인만 봐야 하나요?"

EXECUTE_METHODS = frozenset({"execute", "executemany"})
ORM_LOOKUPS = frozenset({"get", "filter_by", "filter", "where", "get_or_404", "first_or_404"})
# 권한을 확인했다고 인정하는 것: 본인 확인, 관리자 확인, 대상에 걸린 비밀번호 확인 (스펙 4.5)
STRONG = frozenset({("authz", "owner"), ("authz", "admin"), ("authz", "credential")})
WEAK = (("bad", "IDOR-3"), ("role", "IDOR-4"), ("login", "IDOR-2"))
_INSERT = re.compile(r"\s*insert\b", re.IGNORECASE)


def evaluate(source, user_input):
    """(findings, needs_user_input)을 돌려준다. needs_user_input이 있으면 아직 판정하지 않은 것이다."""
    candidates = _candidates(source)
    if not candidates:
        return [], None
    answer = user_input.get(VULN_ID)
    listed = answer.get("public_functions") if isinstance(answer, dict) else None
    if not isinstance(listed, list):
        routes = [{"function": route.name, "route": route.rule, "line": route.line} for route, _, _ in candidates]
        return [], {"type": "idor_routes", "question": QUESTION, "routes": routes}
    return [Finding(line, rule_id) for route, line, rule_id in candidates if route.name not in listed], None


def _candidates(source):
    """보호되지 않은 후보 라우트: (라우트, 보고할 줄, 규칙)."""
    program = source.flow
    found = []
    for route in program.routes:
        fn = route.fn
        reads_password = _reads_password(fn)
        facts, open_lines = set(), []
        for event in program.calls:
            if event.entry is not fn:
                continue
            facts |= event.facts
            values = _lookup_values(program, event)
            if values is None:
                continue
            if not any(_selects(taint, reads_password) for value in values for taint in value.taints()):
                continue
            if not any(value.has_mark("session", deep=True) for value in values):
                open_lines.append(event.entry_line)  # 조회 조건에 세션 사용자가 없다
        for events in (program.returns, program.assigns, program.compares):
            for event in events:
                if event.entry is fn:
                    facts |= event.facts
        if not open_lines or facts & STRONG:
            continue
        rule_id = next((rule for kind, rule in WEAK if ("authz", kind) in facts), "IDOR-1")
        found.append((route, min(open_lines), rule_id))
    return found


def _lookup_values(program, event):
    """이 호출이 DB에서 대상을 고르는 자리면 조건에 쓰인 값들, 아니면 None."""
    if event.method in EXECUTE_METHODS:
        if event.args and any(_INSERT.match(prefix) for prefix in event.args[0].static_prefix()):
            return None  # 새로 넣는 문장은 이미 있는 대상을 고르지 않는다
        return [*event.args, *event.kwargs.values()]
    if event.method in ORM_LOOKUPS and _is_orm(event.node.func):
        values = [*event.args, *event.kwargs.values()]
        for argument in event.node.args:  # filter(Post.id == post_id)처럼 비교식 안에 든 값
            for inner in ast.walk(argument):
                value = program.value(inner)
                if value is not None:
                    values.append(value)
        return values
    return None


def _is_orm(func):
    names = []
    node = func.value
    while isinstance(node, (ast.Attribute, ast.Call)):
        if isinstance(node, ast.Attribute):
            names.append(node.attr)
            node = node.value
        else:
            node = node.func
    return "query" in names or "session" in names


def _selects(taint, reads_password):
    """대상을 고르는 값인지: URL 변수이거나 id류 키의 요청값."""
    if not taint.has(EXTERNAL):
        return False
    if taint.urlvar or is_id_key(taint.key):
        return True
    # 아이디·이메일로 찾는 것도 해당하지만, 비밀번호를 함께 읽는 함수(로그인·가입)는 후보가 아니다
    return is_identity_key(taint.key) and not reads_password


def _reads_password(fn):
    return any(
        isinstance(node, ast.Constant) and isinstance(node.value, str) and is_password_name(node.value)
        for node in ast.walk(fn)
    )
