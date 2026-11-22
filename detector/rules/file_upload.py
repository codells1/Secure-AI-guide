"""4.3 위험한 형식 파일 업로드 (file_upload): UP-1, UP-2.

`request.files`에서 온 객체의 `.save()`마다, 그보다 먼저 확장자 검사와 Content-Type 검사를
통과했는지(실패 시 중단, 스펙 3.6) 확인한다. 조치가 빠졌는지를 찾는 규칙이다.
"""
import ast

from ..astutil import iter_nodes, keyword_argument, string_value
from ..facts import Conditions
from ..result import Finding
from ..taint import Kind, TaintSpec, find_sink_hits, register
from ..taint.consts import Constants

VULN_ID = "file_upload"

CONTENT_TYPE_ATTRIBUTES = frozenset({"content_type", "mimetype"})


def _save_receivers(source):
    """`.save(...)`를 부르는 대상 식들. 그 대상이 request.files에서 왔는지는 엔진이 알려 준다."""
    for node in iter_nodes(source.tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "save":
            yield node.func.value, "save"


SPEC = register(
    TaintSpec(
        vuln_id=VULN_ID,
        sinks=(),
        source_attributes=frozenset({"flask.request.files"}),
        source_calls=frozenset(),
        url_variables=False,
        probes=_save_receivers,
    )
)


def check(source):
    conditions = Conditions(source)
    consts = Constants(source)
    findings = []
    for hit in find_sink_hits(source, SPEC):
        if not any(part.kind is Kind.TAINTED for value in hit.values for part in value):
            continue  # 업로드된 파일이 아닌 것의 .save()
        # 검사는 저장보다 먼저 있어야 한다. 헬퍼 안에서 저장하면 헬퍼를 호출한 곳의 검사도 인정한다.
        facts = conditions.known_at(hit.node)
        if hit.call_node is not None:
            facts += conditions.known_at(hit.call_node)
        if not any(_passed_extension_check(fact, source, consts) for fact in facts):
            findings.append(Finding(hit.report_line, "UP-1"))
        if not any(_passed_content_type_check(fact, source, consts) for fact in facts):
            findings.append(Finding(hit.report_line, "UP-2"))
    return findings


def _passed_extension_check(fact, source, consts):
    """확장자 화이트리스트 검사를 통과했다는 조건인지.

    `<확장자> in 상수목록`, `<확장자> == 상수`, `파일명.endswith(상수 튜플)`이 참.
    """
    test = fact.test
    if isinstance(test, ast.Call):
        return (
            fact.holds
            and isinstance(test.func, ast.Attribute)
            and test.func.attr == "endswith"
            and len(test.args) == 1
            and not test.keywords
            and consts.is_string_tuple(test.args[0], fact.scope)
        )
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return False
    operator, left, right = test.ops[0], test.left, test.comparators[0]
    if isinstance(operator, (ast.Eq, ast.NotEq)):
        equal = isinstance(operator, ast.Eq) == fact.holds
        return equal and any(
            _is_extension(_definition(subject, fact.scope, source), source)
            and bool(source.static.literal_parts(other, fact.scope))
            for subject, other in ((left, right), (right, left))
        )
    return (
        _membership_holds(operator, fact.holds)
        and _is_extension(_definition(left, fact.scope, source), source)
        and consts.is_allow_list(right, fact.scope)
    )


def _passed_content_type_check(fact, source, consts):
    """Content-Type 검사를 통과했다는 조건인지: `file.content_type`·`file.mimetype`이 상수(목록)와 같다."""
    test = fact.test
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return False
    operator, left, right = test.ops[0], test.left, test.comparators[0]
    if isinstance(operator, (ast.Eq, ast.NotEq)):
        equal = isinstance(operator, ast.Eq) == fact.holds
        return equal and any(
            _is_content_type(_definition(subject, fact.scope, source))
            and source.static.is_static(other, fact.scope)
            for subject, other in ((left, right), (right, left))
        )
    return (
        _membership_holds(operator, fact.holds)
        and _is_content_type(_definition(left, fact.scope, source))
        and consts.is_allow_list(right, fact.scope)
    )


def _membership_holds(operator, holds):
    """`x in 목록`이 참이거나 `x not in 목록`이 거짓인지."""
    if isinstance(operator, ast.In):
        return holds
    if isinstance(operator, ast.NotIn):
        return not holds
    return False


def _definition(node, scope, source):
    """변수면 그 변수에 대입된 식을, 아니면 식 그대로 돌려준다 (`ext = ...` 뒤의 `ext not in ...`)."""
    if isinstance(node, ast.Name):
        return source.static.sole_value(node.id, scope) or node
    return node


def _is_content_type(node):
    return isinstance(node, ast.Attribute) and node.attr in CONTENT_TYPE_ATTRIBUTES


def _is_extension(node, source):
    """파일명의 마지막 확장자를 꺼내는 식인지. `.lower()`는 없어도 된다.

    `X.rsplit(".", 1)[1]`, `X.split(".")[-1]`, `os.path.splitext(X)[1]`
    """
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "lower"
        and not node.args
    ):
        node = node.func.value
    if not isinstance(node, ast.Subscript):
        return False
    index = _index(node.slice)
    split = node.value
    if not isinstance(split, ast.Call):
        return False
    if source.names.resolve(split.func) == "os.path.splitext":
        return index in (1, -1)
    if not (isinstance(split.func, ast.Attribute) and split.args and string_value(split.args[0]) == "."):
        return False
    if split.func.attr == "rsplit":
        limit = split.args[1] if len(split.args) > 1 else keyword_argument(split, "maxsplit")
        return _index(limit) == 1 and index in (1, -1)
    if split.func.attr == "split":
        return len(split.args) == 1 and not split.keywords and index == -1
    return False


def _index(node):
    """정수 리터럴이면 그 값 (`-1` 포함), 아니면 None."""
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _index(node.operand)
        return -value if value is not None else None
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None
