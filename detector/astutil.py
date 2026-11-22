"""여러 모듈이 같이 쓰는 AST 도우미. 학생 코드는 읽기만 한다."""
import ast

FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def iter_nodes(root):
    """root와 그 아래 모든 노드를 항상 같은 순서(깊이 우선, 필드 순서)로 돌려준다.

    ast.walk는 순서를 보장하지 않아 쓰지 않는다 (C4).
    """
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def iter_own_nodes(function):
    """함수 본문의 노드들. 안쪽에 정의된 함수·클래스의 본문은 다른 스코프라 들어가지 않는다."""
    stack = list(reversed(function.body))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (*FUNCTION_NODES, ast.ClassDef, ast.Lambda)):
            stack.extend(reversed(list(ast.iter_child_nodes(node))))


def iter_nodes_with_scope(tree):
    """(노드, 그 노드가 속한 함수 또는 None)을 iter_nodes와 같은 순서로 돌려준다."""
    stack = [(tree, None)]
    while stack:
        node, scope = stack.pop()
        yield node, scope
        children = list(ast.iter_child_nodes(node))
        if isinstance(node, FUNCTION_NODES):
            # 본문만 그 함수 안이다. 데코레이터와 매개변수 기본값은 바깥에서 계산된다.
            body = {id(statement) for statement in node.body}
            pairs = [(child, node if id(child) in body else scope) for child in children]
        else:
            pairs = [(child, scope) for child in children]
        stack.extend(reversed(pairs))


def string_value(node):
    """문자열 리터럴이면 그 값, 아니면 None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def keyword_argument(call, name):
    """호출에서 name 키워드 인자의 값 노드를 돌려준다. 없으면 None."""
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def call_argument(call, index, name):
    """호출에서 index번째 위치 인자 또는 name 키워드 인자의 값 노드를 돌려준다. 없으면 None."""
    positional = call.args[: index + 1]
    if len(positional) > index and not any(isinstance(arg, ast.Starred) for arg in positional):
        return positional[index]
    return keyword_argument(call, name)


def added_operands(node):
    """`a + b + c`를 [a, b, c]로 푼다. 길게 이어 붙인 식에서 재귀가 깊어지지 않게 반복문으로 푼다."""
    operands = []
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        operands.append(node.right)
        node = node.left
    operands.append(node)
    operands.reverse()
    return operands


def is_call_on(node, owners, methods):
    """node가 `owner.method(...)` 호출이고 owner가 owners의 이름, method가 methods 중 하나인지."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in methods
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in owners
    )


def assignment_pairs(node):
    """대입문을 (대상, 값) 쌍으로 푼다. 대입문이 아니면 빈 목록.

    `a, b = "x", "y"`는 (a, "x"), (b, "y") 두 쌍이 된다.
    짝을 지을 수 없으면(`a, b = pair`) 대상마다 값 전체를 짝짓는다.
    """
    if isinstance(node, ast.Assign):
        pairs = []
        for target in node.targets:
            _unpack(target, node.value, pairs)
        return pairs
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return [(node.target, node.value)]
    return []


def _unpack(target, value, pairs):
    if isinstance(target, ast.Starred):
        target = target.value
    if not isinstance(target, (ast.Tuple, ast.List)):
        pairs.append((target, value))
        return
    values = [value] * len(target.elts)
    if (
        isinstance(value, (ast.Tuple, ast.List))
        and len(value.elts) == len(target.elts)
        and not any(isinstance(element, ast.Starred) for element in target.elts + value.elts)
    ):
        values = value.elts
    for element, element_value in zip(target.elts, values):
        _unpack(element, element_value, pairs)
