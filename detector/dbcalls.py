"""DB 호출을 알아보는 도우미 (비밀번호 저장, IDOR 규칙이 같이 쓴다)."""
import ast

from .astutil import call_argument

EXECUTE_METHODS = frozenset({"execute", "executemany"})


def is_execute(node):
    """`cur.execute(...)`, `conn.executemany(...)` 형태의 호출인지."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in EXECUTE_METHODS
    )


def query_and_parameters(call):
    """execute 호출의 (쿼리 식, 바인딩 값 식). 없으면 None."""
    query = call_argument(call, 0, "query")
    parameters = call_argument(call, 1, "args") or call_argument(call, 1, "parameters")
    return query, parameters


def binding_elements(parameters):
    """바인딩 값을 하나씩: 튜플·리스트·dict 리터럴이면 원소마다, 아니면 식 전체."""
    if parameters is None:
        return []
    if isinstance(parameters, (ast.Tuple, ast.List)):
        return parameters.elts
    if isinstance(parameters, ast.Dict):
        return parameters.values
    return [parameters]
