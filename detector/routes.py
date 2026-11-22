"""라우트 인식 (스펙 3.5).

`@app.route`, `@app.get`/`@app.post` 등, Blueprint의 같은 데코레이터, `add_url_rule`을 찾는다.
"""
import ast
from dataclasses import dataclass

from .astutil import FUNCTION_NODES, call_argument, is_call_on, iter_nodes, string_value

ROUTE_DECORATORS = frozenset({"route", "get", "post", "put", "delete", "patch"})
ADD_URL_RULE = frozenset({"add_url_rule"})


@dataclass(frozen=True)
class Route:
    path: str | None  # URL 규칙. 문자열 리터럴이 아니면 None
    func_name: str | None
    func: ast.FunctionDef | ast.AsyncFunctionDef | None  # 같은 파일에서 찾지 못하면 None
    line: int  # 데코레이터 또는 add_url_rule 호출이 있는 줄


def find_routes(source) -> list[Route]:
    """파일 안의 라우트를 줄 순서대로 돌려준다."""
    owners = source.names.app_names | source.names.blueprint_names
    nodes = list(iter_nodes(source.tree))
    functions = {}
    for node in nodes:
        if isinstance(node, FUNCTION_NODES):
            functions.setdefault(node.name, node)

    routes = []
    for node in nodes:
        if isinstance(node, FUNCTION_NODES):
            for decorator in node.decorator_list:
                if is_call_on(decorator, owners, ROUTE_DECORATORS):
                    routes.append(Route(_rule(decorator), node.name, node, decorator.lineno))
        elif is_call_on(node, owners, ADD_URL_RULE):
            # add_url_rule(rule, endpoint=None, view_func=None)
            view = call_argument(node, 2, "view_func")
            name = view.id if isinstance(view, ast.Name) else None
            routes.append(Route(_rule(node), name, functions.get(name), node.lineno))
    return sorted(routes, key=lambda route: route.line)


def _rule(call):
    return string_value(call_argument(call, 0, "rule"))
