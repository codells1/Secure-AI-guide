"""import 별칭과 Flask 객체 이름 (스펙 3.5 별칭 처리)."""
import ast

from .astutil import FUNCTION_NODES, assignment_pairs, iter_nodes, iter_own_nodes

# 스펙의 예시가 모두 `app.…` 형태라서, Flask(...) 대입이 보이지 않아도 app은 Flask 객체로 본다.
DEFAULT_APP_NAME = "app"
# 요청 처리를 중단하는 호출. import 없이 `abort(...)`라고만 쓴 것도 포함한다.
ABORT_CALLS = frozenset({"flask.abort", "abort"})


class Names:
    """`import traceback as tb` 같은 별칭을 원래 이름으로 되돌리고, Flask 객체 이름을 모아 둔다."""

    def __init__(self, tree):
        nodes = list(iter_nodes(tree))
        self._aliases = {}
        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self._aliases[alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for alias in node.names:
                    if alias.name != "*":
                        self._aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

        app_names = {DEFAULT_APP_NAME}
        blueprint_names = set()
        assigned_calls = [
            (target.id, value)
            for node in nodes
            for target, value in assignment_pairs(node)
            if isinstance(target, ast.Name) and isinstance(value, ast.Call)
        ]
        for name, call in assigned_calls:
            created = self.resolve(call.func)
            if created == "flask.Flask":
                app_names.add(name)
            elif created == "flask.Blueprint":
                blueprint_names.add(name)
        # 같은 파일의 함수가 돌려준 Flask 객체도 인식한다 (`application = create_app()`, 1단계).
        factories = {
            node.name for node in tree.body if isinstance(node, FUNCTION_NODES) and self._returns_flask(node)
        }
        app_names.update(
            name for name, call in assigned_calls if isinstance(call.func, ast.Name) and call.func.id in factories
        )
        self.app_names = frozenset(app_names)
        self.blueprint_names = frozenset(blueprint_names)

    def _returns_flask(self, function):
        """함수가 `Flask(...)`로 만든 객체를 돌려주는지."""
        created = {
            target.id
            for node in iter_own_nodes(function)
            for target, value in assignment_pairs(node)
            if isinstance(target, ast.Name) and self._is_flask_call(value)
        }
        return any(
            isinstance(node, ast.Return)
            and (self._is_flask_call(node.value) or (isinstance(node.value, ast.Name) and node.value.id in created))
            for node in iter_own_nodes(function)
        )

    def _is_flask_call(self, node):
        return isinstance(node, ast.Call) and self.resolve(node.func) == "flask.Flask"

    def resolve(self, node):
        """`tb.print_exc` 같은 이름·속성 접근을 import 기준의 원래 이름으로 바꾼다.

        예: "traceback.print_exc". import가 없으면 적힌 이름 그대로, 이름·속성 접근이 아니면 None.
        """
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(self._aliases.get(node.id, node.id))
        return ".".join(reversed(parts))

    def is_app(self, node):
        """node가 Flask 객체 이름(`app`)인지."""
        return isinstance(node, ast.Name) and node.id in self.app_names

    def is_app_config(self, node):
        """node가 `app.config`인지."""
        return isinstance(node, ast.Attribute) and node.attr == "config" and self.is_app(node.value)
