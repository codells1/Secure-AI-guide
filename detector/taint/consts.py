"""상수 목록·상수 dict 찾기 (고정 선택 값 판단에 쓴다)."""
import ast

from ..astutil import iter_nodes

# 내용을 바꾸는 메서드. 한 번이라도 불리면 상수로 보지 않는다.
MUTATORS = frozenset({
    "append", "extend", "insert", "add", "update", "setdefault",
    "pop", "popitem", "remove", "discard", "clear", "sort", "reverse",
})


class Constants:
    def __init__(self, source):
        self._static = source.static
        self._changed = _changed_names(source.tree)

    def is_string_list(self, node, scope):
        """node가 문자열 상수만 든 목록(튜플·리스트·집합)이거나 그것에 붙인 이름인지."""
        definition = self._definition(node, scope)
        return (
            isinstance(definition, (ast.Tuple, ast.List, ast.Set))
            and bool(definition.elts)
            and all(self._static.literal_parts(element, scope) for element in definition.elts)
        )

    def is_string_tuple(self, node, scope):
        """node가 문자열 상수만 든 튜플이거나 그것에 붙인 이름인지 (`endswith()`에 넣는 값)."""
        return self.is_string_list(node, scope) and isinstance(self._definition(node, scope), ast.Tuple)

    def is_allow_list(self, node, scope):
        """스펙 3.6의 상수 목록: 문자열 상수 목록, 또는 키를 검사하는 상수 dict."""
        if self.is_string_list(node, scope):
            return True
        return self.is_string_dict(node, scope) and all(
            self._static.literal_parts(key, scope) for key in self._definition(node, scope).keys
        )

    def is_string_dict(self, node, scope):
        """node가 값이 모두 문자열 상수인 dict이거나 그것에 붙인 이름인지."""
        definition = self._definition(node, scope)
        return (
            isinstance(definition, ast.Dict)
            and bool(definition.keys)
            and all(key is not None for key in definition.keys)
            and all(self._static.is_static(value, scope) for value in definition.values)
        )

    def is_fixed_get(self, call, scope):
        """`COLS.get(x, "고정값")`: 상수 dict에서 꺼내고, 없을 때 쓰는 값도 고정."""
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "get"
            and len(call.args) == 2
            and not call.keywords
            and self.is_string_dict(call.func.value, scope)
            and self._static.is_static(call.args[1], scope)
        )

    def _definition(self, node, scope):
        if not isinstance(node, ast.Name):
            return node
        if node.id in self._changed:
            return None
        return self._static.sole_value(node.id, scope)


def _changed_names(tree):
    """첨자 대입·삭제나 내용을 바꾸는 메서드 호출의 대상이 된 이름들."""
    changed = set()
    for node in iter_nodes(tree):
        if isinstance(node, ast.Subscript) and not isinstance(node.ctx, ast.Load):
            target = node.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in MUTATORS
        ):
            target = node.func.value
        else:
            continue
        if isinstance(target, ast.Name):
            changed.add(target.id)
    return changed
