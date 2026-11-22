"""정적 문자열 판단 (스펙 3.4).

문자열 리터럴, 정적 문자열끼리만 이어 붙인 것(+, f-string, %, .format()),
정적 문자열만 대입된 이름(함수 안 또는 모듈 최상위)은 정적이다.
숫자·True·False·None 리터럴, 양쪽이 정적인 삼항식, `sqlalchemy.text(정적 문자열)`도 정적이다.
그 밖의 값이 섞이면 동적이다.
"""
import ast

from .astutil import FUNCTION_NODES, added_operands, assignment_pairs, iter_nodes

STATIC_TEXT_CALL = "sqlalchemy.text"


class _Scope:
    """스코프 하나(모듈 최상위 또는 함수 하나)의 이름 대입 기록."""

    def __init__(self):
        self.values = {}  # 이름 → [(대입된 값 노드, 그 값을 계산하는 함수 또는 None)]
        self.dynamic = set()  # 매개변수, for 변수, import 등 정적 문자열일 수 없는 이름


class StaticStrings:
    def __init__(self, tree, names):
        self._names = names
        self._module = _Scope()
        self._functions = {}
        functions = [node for node in iter_nodes(tree) if isinstance(node, FUNCTION_NODES)]
        for function in functions:
            scope = self._functions[function] = _Scope()
            scope.dynamic.update(_parameter_names(function.args))
        self._record(tree.body, self._module, None)
        for function in functions:
            self._record(function.body, self._functions[function], function)

    def is_static(self, node, scope=None):
        """node가 정적 문자열인지. scope는 node가 속한 함수(모듈 최상위면 None)."""
        return self.literal_parts(node, scope) is not None

    def literal_parts(self, node, scope=None):
        """정적이면 그것을 이루는 문자열·bytes 조각들을, 동적이면 None을 돌려준다.

        숫자·True·False·None은 정적이지만 글자 조각으로 세지 않으므로, 이것들만 있으면 빈 목록이다.
        """
        return self._parts(node, scope, frozenset())

    def _record(self, body, scope, function):
        bindings, global_names = _scan(body)
        for name, value in bindings:
            # 함수 안에서 global로 선언한 이름은 모듈 최상위 이름이다.
            target = self._module if name in global_names else scope
            if value is None:
                target.dynamic.add(name)
            else:
                target.values.setdefault(name, []).append((value, function))

    def _parts(self, node, scope, resolving):
        if isinstance(node, ast.Constant):
            return [node.value] if isinstance(node.value, (str, bytes)) else []
        if is_negative_number(node):
            return []
        if isinstance(node, ast.IfExp):
            return self._all_parts([node.body, node.orelse], scope, resolving)
        if (
            isinstance(node, ast.Call)
            and self._names.resolve(node.func) == STATIC_TEXT_CALL
            and len(node.args) == 1
            and not node.keywords
        ):
            return self._parts(node.args[0], scope, resolving)
        if isinstance(node, ast.JoinedStr):
            return self._all_parts(node.values, scope, resolving)
        if isinstance(node, ast.FormattedValue):
            pieces = [node.value] if node.format_spec is None else [node.value, node.format_spec]
            return self._all_parts(pieces, scope, resolving)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._all_parts(added_operands(node), scope, resolving)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            right = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
            return self._all_parts([node.left, *right], scope, resolving)
        if _is_format_call(node):
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            return self._all_parts([node.func.value, *arguments], scope, resolving)
        if isinstance(node, ast.Name):
            return self._name_parts(node.id, scope, resolving)
        return None

    def _all_parts(self, nodes, scope, resolving):
        parts = []
        for node in nodes:
            node_parts = self._parts(node, scope, resolving)
            if node_parts is None:
                return None
            parts.extend(node_parts)
        return parts

    def sole_value(self, name, scope=None):
        """name에 대입된 값이 딱 하나면 그 값 노드를, 아니면 None을 돌려준다 (상수 목록·dict 찾기용)."""
        table = self._table_for(name, scope)
        values = table.values.get(name, ())
        if name in table.dynamic or len(values) != 1:
            return None
        return values[0][0]

    def is_module_name(self, name):
        """name이 모듈 최상위에서 바인딩된 이름(변수, import, 함수, 클래스)인지."""
        return name in self._module.values or name in self._module.dynamic

    def is_module_variable(self, name):
        """name이 모듈 최상위에서 값을 대입받은 변수인지 (import, 함수, 클래스는 제외)."""
        return name in self._module.values

    def _table_for(self, name, scope):
        """name을 찾을 곳: 그 함수 안에서 바인딩된 이름이면 함수, 아니면 모듈 최상위."""
        local = self._functions.get(scope)
        if local is not None and (name in local.values or name in local.dynamic):
            return local
        return self._module

    def _name_parts(self, name, scope, resolving):
        table = self._table_for(name, scope)
        if name in table.dynamic or name not in table.values:
            return None  # 매개변수이거나 출처를 모르는 이름
        key = (id(table), name)
        if key in resolving:
            return []  # `q = q + "..."`처럼 자기 자신을 거치는 대입은 나머지 대입으로 판단한다
        parts = []
        for value, value_scope in table.values[name]:
            value_parts = self._parts(value, value_scope, resolving | {key})
            if value_parts is None:
                return None
            parts.extend(value_parts)
        return parts


def is_negative_number(node):
    """`-1`처럼 음수 리터럴인지 (AST에서는 단항 연산으로 나온다)."""
    return (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, (int, float))
    )


def _is_format_call(node):
    """`"...".format(a, b=c)` 형태인지. `*args`, `**kwargs`가 있으면 내용을 알 수 없어 제외한다."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and not any(isinstance(argument, ast.Starred) for argument in node.args)
        and not any(keyword.arg is None for keyword in node.keywords)
    )


def _parameter_names(arguments):
    names = [argument.arg for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs]
    names.extend(extra.arg for extra in (arguments.vararg, arguments.kwarg) if extra is not None)
    return names


def _target_names(target):
    return [node.id for node in iter_nodes(target) if isinstance(node, ast.Name)]


def _scan(body):
    """스코프 하나의 문장들에서 이름 바인딩을 모은다. 안쪽 함수·클래스 본문은 다른 스코프라 들어가지 않는다.

    돌려주는 값: ([(이름, 대입된 값 노드 또는 None)], global로 선언된 이름들).
    값이 None이면 정적 문자열일 수 없는 바인딩(for 변수, import 등)이다.
    """
    bindings = []
    global_names = set()
    dynamic = []  # 정적 문자열일 수 없는 이름들
    stack = list(reversed(body))
    while stack:
        node = stack.pop()
        if isinstance(node, (*FUNCTION_NODES, ast.ClassDef)):
            dynamic.append(node.name)
            continue
        if isinstance(node, ast.Lambda):
            dynamic.extend(_parameter_names(node.args))
            continue
        if isinstance(node, ast.Global):
            global_names.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            dynamic.extend(node.names)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for target, value in assignment_pairs(node):
                if isinstance(target, ast.Name):
                    bindings.append((target.id, value))
        elif isinstance(node, ast.NamedExpr):
            bindings.append((node.target.id, node.value))
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                # `q += "..."`는 이어 붙이기다. 붙이는 쪽도 정적이어야 한다.
                appended = node.value if isinstance(node.op, ast.Add) else None
                bindings.append((node.target.id, appended))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            dynamic.extend(_target_names(node.target))
        elif isinstance(node, ast.withitem):
            if node.optional_vars is not None:
                dynamic.extend(_target_names(node.optional_vars))
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                dynamic.append(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            dynamic.extend((alias.asname or alias.name).split(".")[0] for alias in node.names)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name:
                dynamic.append(node.name)
        elif isinstance(node, ast.MatchMapping):
            if node.rest:
                dynamic.append(node.rest)
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    bindings.extend((name, None) for name in dynamic)
    return bindings, global_names
