"""4.7 디버그 모드·오류 정보 노출 (debug_error_exposure): DBG-1, DBG-2, ERR-1, ERR-2."""
import ast

from ..astutil import (
    FUNCTION_NODES,
    assignment_pairs,
    call_argument,
    is_call_on,
    iter_nodes,
    keyword_argument,
    string_value,
)
from ..result import Finding

VULN_ID = "debug_error_exposure"

RUN_DEBUG_POSITION = 2  # Flask.run(host, port, debug)
TRACEBACK_PRINTERS = frozenset({"traceback.print_exc", "traceback.print_exception"})
TRACEBACK_TEXT = "traceback.format_exc"
ERROR_HANDLER = frozenset({"errorhandler"})


def check(source):
    findings = []
    for node in iter_nodes(source.tree):
        for value in _debug_values(node, source.names):
            rule_id = _debug_rule(value)
            if rule_id:
                findings.append(Finding(value.lineno, rule_id))
        if isinstance(node, ast.Call) and source.names.resolve(node.func) in TRACEBACK_PRINTERS:
            findings.append(Finding(node.lineno, "ERR-2"))
        if isinstance(node, FUNCTION_NODES):
            findings.extend(_ErrorResponses(source.names, node).findings())
    return findings


def _debug_values(node, names):
    """node가 디버그 모드를 정하는 코드면 그 debug 값 노드들을 돌려준다."""
    values = []
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "run" and names.is_app(node.func.value):
            values.append(call_argument(node, RUN_DEBUG_POSITION, "debug"))  # app.run(debug=...)
        elif node.func.attr == "update" and names.is_app_config(node.func.value):
            values.append(keyword_argument(node, "DEBUG"))  # app.config.update(DEBUG=...)
    for target, value in assignment_pairs(node):
        if isinstance(target, ast.Attribute):
            if target.attr == "debug" and names.is_app(target.value):
                values.append(value)  # app.debug = ...
        elif isinstance(target, ast.Subscript):
            if names.is_app_config(target.value) and string_value(target.slice) == "DEBUG":
                values.append(value)  # app.config["DEBUG"] = ...
    return [value for value in values if value is not None]


def _debug_rule(value):
    """debug 값이 상수 True면 DBG-1, 상수 False면 안전(None), 그 밖에는 꺼졌는지 알 수 없어 DBG-2."""
    if isinstance(value, ast.Constant) and value.value is True:
        return "DBG-1"
    if isinstance(value, ast.Constant) and value.value is False:
        return None
    return "DBG-2"


class _ErrorResponses:
    """함수 하나에서 예외 정보를 return하는 줄을 찾는다 (ERR-1). 문장은 소스 순서대로 본다.

    예외 정보: except 블록의 예외 변수, errorhandler 함수의 매개변수,
    traceback.format_exc(), 그리고 이것들이 담긴 식을 대입받은 변수.
    """

    def __init__(self, names, function):
        self._names = names
        self._function = function
        self._exception_names = set()
        self._derived_names = set()
        self._findings = []

    def findings(self):
        handler_parameter = _errorhandler_parameter(self._function, self._names)
        if handler_parameter:
            self._exception_names.add(handler_parameter)
        self._visit(self._function.body)
        return self._findings

    def _visit(self, statements):
        for statement in statements:
            if isinstance(statement, (*FUNCTION_NODES, ast.ClassDef)):
                continue  # 안쪽 함수는 check()가 따로 본다
            if isinstance(statement, ast.Return) and statement.value is not None:
                if self._has_exception_info(statement.value):
                    self._findings.append(Finding(statement.lineno, "ERR-1"))
            for target, value in assignment_pairs(statement):
                if isinstance(target, ast.Name) and self._has_exception_info(value):
                    self._derived_names.add(target.id)
            if isinstance(statement, (ast.Try, ast.TryStar)):
                self._visit(statement.body)
                for handler in statement.handlers:
                    self._visit_handler(handler)
                self._visit(statement.orelse)
                self._visit(statement.finalbody)
            else:
                for block in _blocks(statement):
                    self._visit(block)

    def _visit_handler(self, handler):
        # 예외 변수는 그 except 블록 안에서만 살아 있다.
        added = handler.name is not None and handler.name not in self._exception_names
        if added:
            self._exception_names.add(handler.name)
        self._visit(handler.body)
        if added:
            self._exception_names.discard(handler.name)

    def _has_exception_info(self, expression):
        for node in iter_nodes(expression):
            if isinstance(node, ast.Name):
                if node.id in self._exception_names or node.id in self._derived_names:
                    return True
            elif isinstance(node, ast.Call) and self._names.resolve(node.func) == TRACEBACK_TEXT:
                return True
        return False


def _errorhandler_parameter(function, names):
    """`@app.errorhandler(...)` 함수면 예외 객체를 받는 첫 매개변수 이름, 아니면 None."""
    owners = names.app_names | names.blueprint_names
    if not any(is_call_on(decorator, owners, ERROR_HANDLER) for decorator in function.decorator_list):
        return None
    parameters = function.args.posonlyargs + function.args.args
    return parameters[0].arg if parameters else None


def _blocks(statement):
    """if, for, while, with, match 등 복합문 안의 문장 묶음들."""
    for field in ("body", "orelse"):
        block = getattr(statement, field, None)
        if isinstance(block, list):
            yield block
    for case in getattr(statement, "cases", ()):
        yield case.body
