"""4.7 디버그 모드·오류 정보 노출 (debug_error_exposure): DBG-1, DBG-2, ERR-1, ERR-2."""
import ast

from ..result import Finding
from ..values import NOCONST
from .common import is_builtin_call

VULN_ID = "debug_error_exposure"

RUN_DEBUG_POSITION = 2  # Flask.run(host, port, debug)
TRACEBACK_PRINTERS = frozenset({"traceback.print_exc", "traceback.print_exception"})
APP_NAMES = frozenset({"app", "application"})
CONFIG_SETTERS = frozenset({"update", "from_mapping"})


def check(source):
    program = source.flow
    findings = []
    for event in program.calls:
        func = event.node.func
        if event.method == "run" and _is_app(event):
            _debug(findings, program, _argument(event.node, RUN_DEBUG_POSITION, "debug"))  # app.run(debug=...)
        elif event.method in CONFIG_SETTERS and _is_config(func.value):
            _debug(findings, program, _argument(event.node, None, "DEBUG"))  # app.config.update(DEBUG=...)
        if event.name in TRACEBACK_PRINTERS:
            findings.append(Finding(event.line, "ERR-2"))
        elif is_builtin_call(event, "print") and any(arg.has_mark("traceback", deep=True) for arg in event.args):
            findings.append(Finding(event.line, "ERR-2"))
    for event in program.assigns:
        target = event.target
        if event.kind != "assign":
            continue
        value_node = getattr(event.node, "value", None)
        if isinstance(target, ast.Attribute) and target.attr == "debug" and _is_app_node(program, target.value):
            _debug(findings, program, value_node)  # app.debug = ...
        elif isinstance(target, ast.Subscript) and _is_config(target.value) and _key(target) == "DEBUG":
            _debug(findings, program, value_node)  # app.config["DEBUG"] = ...
    for event in program.returns:
        if event.value.has_mark("exception", deep=True):
            findings.append(Finding(event.line, "ERR-1"))
    return findings


def _debug(findings, program, node):
    """debug 값이 켜진 상수면 DBG-1, 꺼진 상수면 안전, 그 밖에는 꺼졌는지 알 수 없어 DBG-2."""
    if node is None:
        return
    value = program.value(node)
    constant = value.const if value is not None and value.is_static else NOCONST
    if constant is NOCONST:
        findings.append(Finding(node.lineno, "DBG-2"))
    elif constant not in (False, None, 0, "", "0"):
        findings.append(Finding(node.lineno, "DBG-1"))


def _argument(call, position, keyword):
    for item in call.keywords:
        if item.arg == keyword:
            return item.value
    if position is not None and position < len(call.args) and not isinstance(call.args[position], ast.Starred):
        return call.args[position]
    return None


def _is_app(event):
    target = event.node.func.value
    if event.instance == "flask.Flask":
        return True
    if isinstance(target, ast.Name) and target.id in APP_NAMES:
        return True
    return bool(event.name) and event.name.endswith((".app.run", ".application.run"))


def _is_app_node(program, node):
    value = program.value(node)
    if value is not None and value.obj == ("instance", "flask.Flask"):
        return True
    return isinstance(node, ast.Name) and node.id in APP_NAMES


def _is_config(node):
    return isinstance(node, ast.Attribute) and node.attr == "config"


def _key(subscript):
    key = subscript.slice
    return key.value if isinstance(key, ast.Constant) else None
