"""흐름 분석 (스펙 3장): 문장을 순서대로 따라가며 값의 상태와, 그 지점에서 확정된 검사 결과를 구한다.

코드는 실행하지 않는다. 결과는 사건(호출·대입·return·비교)의 목록이고, 규칙은 이 목록만 본다.
- 값: values.Value (고정 글자, 추적하는 값, 알 수 없는 값의 나열)
- 사실(facts): 그 지점에 도달했다면 통과한 검사. 실패 시 중단하는 분기 뒤, 또는 통과한 분기 안에서만 생긴다
- 같은 파일의 함수는 인자의 상태를 가지고 안으로 따라 들어간다 (MAX_DEPTH 단계)
"""
import ast
from dataclasses import dataclass, replace

from . import models
from .source import FUNCTION_NODES
from .values import (
    EXTERNAL,
    NOCONST,
    PASSWORD,
    Taint,
    Value,
    boolean,
    const,
    join,
    merge,
    merge_all,
    of_taints,
    owned,
    tainted,
    unknown,
)
from .words import is_password_name

MAX_DEPTH = 4
ROUTE_DECORATORS = frozenset({"route", "get", "post", "put", "delete", "patch"})
STOP_CALLS = frozenset({"flask.abort", "werkzeug.exceptions.abort", "sys.exit", "os._exit"})
STOP_NAMES = frozenset({"exit", "quit"})
MUTATORS = frozenset(
    {"append", "add", "update", "pop", "setdefault", "extend", "remove", "clear", "insert", "popitem", "discard"}
)
NUMBER_CONVERTERS = frozenset({"int", "float"})


class Env:
    __slots__ = ("vars", "facts", "parent")

    def __init__(self, parent=None, facts=()):
        self.vars = {}
        self.facts = set(facts)
        self.parent = parent

    def get(self, name):
        env = self
        while env is not None:
            if name in env.vars:
                return env.vars[name]
            env = env.parent
        return None

    def owner_of(self, name):
        env = self
        while env is not None:
            if name in env.vars:
                return env
            env = env.parent
        return None

    def set(self, name, value):
        self.vars[name] = value

    def copy(self):
        clone = Env(self.parent, self.facts)
        clone.vars = dict(self.vars)
        return clone

    def adopt(self, other):
        self.vars = other.vars
        self.facts = other.facts


def merged(first, second):
    """두 분기의 환경을 합친다: 변수는 가능한 값을 모으고, 사실은 양쪽에 다 있는 것만 남긴다."""
    result = Env(first.parent, first.facts & second.facts)
    for name in dict.fromkeys([*first.vars, *second.vars]):
        a, b = first.vars.get(name), second.vars.get(name)
        result.vars[name] = a if b is None else b if a is None else merge(a, b)
    return result


@dataclass
class Frame:
    fn: ast.AST | None
    call_line: int | None
    returns: list
    globals: set


@dataclass
class Event:
    node: ast.AST
    facts: frozenset
    function: ast.AST | None  # 그 줄이 들어 있는 함수
    entry: ast.AST | None  # 분석을 시작한 함수 (라우트 등). 모듈 최상위면 None
    stack: tuple  # ((호출한 함수 id, 호출한 줄), ...) 시작 함수부터 순서대로

    @property
    def line(self):
        return self.node.lineno

    @property
    def entry_line(self):
        """시작 함수 안에서 이 사건으로 이어진 줄."""
        return self.stack[0][1] if self.stack else self.node.lineno


@dataclass
class CallEvent(Event):
    name: str | None  # import한 이름으로 푼 점 이름: "os.system"
    method: str | None  # `x.method(...)`의 method
    receiver: Value | None
    args: list
    kwargs: dict
    result: Value
    instance: str | None  # receiver를 만든 클래스의 점 이름: "requests.Session"

    def arg(self, position, keyword=None):
        if keyword and keyword in self.kwargs:
            return self.kwargs[keyword]
        return self.args[position] if position is not None and position < len(self.args) else None


@dataclass
class AssignEvent(Event):
    target: ast.AST
    value: Value
    kind: str  # "assign", "aug", "mutate"


@dataclass
class ReturnEvent(Event):
    value: Value


@dataclass
class CompareEvent(Event):
    kind: str  # "password", "limit"
    info: dict


@dataclass(frozen=True)
class Route:
    fn: ast.AST
    name: str
    rule: str | None
    line: int  # 데코레이터 줄
    converters: tuple  # ((변수 이름, 변환기), ...)


class Program:
    """분석 결과. 규칙이 읽는다."""

    def __init__(self, flow):
        self.source = flow.source
        self.calls = flow.calls
        self.assigns = flow.assigns
        self.returns = flow.returns
        self.compares = flow.compares
        self.routes = flow.routes
        self.route_of = flow.route_of
        self.classes = flow.classes
        self.module_names = set(flow.module_env.vars)
        self.mutated = flow.mutated
        self._values = flow.values

    def value(self, node):
        return self._values.get(id(node))

    @staticmethod
    def report_line(event, taint):
        """보고할 줄 (스펙 3.4): 값을 마지막으로 만든 함수가 도착점까지 넘긴 줄."""
        here = id(event.function) if event.function is not None else 0
        if taint.owner == here or not event.stack:
            return event.line
        for function_id, call_line in event.stack:
            if function_id == taint.owner:
                return call_line
        return event.stack[0][1]

    @staticmethod
    def path(taint, line):
        return tuple(dict.fromkeys((*taint.trail, line)))


def analyze_flow(source):
    flow = Flow(source)
    flow.run()
    return Program(flow)


class Flow:
    def __init__(self, source):
        self.source = source
        self.names = source.names
        self.values = {}
        self.calls, self.assigns, self.returns, self.compares = [], [], [], []
        self.functions = {}  # id(함수 노드) → 함수 노드
        self.closures = {}  # id(함수 노드) → 그 함수가 정의된 환경
        self.classes = set()
        self.class_methods = {}  # 클래스 이름 → {메서드 이름: 함수 노드}
        self.method_ids = set()
        self.module_env = Env()
        self.frames = []
        self.entry = None
        self.quiet = 0  # 0보다 크면 사건을 기록하지 않는다 (데코레이터를 흉내 내는 동안)
        self.wrapped_facts = None
        self.last_expr = {}  # 변수 이름 → 마지막으로 대입된 식
        self._origin = 0
        self._decorator_cache = {}
        tree = source.tree
        self.all_functions = [node for node in ast.walk(tree) if isinstance(node, FUNCTION_NODES)]
        self.called, self.mutated = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.called.add(node.func.id)
                elif isinstance(node.func, ast.Attribute) and node.func.attr in MUTATORS:
                    if isinstance(node.func.value, ast.Name):
                        self.mutated.add(node.func.value.id)
                for keyword in node.keywords:  # add_url_rule(view_func=f) 등으로 넘긴 함수
                    if isinstance(keyword.value, ast.Name):
                        self.called.discard(keyword.value.id)
            elif isinstance(node, (ast.Assign, ast.AugAssign, ast.Delete)):
                targets = node.targets if not isinstance(node, ast.AugAssign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        self.mutated.add(target.value.id)
            elif isinstance(node, FUNCTION_NODES):
                for decorator in node.decorator_list:
                    target = decorator.func if isinstance(decorator, ast.Call) else decorator
                    if isinstance(target, ast.Name):
                        self.called.add(target.id)
        self.routes, self.route_of = self._find_routes(tree)

    # ------------------------------------------------------------------ 라우트
    def _find_routes(self, tree):
        routes = []
        by_name = {}
        for fn in self.all_functions:
            by_name.setdefault(fn.name, fn)
            for decorator in fn.decorator_list:
                if self._is_route_call(decorator, ROUTE_DECORATORS):
                    rule = _string(decorator.args[0]) if decorator.args else _string(_keyword(decorator, "rule"))
                    routes.append(Route(fn, fn.name, rule, decorator.lineno, _converters(rule)))
                    break
        for node in ast.walk(tree):
            if self._is_route_call(node, {"add_url_rule"}):
                view = node.args[2] if len(node.args) > 2 else _keyword(node, "view_func")
                fn = by_name.get(view.id) if isinstance(view, ast.Name) else None
                if fn is not None and all(route.fn is not fn for route in routes):
                    rule = _string(node.args[0]) if node.args else _string(_keyword(node, "rule"))
                    routes.append(Route(fn, fn.name, rule, node.lineno, _converters(rule)))
        routes.sort(key=lambda route: route.line)
        return routes, {id(route.fn): route for route in routes}

    @staticmethod
    def _is_route_call(node, attributes):
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in attributes
            and isinstance(node.func.value, ast.Name)
        )

    def _is_errorhandler(self, fn):
        return any(self._is_route_call(decorator, {"errorhandler"}) for decorator in fn.decorator_list)

    # ------------------------------------------------------------------ 실행 순서
    def run(self):
        self.frames = [Frame(None, None, [], set())]
        self._block(self.source.tree.body, self.module_env)
        done = set()
        for _ in range(3):  # 함수 안에서 정의된 라우트는 바깥 함수를 본 뒤에야 볼 수 있다
            for fn in self.all_functions:
                if id(fn) in done or id(fn) not in self.closures or not self._is_entry(fn):
                    continue
                done.add(id(fn))
                self._run_entry(fn)

    def _is_entry(self, fn):
        if id(fn) in self.route_of or self._is_errorhandler(fn):
            return True
        return fn.name not in self.called

    def _run_entry(self, fn):
        env = Env(self.closures[id(fn)])
        route = self.route_of.get(id(fn))
        converters = dict(route.converters) if route else {}
        arguments = fn.args
        parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
        for index, parameter in enumerate(parameters):
            name = parameter.arg
            if route is not None:
                converter = converters.get(name, "string")
                checks = frozenset({"num"}) if converter in NUMBER_CONVERTERS else frozenset()
                removed = frozenset() if converter == "path" else frozenset({"/"})
                value = tainted(
                    self.new_taint({EXTERNAL}, fn.lineno, key=name, urlvar=True, checks=checks, removed=removed,
                                   owner=id(fn))
                )
            elif index == 0 and self._is_errorhandler(fn):
                value = unknown("exception")
            elif is_password_name(name) and id(fn) not in self.method_ids:
                # 메서드의 매개변수는 부른 쪽에서 이미 해시했을 수 있어 출발점으로 보지 않는다 (부른 쪽에서 따라 들어온다)
                value = tainted(self.new_taint({PASSWORD}, fn.lineno, key=name, owner=id(fn)))
            else:
                value = unknown("param")
            env.set(name, value)
        for extra in (arguments.vararg, arguments.kwarg):
            if extra is not None:
                env.set(extra.arg, unknown("param"))
        self.entry = fn
        self.frames = [Frame(fn, None, [], set())]
        env.facts |= self._decorator_facts(fn)
        self._block(fn.body, env)
        self.frames = [Frame(None, None, [], set())]
        self.entry = None

    # ------------------------------------------------------------------ 도우미
    def new_taint(self, labels, line, **details):
        self._origin += 1
        details.setdefault("owner", self.here)
        return Taint(labels=frozenset(labels), origin=self._origin, line=line, trail=(line,), **details)

    @property
    def here(self):
        fn = self.frames[-1].fn if self.frames else None
        return id(fn) if fn is not None else 0

    def _stack(self):
        return tuple(
            (id(frame.fn) if frame.fn is not None else 0, below.call_line)
            for frame, below in zip(self.frames, self.frames[1:])
        )

    def record(self, event_type, node, env, **details):
        if self.quiet:
            return None
        event = event_type(
            node=node,
            facts=frozenset(env.facts),
            function=self.frames[-1].fn if self.frames else None,
            entry=self.entry,
            stack=self._stack(),
            **details,
        )
        {CallEvent: self.calls, AssignEvent: self.assigns, ReturnEvent: self.returns, CompareEvent: self.compares}[
            event_type
        ].append(event)
        return event

    def is_global_store(self, node, env):
        """모듈 최상위에 두고 내용을 바꿔 쓰는 dict·list인지 (서버의 변수에 저장하는 것)."""
        if not isinstance(node, ast.Name) or node.id not in self.mutated:
            return False
        return env.owner_of(node.id) is self.module_env or (
            env.owner_of(node.id) is None and node.id in self.module_env.vars
        )

    # ------------------------------------------------------------------ 문장
    def _block(self, statements, env):
        """문장들을 차례로 본다. 그 블록이 항상 중단(return·raise·abort·continue·break)으로 끝나면 True."""
        for statement in statements:
            if self._statement(statement, env):
                return True
        return False

    def _statement(self, node, env):  # noqa: C901 - 문장 종류별 분기
        if isinstance(node, ast.Expr):
            self.eval(node.value, env)
            return isinstance(node.value, ast.Call) and self._is_stop(node.value)
        if isinstance(node, ast.Assign):
            value = self.eval(node.value, env)
            for target in node.targets:
                self._assign(target, value, env, node)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._assign(node.target, self.eval(node.value, env), env, node)
        elif isinstance(node, ast.AugAssign):
            current = self.eval(node.target, env)
            value = self._binary(node.op, current, self.eval(node.value, env), node.lineno)
            self._assign(node.target, value, env, node, kind="aug")
        elif isinstance(node, ast.Return):
            value = self.eval(node.value, env) if node.value is not None else const(None)
            self.record(ReturnEvent, node, env, value=value)
            self.frames[-1].returns.append((value, frozenset(env.facts)))
            return True
        elif isinstance(node, ast.Raise):
            if node.exc is not None:
                self.eval(node.exc, env)
            return True
        elif isinstance(node, (ast.Break, ast.Continue)):
            return True
        elif isinstance(node, ast.If):
            return self._if(node, env)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            iterable = self.eval(node.iter, env)
            element = models.element_of(self, iterable)
            self._loop(node, env, lambda scope: self._assign(node.target, element, scope, node),
                       at_least_once=models.never_empty(iterable))
        elif isinstance(node, ast.While):
            self._loop(node, env, lambda scope: scope.facts.update(self.cond(node.test, scope).wt))
        elif isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            return self._try(node, env)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = self.eval(item.context_expr, env)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, value, env, node)
            return self._block(node.body, env)
        elif isinstance(node, FUNCTION_NODES):
            self.functions[id(node)] = node
            self.closures[id(node)] = env
            env.set(node.name, Value(obj=("function", id(node))))
        elif isinstance(node, ast.ClassDef):
            self.classes.add(node.name)
            env.set(node.name, Value(obj=("class", node.name)))
            for member in node.body:
                if isinstance(member, FUNCTION_NODES):
                    self.functions[id(member)] = member
                    self.closures[id(member)] = env
                    self.class_methods.setdefault(node.name, {})[member.name] = member
                    self.method_ids.add(id(member))
                elif isinstance(member, (ast.Assign, ast.AnnAssign)) and getattr(member, "value", None) is not None:
                    self.eval(member.value, env)
        elif isinstance(node, ast.Match):
            self.eval(node.subject, env)
            branches = []
            for case in node.cases:
                branch = env.copy()
                if not self._block(case.body, branch):
                    branches.append(branch)
            for branch in branches:
                env.adopt(merged(env, branch))
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            self.frames[-1].globals.update(node.names)
        elif isinstance(node, ast.Assert):
            env.facts |= self.cond(node.test, env).wt
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Subscript):
                    self.eval(target.value, env)
        return False

    def _if(self, node, env):
        test = self.cond(node.test, env)
        body, orelse = env.copy(), env.copy()
        body.facts |= test.wt
        orelse.facts |= test.wf
        body_stops = self._block(node.body, body)
        else_stops = self._block(node.orelse, orelse)
        if body_stops and else_stops:
            env.adopt(merged(body, orelse))
            return True
        env.adopt(orelse if body_stops else body if else_stops else merged(body, orelse))
        return False

    def _loop(self, node, env, prepare, at_least_once=False):
        """본문을 두 번 본다 (앞 반복에서 바뀐 값이 다음 반복에 쓰이는 경우).

        비어 있지 않은 상수 목록을 도는 반복문은 본문이 적어도 한 번 실행되므로, 반복 전의 값을 섞지 않는다.
        """
        before = set(env.facts)
        for turn in range(2):
            body = env.copy()
            prepare(body)
            self._block(node.body, body)
            body.facts = set(before)
            env.adopt(body if at_least_once and turn == 0 else merged(env, body))
        self._block(node.orelse, env)
        env.facts = before

    def _try(self, node, env):
        start = env.copy()
        body_stops = self._block(node.body, env)
        if not body_stops:
            body_stops = self._block(node.orelse, env)
        outcomes = [] if body_stops else [env.copy()]
        for handler in node.handlers:
            scope = merged(start, env)
            if handler.type is not None:
                self.eval(handler.type, scope)
            if handler.name:
                scope.set(handler.name, unknown("exception"))
            if not self._block(handler.body, scope):
                outcomes.append(scope)
        if not outcomes:
            self._block(node.finalbody, env)
            return True
        result = outcomes[0]
        for outcome in outcomes[1:]:
            result = merged(result, outcome)
        env.adopt(result)
        return self._block(node.finalbody, env)

    def _is_stop(self, call):
        name = self.names.resolve(call.func)
        if name in STOP_CALLS:
            return True
        return isinstance(call.func, ast.Name) and call.func.id in STOP_NAMES | {"abort"}

    def _assign(self, target, value, env, statement, kind="assign"):
        if isinstance(target, ast.Name):
            scope = self.module_env if target.id in self.frames[-1].globals else env
            scope.set(target.id, value.plain())
            source_expr = getattr(statement, "value", None)
            if source_expr is not None:
                self.last_expr[target.id] = source_expr
            if kind == "aug":
                self.record(AssignEvent, statement, env, target=target, value=value, kind=kind)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element, part in zip(target.elts, models.unpack(value, len(target.elts))):
                self._assign(element, part, env, statement, kind)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, value, env, statement, kind)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = self.eval(target.value, env)
            key = self.eval(target.slice, env) if isinstance(target, ast.Subscript) else None
            self.record(AssignEvent, statement, env, target=target, value=value, kind=kind)
            if (
                key is not None
                and isinstance(target.value, ast.Name)
                and base.fields is not None
                and key.const is not NOCONST
                and not self.is_global_store(target.value, env)
            ):
                fields = tuple(item for item in base.fields if item[0] != key.const) + ((key.const, value.plain()),)
                holder = env.owner_of(target.value.id) or env
                holder.set(target.value.id, replace(base, fields=fields, const=NOCONST))

    # ------------------------------------------------------------------ 식
    def eval(self, node, env):
        value = self._eval(node, env)
        self.values[id(node)] = value
        return value

    def cond(self, node, env):
        """조건식의 값. 참·거짓일 때 확정되는 사실이 없으면 값 자체의 참·거짓 뜻을 본다 (`if session.get(...)`)."""
        value = self.eval(node, env)
        if not value.wt and not value.wf:
            wt, wf = models.truth(value)
            if wt or wf:
                value = replace(value, wt=frozenset(wt), wf=frozenset(wf))
        return value

    def _eval(self, node, env):  # noqa: C901 - 식 종류별 분기
        if isinstance(node, ast.Constant):
            return const(node.value)
        if isinstance(node, ast.Name):
            return self._name(node, env)
        if isinstance(node, ast.JoinedStr):
            parts = [
                self.eval(item.value, env).plain() if isinstance(item, ast.FormattedValue) else const(item.value)
                for item in node.values
            ]
            return join(parts, self.here, node.lineno)
        if isinstance(node, ast.FormattedValue):
            return self.eval(node.value, env)
        if isinstance(node, ast.BinOp):
            return self._binary(node.op, self.eval(node.left, env), self.eval(node.right, env), node.lineno)
        if isinstance(node, ast.BoolOp):
            return self._boolean(node, env)
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                operand = self.cond(node.operand, env)
                return boolean(operand.wf, operand.wt)
            operand = self.eval(node.operand, env)
            if isinstance(node.op, ast.USub) and isinstance(operand.const, (int, float)):
                return const(-operand.const)
            return operand.plain()
        if isinstance(node, ast.Compare):
            left = self.eval(node.left, env)
            rights = [self.eval(comparator, env) for comparator in node.comparators]
            if len(node.ops) != 1:
                return boolean()
            wt, wf = models.compare(self, node, node.ops[0], left, rights[0], env)
            return boolean(wt, wf)
        if isinstance(node, ast.Call):
            return self._call(node, env)
        if isinstance(node, ast.Attribute):
            return models.attribute(self, node, self.eval(node.value, env), env)
        if isinstance(node, ast.Subscript):
            base = self.eval(node.value, env)
            key = None if isinstance(node.slice, ast.Slice) else self.eval(node.slice, env)
            return models.subscript(self, node, base, key, env)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            items = tuple(self.eval(element, env).plain() for element in node.elts)
            return owned(models.sequence(items), self.here, node.lineno)
        if isinstance(node, ast.Dict):
            pairs = []
            for key, item in zip(node.keys, node.values):
                value = self.eval(item, env).plain()
                key_value = self.eval(key, env) if key is not None else None
                pairs.append((key_value.const if key_value is not None else NOCONST, value))
            return owned(models.mapping(pairs), self.here, node.lineno)
        if isinstance(node, ast.IfExp):
            test = self.cond(node.test, env)
            saved = set(env.facts)
            env.facts |= test.wt
            body = self.eval(node.body, env)
            env.facts = saved | test.wf
            orelse = self.eval(node.orelse, env)
            env.facts = saved
            return merge(body.plain(), orelse.plain())
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            scope = Env(env, env.facts)
            for generator in node.generators:
                element = models.element_of(self, self.eval(generator.iter, scope))
                self._assign(generator.target, element, scope, node)
                for condition in generator.ifs:
                    scope.facts |= self.cond(condition, scope).wt
            parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            found = merge_all(self.eval(part, scope).plain() for part in parts)
            return Value(alts=found.alts)
        if isinstance(node, ast.NamedExpr):
            value = self.eval(node.value, env)
            self._assign(node.target, value, env, node)
            return value
        if isinstance(node, (ast.Await, ast.Starred)):
            return self.eval(node.value, env)
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return self.eval(node.value, env) if node.value is not None else const(None)
        return unknown()

    def _name(self, node, env):
        found = env.get(node.id)
        if found is not None:
            return found
        dotted = self.names.resolve(node)
        return models.reference(dotted) if dotted else unknown()

    def _binary(self, operator, left, right, line):
        if isinstance(left.const, (int, float)) and isinstance(right.const, (int, float)):
            try:
                folded = _ARITHMETIC[type(operator)](left.const, right.const)
            except (KeyError, ArithmeticError, TypeError, ValueError):
                return unknown()
            return const(folded)
        if isinstance(operator, ast.Mult):  # `"?" * n`, `[값] * 2`: 같은 내용을 되풀이한 것이다
            for repeated, times in ((left, right), (right, left)):
                if not times.taints() and (repeated.is_static or repeated.taints() or repeated.items is not None):
                    return Value(alts=repeated.alts)
        if isinstance(operator, ast.Add):
            return join([left.plain(), right.plain()], self.here, line)
        if isinstance(operator, ast.Mod) and left.text is not None:
            return models.percent_format(self, left.text, right, line)
        if isinstance(operator, ast.BitOr) and (left.fields is not None or right.fields is not None):
            return merge(left.plain(), right.plain())
        taints = left.taints() | right.taints()
        return of_taints(taints, *(left.marks() | right.marks())) if taints else unknown(*(left.marks() | right.marks()))

    def _boolean(self, node, env):
        is_and = isinstance(node.op, ast.And)
        saved = set(env.facts)
        operands = []
        for operand in node.values:
            value = self.cond(operand, env)
            operands.append(value)
            env.facts |= value.wt if is_and else value.wf
        env.facts = saved
        trues, falses = [value.wt for value in operands], [value.wf for value in operands]
        wt = frozenset().union(*trues) if is_and else frozenset.intersection(*trues)
        wf = frozenset.intersection(*falses) if is_and else frozenset().union(*falses)
        return replace(merge_all(value.plain() for value in operands), wt=wt, wf=wf)

    # ------------------------------------------------------------------ 호출
    def _call(self, node, env):
        func = node.func
        receiver = method = target = None
        name = self.names.resolve(func)
        if isinstance(func, ast.Attribute):
            method = func.attr
            receiver = self.eval(func.value, env)
            if name is None and receiver.obj and receiver.obj[0] == "ref":
                name = f"{receiver.obj[1]}.{method}"
        elif isinstance(func, ast.Name):
            target = env.get(func.id)
            if target is not None and target.obj and target.obj[0] == "ref":
                name = target.obj[1]
        else:
            receiver = self.eval(func, env)
        args = [self.eval(item.value if isinstance(item, ast.Starred) else item, env) for item in node.args]
        kwargs = {}
        for keyword in node.keywords:
            value = self.eval(keyword.value, env)
            if keyword.arg is not None:
                kwargs[keyword.arg] = value
        call = models.Call(node, name, method, receiver, args, kwargs, env, node.lineno)

        kind = target.obj[0] if target is not None and target.obj else None
        if kind == "wrapped":
            if self.wrapped_facts is not None:
                self.wrapped_facts.append(set(env.facts))
            result = unknown()
        elif kind == "function":
            result = self._invoke(self.functions[target.obj[1]], call)
        elif kind == "class":
            call.name = None
            call.class_name = target.obj[1]
            result = replace(models.default_result(call, opaque=False), obj=("instance", f"<local>.{target.obj[1]}"))
            self._invoke_method(target.obj[1], "__init__", result, call)
        elif self._local_method(receiver, method) is not None:
            result = self._invoke_method(receiver.obj[1].removeprefix("<local>."), method, receiver, call)
        else:
            result = models.call(self, call)
        instance = receiver.obj[1] if receiver is not None and receiver.obj and receiver.obj[0] == "instance" else None
        self.record(
            CallEvent, node, env, name=name, method=method, receiver=receiver, args=args, kwargs=kwargs,
            result=result, instance=call.class_name and f"<local>.{call.class_name}" or instance,
        )
        return result

    def _local_method(self, receiver, method):
        """receiver가 같은 파일의 클래스로 만든 객체이고 그 클래스에 method가 있으면 그 함수 노드."""
        if receiver is None or not receiver.obj or receiver.obj[0] != "instance":
            return None
        return self.class_methods.get(receiver.obj[1].removeprefix("<local>."), {}).get(method)

    def _invoke_method(self, class_name, method, instance, call):
        """같은 파일의 클래스 메서드를 따라 들어간다. 첫 매개변수(self)에는 그 객체가 들어간다."""
        fn = self.class_methods.get(class_name, {}).get(method)
        if fn is None:
            return unknown()
        bound = models.Call(call.node, None, None, None, [instance, *call.args], call.kwargs, call.env, call.line)
        return self._invoke(fn, bound)

    def _invoke(self, fn, call):
        """같은 파일의 함수를 인자의 상태를 가지고 따라 들어간다."""
        if len(self.frames) > MAX_DEPTH or any(frame.fn is fn for frame in self.frames):
            return models.default_result(call, opaque=False)
        env = Env(self.closures.get(id(fn), self.module_env), call.env.facts)
        self._bind(fn, env, call)
        frame = Frame(fn, call.line, [], set())
        self.frames.append(frame)
        stops = self._block(fn.body, env)
        self.frames.pop()
        exits = list(frame.returns)
        if not stops:
            exits.append((const(None), frozenset(env.facts)))
        if not exits:
            return unknown()
        true_facts = [facts | value.wt for value, facts in exits if not _is_falsy(value)]
        false_facts = [facts | value.wf for value, facts in exits if not _is_truthy(value)]
        call.env.facts |= frozenset.intersection(*[facts for _, facts in exits])
        result = merge_all(value.plain() for value, _ in exits)
        return replace(
            result,
            wt=frozenset.intersection(*true_facts) if true_facts else frozenset(),
            wf=frozenset.intersection(*false_facts) if false_facts else frozenset(),
        )

    def _bind(self, fn, env, call):
        arguments = fn.args
        positional = [*arguments.posonlyargs, *arguments.args]
        defaults = dict(zip([p.arg for p in positional[len(positional) - len(arguments.defaults):]], arguments.defaults))
        defaults.update(
            {p.arg: d for p, d in zip(arguments.kwonlyargs, arguments.kw_defaults) if d is not None}
        )
        closure = self.closures.get(id(fn), self.module_env)
        for index, parameter in enumerate([*positional, *arguments.kwonlyargs]):
            name = parameter.arg
            if index < len(positional) and index < len(call.args):
                value = call.args[index]
            elif name in call.kwargs:
                value = call.kwargs[name]
            elif name in defaults:
                value = self.eval(defaults[name], closure)
            else:
                value = unknown("param")
            env.set(name, value.plain())
        if arguments.vararg is not None:
            extra = call.args[len(positional):]
            env.set(arguments.vararg.arg, models.sequence(tuple(item.plain() for item in extra)))
        if arguments.kwarg is not None:
            env.set(arguments.kwarg.arg, unknown("param"))

    # ------------------------------------------------------------------ 데코레이터
    def _decorator_facts(self, fn):
        """같은 파일의 데코레이터가 원래 함수를 부르기 전에 통과시킨 검사들 (스펙 3.3)."""
        facts = set()
        for decorator in fn.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            dotted = self.names.resolve(target)
            if dotted in models.LOGIN_DECORATORS:
                facts.add(("authz", "login"))
            elif isinstance(target, ast.Name):
                value = self.module_env.get(target.id)
                if value is not None and value.obj and value.obj[0] == "function":
                    facts |= self._simulate_decorator(self.functions[value.obj[1]])
        return facts

    def _simulate_decorator(self, decorator):
        if id(decorator) in self._decorator_cache:
            return self._decorator_cache[id(decorator)]
        self._decorator_cache[id(decorator)] = set()
        wrappers = [node for node in ast.walk(decorator) if isinstance(node, FUNCTION_NODES) and node is not decorator]
        candidates = {argument.arg for fn in (decorator, *wrappers) for argument in fn.args.args}
        collected = []
        saved = (self.frames, self.entry, self.wrapped_facts)
        self.quiet += 1
        self.wrapped_facts = collected
        for wrapper in wrappers:
            calls_wrapped = any(
                isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in candidates
                for node in ast.walk(wrapper)
            )
            if not calls_wrapped:
                continue
            env = Env(self.module_env)
            for name in candidates:
                env.set(name, Value(obj=("wrapped",)))
            for extra in (wrapper.args.vararg, wrapper.args.kwarg):
                if extra is not None:
                    env.set(extra.arg, unknown("param"))
            self.frames = [Frame(wrapper, None, [], set())]
            self._block(wrapper.body, env)
        self.frames, self.entry, self.wrapped_facts = saved
        self.quiet -= 1
        facts = set.intersection(*collected) if collected else set()
        self._decorator_cache[id(decorator)] = facts
        return facts


_ARITHMETIC = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Div: lambda a, b: a / b,
    ast.Mod: lambda a, b: a % b,
    ast.Pow: lambda a, b: a**b if abs(b) < 64 else None,
}


def _is_truthy(value):
    return value.const is not NOCONST and bool(value.const)


def _is_falsy(value):
    return value.const is not NOCONST and not value.const


def _string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _keyword(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _converters(rule):
    """`/post/<int:post_id>/<name>` → (("post_id", "int"), ("name", "string"))."""
    if not rule:
        return ()
    found = []
    for piece in rule.split("<")[1:]:
        inner = piece.split(">")[0]
        converter, _, name = inner.rpartition(":")
        found.append((name.strip(), converter.split("(")[0].strip() or "string"))
    return tuple(found)
