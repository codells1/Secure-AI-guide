"""오염 분석 엔진 (스펙 3.1~3.3, 3.5 도착점 감싸기).

함수마다 문장을 소스 순서대로 따라가며 "변수 → 값들" 표를 갱신하고,
등록된 도착점의 위험한 인자 자리에 어떤 값이 들어가는지 모아서 돌려준다.
어떤 규칙 ID로 보고할지는 각 취약점 모듈이 정한다.
"""
import ast
import re
import string
from dataclasses import dataclass

from ..astutil import FUNCTION_NODES, added_operands, assignment_pairs, iter_nodes, iter_nodes_with_scope
from ..names import ABORT_CALLS
from ..routes import find_routes
from ..static_str import STATIC_TEXT_CALL, is_negative_number
from .consts import Constants
from .spec import CLEAN, CallInfo, Marked, Same, TaggedCall, Update, registered_specs
from .values import (
    SANITIZED,
    Kind,
    Part,
    add_line,
    collapse,
    concat,
    first_part,
    is_all_static,
    merge,
    single,
    static,
    static_text,
)

# 출발점 (스펙 3.1)
SOURCE_ATTRIBUTES = frozenset(
    "flask.request." + name
    for name in (
        "args", "form", "values", "json", "files", "cookies", "headers", "view_args",
        "data", "query_string", "url", "path",
    )
)
SOURCE_CALLS = frozenset({"flask.request.get_json", "flask.request.get_data"})
LOOP_PASSES = 2  # 앞 바퀴에서 만든 값이 다음 바퀴에 쓰이는 경우까지 본다

_URL_VARIABLE = re.compile(r"<(?:[^:<>]+:)?([^<>]+)>")
_PERCENT = re.compile(r"%(?:\(([^)]*)\))?[#0\- +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[hlL]?([diouxXeEfFgGcrsa%])")


@dataclass
class SinkHit:
    """도착점(또는 명세가 고른 식 자리) 하나에 대해, 그 자리에 올 수 있는 값들."""

    role: str  # 도착점의 role, 또는 명세의 probes가 붙인 역할
    node: ast.AST  # 도착점 호출, 또는 값을 본 식
    call_node: ast.Call | None  # 같은 파일의 함수를 한 단계 따라 들어가 만났으면 그 함수를 호출한 식
    exact: bool  # 그 함수가 매개변수를 그대로 도착점에 넘기는 감싸기 함수인지 (스펙 3.5)
    values: list

    @property
    def line(self):
        return self.node.lineno

    @property
    def call_line(self):
        return self.call_node.lineno if self.call_node is not None else None

    @property
    def report_line(self):
        """보고할 줄. 감싸기 함수를 거쳤으면 호출한 줄이다."""
        return self.call_line or self.line

    def path(self, part):
        """part가 출발한 줄부터 보고할 줄까지 (같은 줄은 한 번만, 보고할 줄이 마지막)."""
        trail = list(part.trail)
        if self.call_line in trail:
            trail = trail[: trail.index(self.call_line)]
        return tuple(line for line in trail if line != self.report_line) + (self.report_line,)

    def path_to(self, part, end):
        """part가 출발한 줄부터 end까지 (호출한 줄 다음에 헬퍼 안의 줄이 오고, end가 마지막)."""
        return tuple(line for line in part.trail if line != end) + (end,)


def find_sink_hits(source, spec):
    """spec의 도착점마다 위험한 인자 자리에 올 수 있는 값들을 모아, 보고할 줄 순서로 돌려준다."""
    return _Engine(source, spec).run()


class _Frame:
    """함수 하나(또는 모듈 최상위)를 따라가는 동안의 상태."""

    def __init__(self, function, env, call_node=None):
        self.function = function  # 모듈 최상위면 None
        self.env = env  # 변수 이름 → 값들
        self.call_node = call_node  # 다른 함수에서 한 단계 따라 들어왔으면 그 호출 식
        self.returns = ()

    @property
    def call_line(self):
        return self.call_node.lineno if self.call_node is not None else None


class _Engine:
    def __init__(self, source, spec):
        self._source = source
        self._names = source.names
        self._spec = spec
        self._consts = Constants(source)
        # 등록된 모든 취약점의 도착점: 결과로 오염을 전파하지 않는다 (스펙 3.2).
        self._sinks_by_function = {}
        self._sinks_by_method = {}
        for other in dict.fromkeys((*registered_specs(), spec)):
            for sink in other.sinks:
                table = self._sinks_by_function if sink.function else self._sinks_by_method
                table.setdefault(sink.function or sink.method, []).append((other == spec, sink))
        self._functions = {
            node.name: node for node in source.tree.body if isinstance(node, FUNCTION_NODES)
        }
        self._route_variables = _route_variables(find_routes(source))
        self._source_attributes = SOURCE_ATTRIBUTES if spec.source_attributes is None else spec.source_attributes
        self._source_calls = SOURCE_CALLS if spec.source_calls is None else spec.source_calls
        self._probes = {id(node): role for node, role in spec.probes(source)} if spec.probes else {}
        self._objects = _created_objects(source)
        self._module_values = {}
        self._classifying = False
        self._exactness = {}  # id(도착점 호출) → 그 인자가 매개변수 그대로였는지 기록
        self._exact = frozenset()
        self._hits = {}

    def run(self):
        functions = [node for node in iter_nodes(self._source.tree) if isinstance(node, FUNCTION_NODES)]
        # 1) 감싸기 함수 찾기: 매개변수가 그대로 도착점에 가는 호출을 미리 가려 둔다.
        self._classifying = True
        for function in functions:
            self._run_function(function)
        self._exact = frozenset(key for key, flags in self._exactness.items() if all(flags))
        # 2) 실제 분석: 모듈 최상위, 그다음 함수들.
        self._classifying = False
        self._run_block(self._source.tree.body, _Frame(None, {}))
        for function in functions:
            self._run_function(function)
        return sorted(self._hits.values(), key=lambda hit: (hit.report_line, hit.line))

    def _run_function(self, function):
        """함수를 혼자 분석한다. 라우트의 URL 변수는 오염, 나머지 매개변수는 '매개변수'로 둔다."""
        is_route = function in self._route_variables
        variables = self._route_variables.get(function)
        env = {}
        for parameter in _parameters(function.args):
            from_url = (
                self._spec.url_variables and is_route and (variables is None or parameter.arg in variables)
            )
            env[parameter.arg] = single(Kind.TAINTED if from_url else Kind.PARAM, parameter.lineno)
        self._run_block(function.body, _Frame(function, env))

    # ---- 문장 ----

    def _run_block(self, statements, frame):
        """문장들을 순서대로 따라간다. 중단(return, raise, abort, continue)으로 끝났으면 True."""
        for statement in statements:
            if self._run_statement(statement, frame):
                return True
        return False

    def _run_statement(self, node, frame):
        if isinstance(node, (*FUNCTION_NODES, ast.ClassDef)):
            return False  # 다른 함수는 따로 분석한다
        if isinstance(node, ast.Return):
            value = single(Kind.UNKNOWN) if node.value is None else self._eval(node.value, frame)
            frame.returns = merge(frame.returns, add_line(value, node.lineno))
            return True
        if isinstance(node, ast.Raise):
            self._eval_children(node, frame)
            return True
        if isinstance(node, ast.Continue):
            return True
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            self._assign(node, frame)
            return False
        if isinstance(node, ast.AugAssign):
            self._augmented_assign(node, frame)
            return False
        if isinstance(node, ast.Expr):
            self._eval(node.value, frame)
            return self._is_abort(node.value)
        if isinstance(node, ast.If):
            return self._run_if(node, frame)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            # 오염된 것을 돌면 꺼낸 값도 오염이다.
            item = collapse([self._eval(node.iter, frame)], node.lineno)
            self._run_loop(node, frame, lambda: self._bind(node.target, item, frame))
            return False
        if isinstance(node, ast.While):
            self._run_loop(node, frame, lambda: self._eval(node.test, frame))
            return False
        if isinstance(node, (ast.Try, ast.TryStar)):
            return self._run_try(node, frame)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = collapse([self._eval(item.context_expr, frame)], node.lineno)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, value, frame)
            return self._run_block(node.body, frame)
        if isinstance(node, ast.Match):
            return self._run_match(node, frame)
        self._eval_children(node, frame)  # assert, del 등: 안에 든 식만 본다
        return False

    def _assign(self, node, frame):
        evaluated = {}
        for target, value in assignment_pairs(node):
            if id(value) not in evaluated:
                evaluated[id(value)] = add_line(self._eval(value, frame), node.lineno)
            group = evaluated[id(value)]
            if (
                isinstance(target, ast.Name)
                and self._spec.source_names is not None
                and self._spec.source_names(target.id)
            ):
                group = _as_source(group, node.lineno)
            self._bind(target, group, frame)

    def _augmented_assign(self, node, frame):
        value = self._eval(node.value, frame)
        if not isinstance(node.target, ast.Name):
            return
        current = self._lookup(node.target.id, frame)
        if isinstance(node.op, ast.Add):
            result = concat(current, value)
        else:
            result = collapse([current, value], node.lineno)
        frame.env[node.target.id] = add_line(result, node.lineno)

    def _bind(self, target, value, frame):
        """대입 대상 이름에 값을 적는다. 고정 값을 대입하면 오염이 해제된다. 속성·첨자 대입은 적지 않는다."""
        if isinstance(target, ast.Name):
            frame.env[target.id] = value
        elif isinstance(target, ast.Starred):
            self._bind(target.value, value, frame)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element, value, frame)

    def _run_if(self, node, frame):
        """if/else는 갈 수 있는 길을 모두 따라가고, 중간에 끝난 길은 뺀다.

        허용목록 검사(스펙 3.6)를 통과한 길에서는 그 변수가 목록 안의 값 중 하나다.
        """
        self._eval(node.test, frame)
        before = frame.env
        frame.env = dict(before)
        self._mark_allowed(node.test, True, frame)
        body_stopped = self._run_block(node.body, frame)
        body_env = frame.env
        frame.env = dict(before)
        self._mark_allowed(node.test, False, frame)
        else_stopped = self._run_block(node.orelse, frame)
        else_env = frame.env
        live = [env for env, stopped in ((body_env, body_stopped), (else_env, else_stopped)) if not stopped]
        frame.env = self._join(live) if live else else_env
        return not live

    def _mark_allowed(self, test, holds, frame):
        for name in self._allowed_names(test, holds, frame):
            frame.env[name] = _checked(self._lookup(name, frame))

    def _allowed_names(self, test, holds, frame):
        """조건식 test가 holds일 때 허용목록 안의 값으로 확정되는 변수 이름들 (스펙 3.6)."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._allowed_names(test.operand, not holds, frame)
        if isinstance(test, ast.BoolOp):
            if isinstance(test.op, ast.And) != holds:
                return set()  # (A and B)가 거짓이거나 (A or B)가 참: 어느 쪽 때문인지 알 수 없다
            return {name for value in test.values for name in self._allowed_names(value, holds, frame)}
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
            return set()
        operator, left, right = test.ops[0], test.left, test.comparators[0]
        if isinstance(operator, (ast.In, ast.NotIn)):
            if (
                isinstance(operator, ast.In) == holds
                and isinstance(left, ast.Name)
                and self._consts.is_allow_list(right, frame.function)
            ):
                return {left.id}
        elif isinstance(operator, (ast.Eq, ast.NotEq)) and isinstance(operator, ast.Eq) == holds:
            # 상수 하나와 비교: 목록이 하나인 경우와 같다
            return {
                subject.id
                for subject, other in ((left, right), (right, left))
                if isinstance(subject, ast.Name) and self._source.static.is_static(other, frame.function)
            }
        return set()

    def _run_loop(self, node, frame, start):
        before = dict(frame.env)
        for _ in range(LOOP_PASSES):
            start()
            self._run_block(node.body, frame)
            frame.env = self._join([before, frame.env])
            before = dict(frame.env)
        self._run_block(node.orelse, frame)

    def _run_try(self, node, frame):
        before = dict(frame.env)
        body_stopped = self._run_block(node.body, frame)
        after_body = frame.env
        live = []
        if not body_stopped:
            frame.env = dict(after_body)
            if not self._run_block(node.orelse, frame):
                live.append(frame.env)
        for handler in node.handlers:
            # 예외는 본문 어디서든 날 수 있으므로 본문 전과 후의 값을 모두 본다.
            frame.env = self._join([before, after_body])
            if handler.type is not None:
                self._eval(handler.type, frame)
            if handler.name:
                frame.env[handler.name] = single(Kind.UNKNOWN, handler.lineno)
            if not self._run_block(handler.body, frame):
                live.append(frame.env)
        frame.env = self._join(live) if live else self._join([before, after_body])
        final_stopped = self._run_block(node.finalbody, frame)
        return final_stopped or not live

    def _run_match(self, node, frame):
        self._eval(node.subject, frame)
        before = dict(frame.env)
        live = [before]  # 맞는 case가 없을 수도 있다
        for case in node.cases:
            frame.env = dict(before)
            if not self._run_block(case.body, frame):
                live.append(frame.env)
        frame.env = self._join(live)
        return False

    def _join(self, envs):
        names = dict.fromkeys(name for env in envs for name in env)
        return {
            name: merge(*(env[name] if name in env else self._module_value(name) for env in envs))
            for name in names
        }

    def _is_abort(self, node):
        return isinstance(node, ast.Call) and self._names.resolve(node.func) in ABORT_CALLS

    # ---- 식 ----

    def _eval(self, node, frame):
        """식의 값들을 계산한다. 식 안의 도착점 호출과, 명세가 고른 식 자리의 값도 이때 기록된다."""
        group = self._evaluate(node, frame)
        role = self._probes.get(id(node))
        if role is not None:
            self._record(frame, role, node, group)
        return group

    def _evaluate(self, node, frame):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return static(node.value)
            if isinstance(node.value, bytes):
                return static(node.value.decode("latin-1"))
            return static(str(node.value))  # 숫자·True·False·None도 정적이다 (스펙 3.4)
        if is_negative_number(node):
            return static(f"-{node.operand.value}")
        if isinstance(node, ast.JoinedStr):
            pieces = (piece.value if isinstance(piece, ast.FormattedValue) else piece for piece in node.values)
            return concat(*(self._eval(piece, frame) for piece in pieces))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return concat(*(self._eval(operand, frame) for operand in added_operands(node)))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return self._eval_percent(node, frame)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and self._spec.division_joins:
            return concat(self._eval(node.left, frame), self._eval(node.right, frame))
        if isinstance(node, ast.Name):
            return self._lookup(node.id, frame)
        if isinstance(node, ast.IfExp):
            self._eval(node.test, frame)
            return merge(
                self._eval_branch(node.test, True, node.body, frame),
                self._eval_branch(node.test, False, node.orelse, frame),
            )
        if isinstance(node, ast.BoolOp):
            return merge(*(self._eval(value, frame) for value in node.values))
        if isinstance(node, ast.NamedExpr):
            value = add_line(self._eval(node.value, frame), node.lineno)
            self._bind(node.target, value, frame)
            return value
        if isinstance(node, (ast.Await, ast.Starred)):
            return self._eval(node.value, frame)
        if isinstance(node, ast.Attribute):
            return self._eval_attribute(node, frame)
        if isinstance(node, ast.Subscript):
            return self._eval_subscript(node, frame)
        if isinstance(node, ast.Call):
            return self._eval_call(node, frame)
        # 그 밖의 식(비교, 목록, 컴프리헨션 등): 안에 오염된 값이 있으면 오염으로 본다.
        return collapse(self._eval_children(node, frame), getattr(node, "lineno", None))

    def _eval_branch(self, test, holds, expression, frame):
        """삼항식의 한쪽: `x if x in 목록 else 상수`의 x는 허용목록 안의 값이다 (스펙 3.6)."""
        saved = {}
        for name in self._allowed_names(test, holds, frame):
            saved[name] = frame.env.get(name)
            frame.env[name] = _checked(self._lookup(name, frame))
        value = self._eval(expression, frame)
        for name, previous in saved.items():
            if previous is None:
                frame.env.pop(name, None)
            else:
                frame.env[name] = previous
        return value

    def _eval_children(self, node, frame):
        groups = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.comprehension):
                child = child.iter
            if isinstance(child, ast.expr):
                groups.append(self._eval(child, frame))
        return groups

    def _lookup(self, name, frame):
        if name in frame.env:
            return frame.env[name]
        return self._module_value(name)

    def _module_value(self, name):
        """함수 안에서 대입한 적 없는 이름: 모듈 최상위의 정적 문자열(3.4)이거나 출처를 모르는 값."""
        if name not in self._module_values:
            parts = self._source.static.literal_parts(ast.Name(id=name, ctx=ast.Load()))
            if parts is None:
                value = single(Kind.UNKNOWN)
            else:
                value = static("".join(p if isinstance(p, str) else p.decode("latin-1") for p in parts))
            self._module_values[name] = value
        return self._module_values[name]

    def _eval_attribute(self, node, frame):
        if self._names.resolve(node) in self._source_attributes:
            return single(Kind.TAINTED, node.lineno)
        return collapse([self._eval(node.value, frame)], node.lineno, self._spec.sticky_tags)

    def _eval_subscript(self, node, frame):
        base = self._eval(node.value, frame)
        self._eval(node.slice, frame)
        if self._is_extra_source(node, frame):
            return single(Kind.TAINTED, node.lineno)
        if self._consts.is_string_dict(node.value, frame.function):
            return single(Kind.CHOICE, node.lineno, {"dict_subscript"})
        if self._consts.is_string_list(node.value, frame.function):
            return single(Kind.CHOICE, node.lineno, {"list_item"})
        return collapse([base], node.lineno, self._spec.sticky_tags)

    def _eval_call(self, node, frame):
        line = node.lineno
        name = self._names.resolve(node.func)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else None
        receiver = None
        if method is not None:
            receiver = self._eval(node.func.value, frame)
        elif not isinstance(node.func, ast.Name):
            self._eval(node.func, frame)
        if method == "join" and _is_literal_join(node, receiver):
            return self._eval_join(node, receiver, frame)
        values = {}  # id(인자 노드) → 값들
        for argument in (*node.args, *(keyword.value for keyword in node.keywords)):
            values[id(argument)] = self._eval(argument, frame)
        arguments = [values[id(argument)] for argument in node.args]

        sinks = [
            *self._sinks_by_function.get(name, ()),
            *(entry for entry in self._sinks_by_method.get(method, ()) if self._sink_applies(entry[1], node, frame)),
        ]
        if sinks:
            for mine, sink in sinks:
                argument = _sink_argument(node, sink) if mine else None
                if argument is not None:
                    self._record(frame, sink.role, node, values[id(argument)])
            return single(Kind.UNKNOWN, line)  # 도착점의 결과로는 오염을 전파하지 않는다
        if name in self._source_calls or self._is_extra_source(node, frame):
            return single(Kind.TAINTED, line)
        if self._spec.on_call is not None:
            keywords = {keyword.arg: values[id(keyword.value)] for keyword in node.keywords if keyword.arg}
            outcome = self._spec.on_call(
                CallInfo(node, name, method, receiver, tuple(arguments), keywords, frame.function, self._source)
            )
            if outcome == CLEAN:
                return single(Kind.UNKNOWN, line, {SANITIZED})
            if isinstance(outcome, Same):
                return outcome.group
            if isinstance(outcome, Update):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    frame.env[node.func.value.id] = add_line(outcome.group, line)
                return single(Kind.UNKNOWN, line)
            if isinstance(outcome, Marked):
                origin = first_part(merge(receiver or (), *values.values()), Kind.TAINTED)
                if origin is None:
                    return single(Kind.UNKNOWN, line, outcome.tags)
                return add_line(((Part(Kind.TAINTED, trail=origin.trail, tags=outcome.tags),),), line)
        if name == STATIC_TEXT_CALL and len(arguments) == 1 and not node.keywords:
            return arguments[0]
        if name in self._spec.sanitizers:
            return single(Kind.UNKNOWN, line, {SANITIZED})
        if name in self._spec.propagators:
            return concat(*arguments) if arguments else single(Kind.UNKNOWN, line)
        if self._consts.is_fixed_get(node, frame.function):
            return single(Kind.CHOICE, line, {"dict_get"})
        if method == "format":
            return self._eval_format(node, receiver, values)
        if name == "str" and len(arguments) == 1 and not node.keywords:
            return _stringified(arguments[0], line)
        function = self._functions.get(node.func.id) if isinstance(node.func, ast.Name) else None
        if function is not None and frame.call_line is None and not self._classifying:
            return self._follow(function, node, values)
        return self._eval_other_call(node, name, method, receiver, values)

    def _is_extra_source(self, node, frame):
        hook = self._spec.extra_source
        return hook is not None and hook(node, frame.function, self._source)

    def _sink_applies(self, sink, call, frame):
        """메서드 도착점이 객체를 한정했으면, 호출 대상이 그 객체인지 본다 (`requests.Session().get`)."""
        if not sink.objects:
            return True
        receiver = call.func.value
        if isinstance(receiver, ast.Call):
            return self._names.resolve(receiver.func) in sink.objects
        if not isinstance(receiver, ast.Name):
            return False
        created = self._objects.get((frame.function, receiver.id)) or self._objects.get((None, receiver.id), ())
        return not set(sink.objects).isdisjoint(created)

    def _eval_join(self, node, receiver, frame):
        """`"".join([a, b])`: 리스트 리터럴의 값들을 구분자와 함께 조각 그대로 이어 붙인다 (스펙 3.2)."""
        pieces = []
        for index, element in enumerate(node.args[0].elts):
            if index:
                pieces.append(receiver)
            pieces.append(self._eval(element, frame))
        return concat(*pieces)

    def _eval_other_call(self, node, name, method, receiver, values):
        """그 밖의 호출: 오염된 값의 메서드이거나 오염된 인자를 받았으면 결과도 오염이다."""
        if receiver is not None and first_part(receiver, Kind.TAINTED):
            subject = receiver
        else:
            method = None
            subject = next((group for group in values.values() if first_part(group, Kind.TAINTED)), None)
        if subject is None:
            return collapse([receiver or (), *values.values()], node.lineno)
        tags = added = frozenset()
        if self._spec.tagger is not None:
            texts = tuple(static_text(values[id(argument)]) for argument in node.args)
            keywords = tuple(keyword.arg for keyword in node.keywords)
            added = self._spec.tagger(TaggedCall(name, method, texts, keywords))
        if added or method in self._spec.tag_keeping_methods:
            kept = [part.tags for value in subject for part in value if part.kind is Kind.TAINTED]
            tags = frozenset.intersection(*kept) | added
        trail = first_part(subject, Kind.TAINTED).trail
        return add_line(((Part(Kind.TAINTED, trail=trail, tags=tags),),), node.lineno)

    def _follow(self, function, call, values):
        """같은 파일의 함수를 한 단계 따라 들어가 반환값을 구한다 (스펙 3.2). 그 안의 도착점도 기록된다."""
        callee = _Frame(function, self._bind_arguments(function, call, values), call_node=call)
        if not self._run_block(function.body, callee):
            callee.returns = merge(callee.returns, single(Kind.UNKNOWN, call.lineno))  # return 없이 끝나는 길
        return callee.returns or single(Kind.UNKNOWN, call.lineno)

    def _bind_arguments(self, function, call, values):
        line = call.lineno
        parameters = function.args.posonlyargs + function.args.args
        keyword_only = function.args.kwonlyargs
        env = {}
        loose = []  # 어느 매개변수로 갈지 알 수 없는 인자들 (*args, **kwargs, 남는 인자)
        position = 0
        for argument in call.args:
            value = add_line(values[id(argument)], line)
            if isinstance(argument, ast.Starred) or loose or position >= len(parameters):
                loose.append(value)
            else:
                env[parameters[position].arg] = value
                position += 1
        named = {parameter.arg for parameter in parameters + keyword_only}
        for keyword in call.keywords:
            value = add_line(values[id(keyword.value)], line)
            if keyword.arg in named:
                env[keyword.arg] = value
            else:
                loose.append(value)
        defaults = list(zip(parameters[len(parameters) - len(function.args.defaults):], function.args.defaults))
        defaults += [pair for pair in zip(keyword_only, function.args.kw_defaults) if pair[1] is not None]
        for parameter, default in defaults:
            if parameter.arg not in env and not loose:
                env[parameter.arg] = self._eval(default, _Frame(None, {}))
        rest = collapse(loose, line)  # 못 맞춘 인자에 오염이 있으면 남은 매개변수도 오염으로 본다
        for parameter in parameters + keyword_only:
            env.setdefault(parameter.arg, rest)
        for extra in (function.args.vararg, function.args.kwarg):
            if extra is not None:
                env[extra.arg] = rest
        return env

    def _record(self, frame, role, call, group):
        """도착점 호출(또는 명세가 고른 식) call의 위험한 자리에 group이 올 수 있다고 적는다."""
        if self._classifying:
            # 감싸기 함수는 이름으로 호출을 따라갈 수 있는 모듈 최상위 함수만 될 수 있다.
            # 메서드나 안쪽 함수는 호출한 곳을 찾을 수 없으므로 그 안에서 보고한다.
            exact = self._functions.get(frame.function.name) is frame.function and all(
                len(value) == 1 and value[0].kind is Kind.PARAM for value in group
            )
            self._exactness.setdefault(id(call), []).append(exact)
            return
        if frame.call_line is None and id(call) in self._exact:
            return  # 감싸기 함수: 이 안에서는 보고하지 않고 호출한 곳에서 판정한다
        key = (id(call), frame.call_line)
        if key not in self._hits:
            self._hits[key] = SinkHit(role, call, frame.call_node, id(call) in self._exact, [])
        hit = self._hits[key]
        hit.values.extend(value for value in group if value not in hit.values)

    def _eval_percent(self, node, frame):
        """`"... %s ..." % (a, b)`: 리터럴의 %s 자리에 값을 끼워 넣는다."""
        left = self._eval(node.left, frame)
        elements = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        items = [self._eval(element, frame) for element in elements]
        results = []
        for value in left:
            pieces = None if isinstance(node.right, ast.Dict) else _split_percent(value, len(items))
            if pieces is None:
                results.append(collapse([(value,), *items], node.lineno))  # 자리를 알 수 없다
            else:
                results.append(concat(*(static(p) if isinstance(p, str) else items[p] for p in pieces)))
        return merge(*results)

    def _eval_format(self, node, receiver, values):
        """`"... {} ...".format(a, b=c)`: 리터럴의 {} 자리에 값을 끼워 넣는다."""
        positional = [values[id(argument)] for argument in node.args]
        named = {keyword.arg: values[id(keyword.value)] for keyword in node.keywords}
        unpacked = any(isinstance(argument, ast.Starred) for argument in node.args) or None in named
        results = []
        for value in receiver:
            pieces = None if unpacked else _split_format(value)
            try:
                if pieces is None:
                    raise LookupError
                group = concat(
                    *(static(p) if isinstance(p, str) else positional[p] if isinstance(p, int) else named[p[0]]
                      for p in pieces)
                )
            except LookupError:  # 자리를 알 수 없다
                group = collapse([(value,), *positional, *named.values()], node.lineno)
            results.append(group)
        return merge(*results)


def _route_variables(routes):
    """라우트 함수 → URL 변수 이름들. 경로를 알 수 없는 라우트면 None (모든 매개변수를 URL 변수로 본다)."""
    variables = {}
    for route in routes:
        if route.func is None:
            continue
        known = variables.get(route.func, set())
        if route.path is None or known is None:
            variables[route.func] = None
        else:
            variables[route.func] = known | set(_URL_VARIABLE.findall(route.path))
    return variables


def _parameters(arguments):
    extras = [extra for extra in (arguments.vararg, arguments.kwarg) if extra is not None]
    return arguments.posonlyargs + arguments.args + arguments.kwonlyargs + extras


def _sink_argument(call, sink):
    """도착점 호출에서 위험한 인자 자리의 노드. 위치 인자에 없으면 키워드 이름으로 찾는다."""
    positional = call.args[: sink.arg + 1]
    if len(positional) > sink.arg and not any(isinstance(argument, ast.Starred) for argument in positional):
        return positional[sink.arg]
    for keyword in call.keywords:
        if keyword.arg in sink.keywords:
            return keyword.value
    return None


def _is_literal_join(node, receiver):
    """구분자가 정적이고 인자가 리스트 리터럴인 `sep.join([...])`인지."""
    return (
        len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.List)
        and is_all_static(receiver)
    )


def _created_objects(source):
    """(함수 또는 None, 변수 이름) → 그 변수를 만든 호출의 이름들 (대입, `with … as`)."""
    objects = {}
    for node, scope in iter_nodes_with_scope(source.tree):
        if isinstance(node, ast.withitem):
            pairs = [(node.optional_vars, node.context_expr)]
        else:
            pairs = assignment_pairs(node)
        for target, value in pairs:
            if isinstance(target, ast.Name) and isinstance(value, ast.Call):
                created = source.names.resolve(value.func)
                if created:
                    objects.setdefault((scope, target.id), set()).add(created)
    return objects


def _checked(group):
    """허용목록 검사를 통과한 값: 목록 안의 값 중 하나. 원래 사용자 입력이었으면 표시를 남긴다."""
    if is_all_static(group):
        return group  # 이미 고정된 값은 그대로 둔다
    tags = {"guard", "input"} if first_part(group, Kind.TAINTED) else {"guard"}
    trail = next((part.trail for value in group for part in value if part.kind is not Kind.STATIC), ())
    return ((Part(Kind.CHOICE, trail=trail, tags=frozenset(tags)),),)


def _as_source(group, line):
    """출발점으로 보는 이름의 변수에 대입된 값: 아직 오염되지 않았고 표시도 없는 값은 여기서 출발한 것으로 본다."""
    return merge(
        tuple(
            value
            if any(part.kind is Kind.TAINTED or part.tags for part in value)
            else (Part(Kind.TAINTED, trail=(line,)),)
            for value in group
        )
    )


def _stringified(group, line):
    """`str(x)`: 오염은 그대로 옮기고, 나머지는 문자열 리터럴이 아니므로 모르는 값이 된다."""
    converted = tuple(
        tuple(part if part.kind is Kind.TAINTED else Part(Kind.UNKNOWN, trail=part.trail) for part in value)
        for value in group
    )
    return merge(add_line(converted, line))


def _split_percent(value, count):
    """리터럴을 %s 자리에서 나눈다: 글자는 str, 끼울 자리는 인자 번호. 나눌 수 없으면 None."""
    if any(part.kind is not Kind.STATIC for part in value):
        return None
    text = "".join(part.text for part in value)
    pieces, position, index = [], 0, 0
    for match in _PERCENT.finditer(text):
        pieces.append(text[position : match.start()])
        position = match.end()
        if match.group(2) == "%":
            pieces.append("%")
        elif match.group(1) is not None:
            return None  # %(name)s
        else:
            pieces.append(index)
            index += 1
    pieces.append(text[position:])
    return pieces if index == count else None


def _split_format(value):
    """리터럴을 {} 자리에서 나눈다: 글자는 str, 끼울 자리는 인자 번호 또는 (이름,). 나눌 수 없으면 None."""
    if any(part.kind is not Kind.STATIC for part in value):
        return None
    text = "".join(part.text for part in value)
    pieces, automatic = [], 0
    try:
        for literal, field, _spec, _conversion in string.Formatter().parse(text):
            pieces.append(literal)
            if field is None:
                continue
            key = re.split(r"[.\[]", field, maxsplit=1)[0]
            if key == "":
                pieces.append(automatic)
                automatic += 1
            elif key.isdigit():
                pieces.append(int(key))
            else:
                pieces.append((key,))
    except ValueError:
        return None
    return pieces
