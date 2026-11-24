"""소스 읽기: 문법 검사, 주석, 가져온 이름, 고정 문자열 (스펙 1장, 3장). 코드는 실행하지 않는다."""
import ast
import io
import tokenize
from dataclasses import dataclass
from functools import cached_property

FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


class SourceSyntaxError(Exception):
    def __init__(self, line):
        super().__init__(line)
        self.line = line
        self.message = f"{line}번째 줄에 문법 오류가 있어요."


@dataclass(frozen=True)
class Comment:
    line: int  # 1부터
    text: str  # `#`부터 줄 끝까지 그대로


def normalize(code):
    """BOM을 떼고 줄바꿈을 `\\n`으로 통일한다. 줄 번호는 이 글 기준이다."""
    return code.removeprefix("﻿").replace("\r\n", "\n").replace("\r", "\n")


def parse_source(code):
    text = normalize(code)
    try:
        tree = ast.parse(text)
    except SyntaxError as error:
        raise SourceSyntaxError(error.lineno or 1) from error
    except (ValueError, RecursionError, MemoryError) as error:
        raise SourceSyntaxError(1) from error
    return Source(text, tree)


class Source:
    def __init__(self, text, tree):
        self.text = text
        self.tree = tree
        self.lines = text.split("\n")
        self.comments = _comments(text)
        self.names = Names(tree)
        self.static = StaticStrings(tree)

    @cached_property
    def flow(self):
        """흐름 분석 결과. 필요한 규칙이 처음 볼 때 한 번만 계산한다."""
        from .flow import analyze_flow

        return analyze_flow(self)


def _comments(text):
    comments = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                comments.append(Comment(token.start[0], token.string))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return comments


def iter_nodes_with_scope(tree):
    """(노드, 그 노드가 들어 있는 함수 또는 None)을 소스 순서대로. 데코레이터와 기본값은 바깥 스코프다."""
    def visit(node, scope):
        yield node, scope
        if isinstance(node, FUNCTION_NODES):
            for outer in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
                if outer is not None:
                    yield from visit(outer, scope)
            if node.returns is not None:
                yield from visit(node.returns, scope)
            for statement in node.body:
                yield from visit(statement, node)
        else:
            for child in ast.iter_child_nodes(node):
                yield from visit(child, scope)

    yield from visit(tree, None)


class Names:
    """import로 들여온 이름을 원래의 점 이름으로 푼다: `rq.get` → `requests.get`."""

    def __init__(self, tree):
        self.aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.aliases[alias.asname] = alias.name
                    else:
                        root = alias.name.split(".")[0]
                        self.aliases[root] = root
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def resolve(self, node):
        """Name·Attribute 사슬을 점 이름으로. import한 이름에서 시작하지 않으면 None."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        return None


class StaticStrings:
    """코드에 적어 둔 값인지 본다: 리터럴과, 리터럴만 대입된 이름으로 만든 문자열 (스펙 4.8)."""

    def __init__(self, tree):
        self._assigned = {}  # (id(스코프) 또는 0, 이름) → [(값 노드, 스코프)]
        self._dynamic = set()  # 리터럴이 아닌 방식으로 값이 정해지는 (스코프, 이름)
        for node, scope in iter_nodes_with_scope(tree):
            key = id(scope) if scope is not None else 0
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._note(target, node.value, scope, key)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                self._note(node.target, node.value, scope, key)
            elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor, ast.NamedExpr)):
                self._mark_dynamic(node.target, key)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        self._mark_dynamic(item.optional_vars, key)
            elif isinstance(node, FUNCTION_NODES):
                arguments = node.args
                for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                                 arguments.vararg, arguments.kwarg):
                    if argument is not None:
                        self._dynamic.add((id(node), argument.arg))
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self._dynamic.add((key, node.name))

    def _note(self, target, value, scope, key):
        if isinstance(target, ast.Name):
            self._assigned.setdefault((key, target.id), []).append((value, scope))
        else:
            self._mark_dynamic(target, key)

    def _mark_dynamic(self, target, key):
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                self._dynamic.add((key, node.id))

    def assigned_values(self, name, scope):
        """그 이름에 대입된 (값 노드, 스코프)들. 함수 안에서 찾지 못하면 모듈 최상위를 본다."""
        for key in ((id(scope),) if scope is not None else ()) + (0,):
            if (key, name) in self._dynamic:
                return None
            if (key, name) in self._assigned:
                return self._assigned[(key, name)]
        return None

    def parts(self, node, scope, _seen=()):
        """node가 고정 문자열이면 그 조각(str·bytes)들, 아니면 None."""
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, bytes)):
                return [node.value]
            if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
                return [node.value]  # 숫자는 문자열에 끼어 있을 수 있지만 그 자체로 비밀 값은 아니다
            return None
        if isinstance(node, ast.JoinedStr):
            return self._all(
                [item.value if isinstance(item, ast.FormattedValue) else item for item in node.values], scope, _seen
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._all([node.left, node.right], scope, _seen)
        if isinstance(node, ast.Tuple):
            return self._all(node.elts, scope, _seen)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and not any(keyword.arg is None for keyword in node.keywords)
        ):
            return self._all([node.func.value, *node.args, *[k.value for k in node.keywords]], scope, _seen)
        if isinstance(node, ast.Name) and node.id not in _seen:
            assigned = self.assigned_values(node.id, scope)
            if not assigned:
                return None
            pieces = []
            for value, value_scope in assigned:
                found = self.parts(value, value_scope, (*_seen, node.id))
                if found is None:
                    return None
                pieces += found
            return pieces
        return None

    def _all(self, nodes, scope, seen):
        pieces = []
        for node in nodes:
            found = self.parts(node, scope, seen)
            if found is None:
                return None
            pieces += found
        return pieces

    def is_hardcoded(self, node, scope):
        """비어 있지 않은 고정 문자열인지."""
        pieces = self.parts(node, scope)
        return pieces is not None and any(isinstance(piece, (str, bytes)) and piece for piece in pieces)
