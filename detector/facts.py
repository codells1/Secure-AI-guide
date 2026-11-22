"""조건 분석: 코드의 한 지점에 도달했을 때 참·거짓이 확정된 조건식을 구한다.

"있어야 할 검사가 빠졌는지"를 볼 때 쓴다 (파일 업로드, 로그인 시도 제한).
검사는 그 결과로 분기해서 실패 시 중단하는 경우만 인정한다 (스펙 3.5 검사 함수 따라가기).
중단은 return, abort(), raise, 반복문 안의 continue다 (스펙 3.6).
"""
import ast
from dataclasses import dataclass

from .astutil import FUNCTION_NODES, iter_nodes, iter_own_nodes
from .names import ABORT_CALLS


@dataclass(frozen=True)
class Fact:
    test: ast.expr  # 조건식
    holds: bool  # 그 조건식이 참으로 확정됐는지, 거짓으로 확정됐는지
    scope: ast.AST | None  # 조건식이 있는 함수 (그 안의 이름을 풀 때 쓴다)


class Conditions:
    def __init__(self, source):
        self._source = source
        self._parents = {}  # id(노드) → (부모, 부모의 필드 이름, 목록 안에서의 순서 또는 None)
        for parent in iter_nodes(source.tree):
            for field, value in ast.iter_fields(parent):
                if isinstance(value, list):
                    for index, child in enumerate(value):
                        if isinstance(child, ast.AST):
                            self._parents[id(child)] = (parent, field, index)
                elif isinstance(value, ast.AST):
                    self._parents[id(value)] = (parent, field, None)
        self._functions = {
            node.name: node for node in source.tree.body if isinstance(node, FUNCTION_NODES)
        }

    def parent_of(self, node):
        """node를 직접 품고 있는 노드. 없으면 None."""
        entry = self._parents.get(id(node))
        return entry[0] if entry else None

    def function_of(self, node):
        """node가 들어 있는 함수. 모듈 최상위면 None."""
        while id(node) in self._parents:
            node = self._parents[id(node)][0]
            if isinstance(node, FUNCTION_NODES):
                return node
        return None

    def known_at(self, node):
        """node가 실행될 때 참·거짓이 확정된 조건들 (낱개 조건으로 푼 것)."""
        scope = self.function_of(node)
        facts = []
        for test, holds in self._enclosing_tests(node):
            facts.extend(self.expand(test, holds, scope))
        if scope is not None:
            facts.extend(self._decorator_facts(scope))
        return facts

    def _decorator_facts(self, function):
        """같은 파일에 정의된 데코레이터가 원래 함수를 부르기 전에 확정한 조건들 (1단계)."""
        facts = []
        for decorator in function.decorator_list:
            helper = self._functions.get(decorator.id) if isinstance(decorator, ast.Name) else None
            if helper is None or not helper.args.args:
                continue
            wrapped = helper.args.args[0].arg
            for inner in iter_nodes(helper):
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id == wrapped:
                    scope = self.function_of(inner)
                    for test, holds in self._enclosing_tests(inner):
                        facts.extend(self.expand(test, holds, scope))
        return facts

    def branch_of(self, node):
        """node의 결과로 갈리는 if문을 찾는다: (그 if문, node가 참일 때 조건식도 참이 되는 쪽인지).

        node가 if 조건식 안에 있거나, 변수에 담긴 뒤 그 변수가 if 조건식에 쓰이는 경우를 본다. 없으면 None.
        """
        positive = True
        current = node
        while id(current) in self._parents:
            parent, field, _ = self._parents[id(current)]
            if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
                positive = not positive
            elif isinstance(parent, ast.If) and field == "test":
                return parent, positive
            elif isinstance(parent, ast.stmt):
                return self._branch_on_variable(parent, positive)
            current = parent
        return None

    def _branch_on_variable(self, statement, positive):
        """`ok = <검사>` 뒤에 `ok`를 조건식에 쓰는 첫 if문."""
        function = self.function_of(statement)
        if not (
            function is not None
            and isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            return None
        name = statement.targets[0].id
        for candidate in iter_own_nodes(function):
            if not (isinstance(candidate, ast.If) and candidate.lineno > statement.lineno):
                continue
            for inner in iter_nodes(candidate.test):
                if isinstance(inner, ast.Name) and inner.id == name:
                    branch, same_direction = self.branch_of(inner)
                    return branch, same_direction == positive
        return None

    def expand(self, test, holds, scope, follow_calls=True, seen=()):
        """(조건식, 참/거짓)을 and/or/not, 변수, 같은 파일의 검사 함수를 따라가며 낱개 조건으로 푼다."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.expand(test.operand, not holds, scope, follow_calls, seen)
        if isinstance(test, ast.BoolOp):
            if isinstance(test.op, ast.And) != holds:
                return []  # (A and B)가 거짓이거나 (A or B)가 참: 어느 쪽 때문인지 알 수 없다
            return [
                fact
                for operand in test.values
                for fact in self.expand(operand, holds, scope, follow_calls, seen)
            ]
        facts = [Fact(test, holds, scope)]
        if isinstance(test, ast.Name) and test.id not in seen:
            definition = self._source.static.sole_value(test.id, scope)
            if definition is not None:
                facts += self.expand(definition, holds, scope, follow_calls, (*seen, test.id))
        elif follow_calls and isinstance(test, ast.Call) and isinstance(test.func, ast.Name):
            function = self._functions.get(test.func.id)
            if function is not None:
                facts += self._facts_from_call(function, holds)
        return facts

    def _enclosing_tests(self, node):
        """node를 감싼 분기와, 같은 블록에서 앞서 "검사 후 중단"한 if의 (조건식, 참/거짓)."""
        current = node
        while id(current) in self._parents:
            parent, field, index = self._parents[id(current)]
            if index is not None and field in ("body", "orelse", "finalbody"):
                for statement in getattr(parent, field)[:index]:
                    if isinstance(statement, ast.If):
                        body_stops = self._stops(statement.body)
                        else_stops = self._stops(statement.orelse)
                        if body_stops != else_stops:
                            # 본문에서 중단했다면 여기까지 온 것은 조건이 거짓이었다는 뜻이다.
                            yield statement.test, else_stops
            if isinstance(parent, (ast.If, ast.While, ast.IfExp)):
                if field == "body":
                    yield parent.test, True
                elif field == "orelse" and not isinstance(parent, ast.While):
                    yield parent.test, False
            elif isinstance(parent, ast.BoolOp) and field == "values":
                # `A and B`의 B는 A가 참일 때만, `A or B`의 B는 A가 거짓일 때만 계산된다.
                for operand in parent.values[:index]:
                    yield operand, isinstance(parent.op, ast.And)
            if isinstance(parent, (*FUNCTION_NODES, ast.Lambda, ast.ClassDef)):
                break
            current = parent

    def _stops(self, block):
        """블록이 항상 중단(return, abort, raise, continue)으로 끝나는지."""
        if not block:
            return False
        last = block[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue)):
            return True
        if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
            return self._source.names.resolve(last.value.func) in ABORT_CALLS
        if isinstance(last, ast.If):
            return self._stops(last.body) and self._stops(last.orelse)
        return False

    def _facts_from_call(self, function, holds):
        """검사 함수가 holds를 돌려줬다면 그 안에서 확정된 조건들. 한 단계만 따라간다."""
        returns = [
            node for node in iter_own_nodes(function) if isinstance(node, ast.Return) and node.value is not None
        ]
        # 반대 결과를 돌려주는 return은 뺀다: 참을 돌려받았다면 `return False`에서 온 것이 아니다.
        candidates = [
            node
            for node in returns
            if not (isinstance(node.value, ast.Constant) and bool(node.value.value) != holds)
        ]
        if len(candidates) != 1:
            return []
        (chosen,) = candidates
        facts = []
        for test, value in self._enclosing_tests(chosen):
            facts += self.expand(test, value, function, follow_calls=False)
        if not isinstance(chosen.value, ast.Constant):
            facts += self.expand(chosen.value, holds, function, follow_calls=False)
        return facts
