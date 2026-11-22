"""4.10 로그인 보안: 반복된 인증시도 제한 (login_attempt_limit): LOGIN-1 ~ LOGIN-4.

로그인 함수마다 실패 횟수 제한(카운터 또는 Flask-Limiter)이 있는지 확인한다.
조치가 빠졌는지를 찾는 규칙이다.
"""
import ast
import re

from ..astutil import (
    FUNCTION_NODES,
    assignment_pairs,
    call_argument,
    iter_nodes,
    iter_own_nodes,
    keyword_argument,
    string_value,
)
from ..facts import Conditions
from ..result import Finding
from ..routes import find_routes
from .password_storage import is_password_name

VULN_ID = "login_attempt_limit"

MAX_ATTEMPTS = 5  # N ≤ 5
VERIFY_CALLS = frozenset({"werkzeug.security.check_password_hash", "bcrypt.checkpw"})
# 공격자가 지울 수 없는 저장 위치: 모듈 수준 전역 변수, DB (ORM 객체의 속성 포함), Redis·캐시
SAFE_STORAGES = frozenset({"global", "db", "attr", "cache"})
DB_RESULT_METHODS = frozenset({"execute", "executemany", "fetchone", "fetchall", "fetchmany"})
COUNT_COMPARISONS = (ast.Gt, ast.GtE, ast.Lt, ast.LtE, ast.Eq)
MINUTE_OR_LONGER = frozenset({"minute", "hour", "day", "month", "year"})

# "5 per minute", "5/minute", "5 per 2 minutes"
_LIMIT = re.compile(r"(\d+)\s*(?:per\b|/)\s*(?:\d+\s*)?([a-z]+)", re.IGNORECASE)
_SQL_ADD_ONE = re.compile(r"\bupdate\b.*\bset\b.*?(\w+)\s*=\s*\1\s*\+\s*1", re.IGNORECASE | re.DOTALL)
_SQL_WRITE = re.compile(r"\s*(insert|update)\b", re.IGNORECASE)
_SQL_INSERT = re.compile(r"\s*insert\b", re.IGNORECASE)


def check(source):
    analysis = _Analysis(source)
    findings = []
    for function in analysis.login_functions():
        findings.extend(analysis.judge(function))
    return findings


class _Analysis:
    def __init__(self, source):
        self._source = source
        self._names = source.names
        self._conditions = Conditions(source)
        self._functions = {node.name: node for node in source.tree.body if isinstance(node, FUNCTION_NODES)}
        self._route_functions = list(
            dict.fromkeys(route.func for route in find_routes(source) if route.func is not None)
        )
        self._origins = {}
        self._config_ints = self._read_config_ints()
        self._default_limits = self._read_default_limits()

    def login_functions(self):
        """로그인 함수: 비밀번호 검증을 하는 라우트 함수. 폼만 보여 주는 함수는 대상이 아니다."""
        return [function for function in self._route_functions if self._verifications(function)]

    def judge(self, function):
        limits = [*self._limiter_limits(function), *self._default_limits]
        if any(strict for strict, _ in limits):
            return []  # 안전 B: Flask-Limiter
        body = self._body_with_helpers(function)
        increments = self._increments(body)
        comparisons = self._comparisons(body, {storage for storage, _ in increments})
        if not comparisons:
            if limits:
                return [Finding(limits[0][1], "LOGIN-2")]
            return [Finding(function.lineno, "LOGIN-1")]  # 제한 구조 없음
        # 안전 A: 카운터 하나라도 조건을 모두 채우면 된다. 아니면 문제가 가장 적은 카운터의 문제를 알려 준다.
        verifications = [(node, self._tests_known_around(node)) for node in self._verifications(function)]
        candidates = []
        for storage, limit, comparison in comparisons:
            problems = []
            if storage[0] not in SAFE_STORAGES:
                line = next(line for stored, line in increments if stored == storage)
                problems.append(Finding(line, "LOGIN-3"))
            if limit is None or limit > MAX_ATTEMPTS:  # N을 코드에서 알 수 없거나 너무 크다
                problems.append(Finding(comparison.lineno, "LOGIN-2"))
            for node, known in verifications:
                if id(comparison) not in known:
                    problems.append(Finding(node.lineno, "LOGIN-4"))  # 잠금 확인 없이 비밀번호만 본다
                    break
            candidates.append(problems)
        return min(candidates, key=len)

    # ---- 로그인 함수와 비밀번호 검증 ----

    def _verifications(self, function):
        """함수 안의 비밀번호 검증 지점들. 같은 파일의 함수가 검증하면 그 호출도 검증 지점이다 (한 단계)."""
        found = []
        for node in iter_own_nodes(function):
            if self._is_verification(node, function):
                found.append(node)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                helper = self._functions.get(node.func.id)
                if helper is not None and helper is not function and any(
                    self._is_verification(inner, helper) for inner in iter_own_nodes(helper)
                ):
                    found.append(node)
        return found

    def _is_verification(self, node, scope):
        """`check_password_hash`, `bcrypt.checkpw`, 해시값의 `==`, 비밀번호 이름 값의 평문 `==`/`!=` 비교."""
        if isinstance(node, ast.Call):
            return self._names.resolve(node.func) in VERIFY_CALLS
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            sides = (node.left, node.comparators[0])
            return any(self._is_hash(side, scope) or _is_password_value(side) for side in sides)
        return False

    def _is_hash(self, node, scope):
        """hashlib으로 만든 해시 값인지 (변수면 대입된 식을 본다)."""
        if isinstance(node, ast.Name):
            node = self._source.static.sole_value(node.id, scope) or node
        for inner in iter_nodes(node):
            if isinstance(inner, ast.Call):
                name = self._names.resolve(inner.func) or ""
                if name.startswith("hashlib.") or name.endswith(".hexdigest"):
                    return True
                if isinstance(inner.func, ast.Attribute) and inner.func.attr == "hexdigest":
                    return True
        return False

    def _tests_known_around(self, verification):
        """검증 지점에 도달했을 때와 검증에 성공한 뒤에 확정된 조건식들 (id로 모은다)."""
        facts = list(self._conditions.known_at(verification))
        branch = self._conditions.branch_of(verification)
        if branch is not None:
            statement, same_direction = branch
            failure_test = isinstance(verification, ast.Compare) and isinstance(verification.ops[0], ast.NotEq)
            succeeded = same_direction != failure_test  # 검증에 성공했을 때 if 조건식의 참/거짓
            facts += self._conditions.known_at(statement)
            facts += self._conditions.expand(statement.test, succeeded, self._conditions.function_of(statement))
        return {id(fact.test) for fact in facts}

    # ---- Flask-Limiter ----

    def _limiter_limits(self, function):
        """`@limiter.limit("N per ...")` 데코레이터들의 (기준을 채우는지, 줄 번호)."""
        limits = []
        for decorator in function.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "limit"
                and decorator.args
            ):
                limits.append((_is_strict_limit(self._static_text(decorator.args[0], None)), decorator.lineno))
        return limits

    def _read_default_limits(self):
        """`Limiter(..., default_limits=[...])`들의 (기준을 채우는 제한이 있는지, 줄 번호)."""
        limits = []
        for node in iter_nodes(self._source.tree):
            if not (isinstance(node, ast.Call) and self._names.resolve(node.func) == "flask_limiter.Limiter"):
                continue
            value = keyword_argument(node, "default_limits")
            if value is None:
                continue
            elements = value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]
            strict = any(_is_strict_limit(self._static_text(element, None)) for element in elements)
            limits.append((strict, value.lineno))
        return limits

    # ---- 실패 횟수 카운터 ----

    def _body_with_helpers(self, function):
        """(노드, 그 노드가 있는 함수)들: 로그인 함수와, 거기서 부르는 같은 파일 함수 한 단계."""
        body = [(node, function) for node in iter_own_nodes(function)]
        helpers = []
        for node, _ in list(body):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                helper = self._functions.get(node.func.id)
                if helper is not None and helper is not function and helper not in helpers:
                    helpers.append(helper)
        for helper in helpers:
            body.extend((node, helper) for node in iter_own_nodes(helper))
        return body

    def _increments(self, body):
        """횟수를 늘리는 곳의 (저장 위치, 줄 번호)들."""
        found = []
        for node, scope in body:
            origins = self._origins_in(scope)
            storages = set()
            if isinstance(node, ast.AugAssign):
                if isinstance(node.op, ast.Add) and _is_step(node.value):
                    storages = origins.storage_of_target(node.target)  # n += 1
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                for target, value in assignment_pairs(node):
                    if origins.adds_one(value):
                        storages |= origins.storage_of_target(target) or origins.of(value)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "set_cookie" and any(origins.adds_one(argument) for argument in node.args):
                    storages = {("cookie",)}
                elif node.func.attr in ("execute", "executemany") and self._sql_increments(node, origins, scope):
                    storages = {("db",)}
                elif node.func.attr == "incr":  # Redis·캐시
                    storages = {("cache", ast.unparse(node.func.value))}
            found.extend((storage, node.lineno) for storage in sorted(storages))
        return found

    def _sql_increments(self, call, origins, scope):
        """`UPDATE … SET n = n + 1`, 늘린 값을 넣는 UPDATE, 실패 기록을 쌓는 INSERT인지."""
        query = self._static_text(call_argument(call, 0, "query"), scope) or ""
        if _SQL_ADD_ONE.search(query) or _SQL_INSERT.match(query):
            return True
        parameters = call_argument(call, 1, "args")
        elements = parameters.elts if isinstance(parameters, (ast.Tuple, ast.List)) else []
        return bool(_SQL_WRITE.match(query)) and any(origins.adds_one(element) for element in elements)

    def _comparisons(self, body, storages):
        """카운터를 N과 비교하는 곳의 (저장 위치, N, 비교식)들. N을 코드에서 알 수 없으면 None이다."""
        found = []
        for node, scope in body:
            if not (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], COUNT_COMPARISONS)
            ):
                continue
            origins = self._origins_in(scope)
            for count, limit in ((node.left, node.comparators[0]), (node.comparators[0], node.left)):
                if isinstance(limit, ast.Constant) and type(limit.value) is not int:
                    continue  # None, 문자열과의 비교는 횟수 비교가 아니다
                number = self._int_constant(limit, scope)
                for storage in sorted(origins.of(count) & storages):
                    found.append((storage, number, node))
        return found

    def _origins_in(self, function):
        if function not in self._origins:
            self._origins[function] = _Origins(self._source, function)
        return self._origins[function]

    def _int_constant(self, node, scope):
        """정수 리터럴, 같은 파일에서 정수로 정한 이름·`app.config` 값이면 그 값, 아니면 None."""
        if isinstance(node, ast.Name):
            node = self._source.static.sole_value(node.id, scope)
        key = self._config_key(node)
        if key is not None:
            values = self._config_ints.get(key, ())
            return next(iter(values)) if len(values) == 1 else None
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        return None

    def _config_key(self, node):
        """`app.config["KEY"]`, `app.config.get("KEY")`의 키. 아니면 None."""
        if isinstance(node, ast.Subscript) and self._names.is_app_config(node.value):
            return string_value(node.slice)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and self._names.is_app_config(node.func.value)
            and node.args
        ):
            return string_value(node.args[0])
        return None

    def _read_config_ints(self):
        """`app.config` 키 → 파일 안에서 대입된 값들 (정수가 아니면 None)."""
        values = {}
        for node in iter_nodes(self._source.tree):
            pairs = [
                (string_value(target.slice), value)
                for target, value in assignment_pairs(node)
                if isinstance(target, ast.Subscript) and self._names.is_app_config(target.value)
            ]
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "update"
                and self._names.is_app_config(node.func.value)
            ):
                pairs += [(keyword.arg, keyword.value) for keyword in node.keywords]
            for key, value in pairs:
                number = value.value if isinstance(value, ast.Constant) and type(value.value) is int else None
                values.setdefault(key, set()).add(number)
        return values

    def _static_text(self, node, scope):
        if node is None:
            return None
        parts = self._source.static.literal_parts(node, scope)
        if parts is None or not all(isinstance(part, str) for part in parts):
            return None
        return "".join(parts)


class _Origins:
    """함수 하나에서, 식의 값이 어디에 저장된 것에서 왔는지 찾는다.

    저장 위치: ("global", 이름), ("session",), ("cookie",), ("db",), ("attr", 속성 이름), ("local", 이름)
    """

    def __init__(self, source, function):
        self._source = source
        self._names = source.names
        arguments = function.args
        self._parameters = {
            argument.arg for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs
        }
        self._global_names = set()
        self._assigned = {}  # 함수 안에서 대입된 이름 → 대입된 값 식들
        self._augmented = set()  # `n += 1`처럼 늘어나는 이름
        for node in iter_own_nodes(function):
            if isinstance(node, ast.Global):
                self._global_names.update(node.names)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                self._assigned.setdefault(node.target.id, [])
                if isinstance(node.op, ast.Add) and _is_step(node.value):
                    self._augmented.add(node.target.id)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self._bind(node.target, node.iter)
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                self._bind(node.optional_vars, node.context_expr)
            for target, value in assignment_pairs(node):
                self._bind(target, value)

    def _bind(self, target, value):
        for node in iter_nodes(target):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self._assigned.setdefault(node.id, []).append(value)

    def of(self, node, seen=frozenset()):
        if isinstance(node, ast.Name):
            return self._of_name(node, seen)
        if isinstance(node, ast.Attribute):
            resolved = self._names.resolve(node)
            if resolved == "flask.request.cookies":
                return {("cookie",)}
            if resolved == "flask.session":
                return {("session",)}
            return self.of(node.value, seen) | {("attr", node.attr)}
        if isinstance(node, ast.Subscript):
            return self.of(node.value, seen)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in DB_RESULT_METHODS:
                return {("db",)}
            return self.of(node.func.value, seen) | {("cache", ast.unparse(node.func.value))}
        found = set()
        children = node.args if isinstance(node, ast.Call) else ast.iter_child_nodes(node)
        for child in children:
            if isinstance(child, ast.expr):
                found |= self.of(child, seen)
        return found

    def _of_name(self, node, seen):
        name = node.id
        if self._names.resolve(node) == "flask.session":
            return {("session",)}
        if name in self._global_names:
            return {("global", name)}
        if name in self._assigned:
            if name in seen:
                return set()
            found = set()
            for value in self._assigned[name]:
                found |= self.of(value, seen | {name})
            return found or {("local", name)}  # 상수로만 만든 지역 변수
        if name not in self._parameters and self._source.static.is_module_variable(name):
            return {("global", name)}
        return set()

    def storage_of_target(self, target):
        """대입 대상이 가리키는 저장 위치."""
        if isinstance(target, ast.Attribute):
            return {("attr", target.attr)}
        if isinstance(target, ast.Subscript):
            return self.of(target.value)
        if isinstance(target, ast.Name):
            return self.of(target)
        return set()

    def adds_one(self, node):
        """`… + 1`로 늘린 값인지 (변수면 그 변수에 대입된 식까지 본다)."""
        if isinstance(node, ast.Name):
            if node.id in self._augmented:
                return True
            return any(_has_add_one(value) for value in self._assigned.get(node.id, ()))
        return _has_add_one(node)


def _is_strict_limit(text):
    """Flask-Limiter 제한 문구에 N ≤ 5이고 단위가 분 이상인 제한이 하나라도 있는지."""
    return any(
        int(number) <= MAX_ATTEMPTS and unit.lower().rstrip("s") in MINUTE_OR_LONGER
        for number, unit in _LIMIT.findall(text or "")
    )


def _is_password_value(node):
    """비밀번호 이름의 값인지: `password`, `user.password`, `row["pw"]`, `form.get("password")`."""
    if isinstance(node, ast.Name):
        return is_password_name(node.id)
    if isinstance(node, ast.Attribute):
        return is_password_name(node.attr)
    if isinstance(node, ast.Subscript):
        return is_password_name(string_value(node.slice) or "")
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
        return is_password_name(string_value(node.args[0]) or "")
    return False


def _is_step(node):
    """횟수를 늘리는 양의 정수 상수인지."""
    return isinstance(node, ast.Constant) and type(node.value) is int and node.value >= 1


def _has_add_one(node):
    for inner in iter_nodes(node):
        if isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.Add):
            if _is_step(inner.left) or _is_step(inner.right):
                return True
    return False
