"""4.5 부적절한 인가 / IDOR (idor): IDOR-1 ~ IDOR-4.

라우트 함수가 URL 변수나 id류 요청값으로 DB를 조회·수정·삭제하는데 세션 사용자 기준의 검증이 없으면,
먼저 학생에게 본인만 봐야 하는 페이지인지 묻고(스펙 5장), 그렇다고 답한 라우트만 위험으로 판정한다.
"""
import ast
import re
from dataclasses import dataclass

from ..astutil import iter_nodes, iter_own_nodes, string_value
from ..dbcalls import binding_elements, is_execute, query_and_parameters
from ..facts import Conditions
from ..naming import has_word, split_words
from ..result import Finding
from ..routes import find_routes
from ..taint import Kind, TaintSpec, find_sink_hits, register
from .password_storage import is_password_name

VULN_ID = "idor"
QUESTION = "이 페이지에 나오는 정보는 로그인한 본인만 봐야 하나요?"

# 요청값 가운데 id류로 보는 키: 이름을 단어로 나눴을 때 이 낱말이 있으면 해당한다.
ID_WORDS = ("id", "uid", "idx", "no", "num", "seq", "pk", "userid")
# 이 낱말의 키도 id류지만, 같은 함수가 비밀번호를 읽으면(로그인·가입·비밀번호 변경) 후보가 아니다.
IDENTITY_WORDS = ("username", "email")
EXCLUDED_KEY_WORDS = ("page",)  # page_no 같은 페이지 번호
# 소유자 필드 이름 사전. CREATE TABLE에서 users를 참조하는 컬럼도 더한다.
OWNER_FIELDS = frozenset({"user_id", "owner_id", "author_id", "writer_id"})
USER_TABLES = frozenset({"users", "user"})
ADMIN_VALUES = frozenset({"admin", "administrator", "관리자"})
ADMIN_FLAG = "is_admin"
# 역할 검사로 보는 세션 키 사전
ROLE_KEYS = frozenset({"role", "is_admin", "admin", "level", "grade", "권한", "등급"})
ORM_LOOKUPS = frozenset({"get", "filter_by", "filter", "where"})

QUERY, BINDING, ORM = "query", "binding", "orm"

# 비교식의 한쪽이 무엇인지
SESSION = "session"  # 세션 사용자: session[...], current_user, g.user
REQUEST = "request"  # 요청값, URL 변수
OWNER_FIELD = "owner_field"  # 조회한 객체의 소유자 필드
OTHER_FIELD = "field"  # 그 밖의 필드
ADMIN_VALUE = "admin_value"  # "admin", "관리자" 같은 관리자 값
OTHER_VALUE = "value"  # 그 밖의 문자열 상수
OTHER = "other"

# 확정된 조건이 뜻하는 검증
OWNER_CHECK = "owner"  # 안전 1: 세션 사용자와 소유자가 같다
ADMIN_CHECK = "admin"  # 안전 3: 세션 기반 관리자 검사
BAD_CHECK = "bad"  # IDOR-3: 요청값과 비교하거나 소유자 필드가 아닌 필드와 비교
ROLE_CHECK = "role"  # IDOR-4: 관리자가 아닌 역할만 확인
LOGIN_CHECK = "login"  # IDOR-2: 로그인 여부만 확인

_EQUAL_MEANS = {
    frozenset({SESSION, OWNER_FIELD}): OWNER_CHECK,
    frozenset({SESSION, ADMIN_VALUE}): ADMIN_CHECK,
    frozenset({SESSION, OTHER_VALUE}): ROLE_CHECK,
    frozenset({SESSION, OTHER_FIELD}): BAD_CHECK,
    frozenset({OWNER_FIELD, REQUEST}): BAD_CHECK,
    frozenset({REQUEST, ADMIN_VALUE}): BAD_CHECK,  # 역할 값을 요청에서 읽었다
}

_SELECT = re.compile(r"\s*select\s+(?:distinct\s+)?(.*?)\s+from\s+[`\"']?(\w+)", re.IGNORECASE | re.DOTALL)
_CREATE_TABLE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?[`\"']?(\w+)[`\"']?\s*\(", re.IGNORECASE)
_REFERENCES_USERS = re.compile(r"references\s+[`\"']?users\b", re.IGNORECASE)
_FOREIGN_KEY = re.compile(r"foreign\s+key\s*\(([^)]*)\)", re.IGNORECASE)
_CONSTRAINTS = frozenset({"primary", "foreign", "unique", "check", "constraint"})
_TABLE = re.compile(r"\b(?:from|update|into)\s+[`\"']?(\w+)", re.IGNORECASE)
_POSITIONAL = re.compile(r"(?:([\w.`\"]+)\s*=\s*)?(?:\?|%s)")  # 자리표시자마다 비교되는 컬럼
_NAMED = re.compile(r"([\w.`\"]+)\s*=\s*(?::(\w+)|%\((\w+)\)s)")


def _request_key(node):
    """`x["id"]`, `x.get("id")` 형태의 키. 아니면 None."""
    if isinstance(node, ast.Subscript):
        return string_value(node.slice)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
        return string_value(node.args[0])
    return None


def _from_request(node, scope, source):
    """요청에서 꺼낸 값인지: `request.…`, 또는 요청값을 담아 둔 변수(`data = request.get_json()`)."""
    root, _ = _chain(node)
    if root is None:
        return False
    if source.names.resolve(root) == "flask.request":
        return True
    definition = source.static.sole_value(root.id, scope)
    if definition is None:
        return False
    # `data = request.get_json() or {}`도 요청값이다
    choices = definition.values if isinstance(definition, ast.BoolOp) else [definition]
    roots = (_chain(choice)[0] for choice in choices)
    return any(name is not None and source.names.resolve(name) == "flask.request" for name in roots)


def _reads_password(scope, source):
    """같은 함수가 비밀번호 이름의 요청값을 읽는지 (로그인·회원가입·비밀번호 변경)."""
    if scope is None:
        return False
    return any(
        is_password_name(_request_key(node) or "") and _from_request(node, scope, source)
        for node in iter_own_nodes(scope)
    )


def _is_id_request_value(node, scope, source):
    """`request.args["id"]`, `data.get("post_id")`처럼 id류 키로 요청 값을 꺼내는 식인지."""
    key = _request_key(node)
    if not key or has_word(key, EXCLUDED_KEY_WORDS):
        return False
    is_id = has_word(key, ID_WORDS)
    if not is_id and not has_word(key, IDENTITY_WORDS):
        return False
    if not _from_request(node, scope, source):
        return False
    return is_id or not _reads_password(scope, source)


def _db_arguments(source):
    """DB 호출에 넘기는 값들: execute()의 쿼리와 바인딩 값, ORM 조회(`Model.query.get(id)` 등)의 인자."""
    for node in iter_nodes(source.tree):
        if is_execute(node):
            query, parameters = query_and_parameters(node)
            if query is not None:
                yield query, QUERY
            for element in binding_elements(parameters):
                yield element, BINDING
        elif _is_orm_lookup(node):
            for argument in (*node.args, *(keyword.value for keyword in node.keywords)):
                yield argument, ORM


def _is_orm_lookup(node):
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr == "get_or_404":
        return True
    if node.func.attr not in ORM_LOOKUPS:
        return False
    _, names = _chain(node.func.value)
    return "query" in names or "session" in names  # Model.query.…, db.session.…


SPEC = register(
    TaintSpec(
        vuln_id=VULN_ID,
        sinks=(),
        source_attributes=frozenset(),
        source_calls=frozenset(),
        probes=_db_arguments,
        extra_source=_is_id_request_value,
    )
)


def evaluate(source, user_input):
    """(findings, needs_user_input)을 돌려준다. needs_user_input이 있으면 아직 판정하지 않은 것이다."""
    candidates = _Analysis(source).unverified_candidates()
    if not candidates:
        return [], None
    answer = user_input.get(VULN_ID)
    if not isinstance(answer, dict):
        routes = [
            {"function": candidate.function, "route": route.path, "line": route.line}
            for candidate in candidates
            for route in candidate.routes
        ]
        return [], {"type": "idor_routes", "question": QUESTION, "routes": routes}
    listed = answer.get("public_functions")
    public = {name for name in listed if isinstance(name, str)} if isinstance(listed, list) else set()
    # 공개라고 답한 함수는 후보에서 뺀다. 목록에 없는 후보는 본인만 봐야 한다고 답한 것으로 본다.
    return [
        Finding(candidate.line, candidate.rule_id)
        for candidate in candidates
        if candidate.function not in public
    ], None


@dataclass(frozen=True)
class _Candidate:
    function: str  # 라우트 함수 이름 (학생 응답의 기준)
    routes: tuple  # 이 함수에 걸린 라우트들
    line: int  # id가 처음 쓰인 DB 호출 줄
    rule_id: str  # 본인만 봐야 한다면 걸리는 규칙


@dataclass(frozen=True)
class _Operation:
    site: ast.AST  # 라우트 함수 안에서의 위치: DB 호출, 또는 DB 호출을 하는 헬퍼를 부른 곳
    call: ast.Call  # DB 호출
    writes: bool  # 수정·삭제인지 (조회가 아니라)
    inlined: bool  # 헬퍼를 한 단계 따라 들어가 찾았는지


class _Analysis:
    def __init__(self, source):
        self._source = source
        self._names = source.names
        self._conditions = Conditions(source)
        self._schema = _Schema(source)
        self._owner_fields = OWNER_FIELDS | self._schema.owner_columns
        self._routes = {}  # 라우트 함수 → 그 함수에 걸린 라우트들
        for route in find_routes(source):
            if route.func is not None:
                self._routes.setdefault(route.func, []).append(route)

    def unverified_candidates(self):
        """id로 DB를 다루는데 소유자·관리자 검증이 없는 라우트들."""
        operations = self._operations()
        candidates = []
        for function, routes in self._routes.items():
            unverified = [op for op in operations.get(function, ()) if not self._is_verified(function, op)]
            if unverified:
                rule_id = self._rule(function, unverified)
                candidates.append(_Candidate(function.name, tuple(routes), unverified[0].site.lineno, rule_id))
        return candidates

    # ---- 후보: id가 쓰인 DB 호출 ----

    def _operations(self):
        """라우트 함수 → URL 변수·id류 요청값이 쓰인 DB 조회·수정·삭제들."""
        call_of = {}  # id(값을 본 식) → 그 식을 인자로 받는 DB 호출
        for node in iter_nodes(self._source.tree):
            if is_execute(node):
                query, parameters = query_and_parameters(node)
                arguments = (query, *binding_elements(parameters))
            elif _is_orm_lookup(node):
                arguments = (*node.args, *(keyword.value for keyword in node.keywords))
            else:
                continue
            for argument in arguments:
                if argument is not None:
                    call_of[id(argument)] = node

        hits = find_sink_hits(self._source, SPEC)
        queries = {(id(hit.node), hit.call_line): hit for hit in hits if hit.role == QUERY}
        operations, seen = {}, set()
        for hit in hits:
            if not any(part.kind is Kind.TAINTED for value in hit.values for part in value):
                continue
            call = call_of[id(hit.node)]
            site = hit.call_node or call
            function = self._conditions.function_of(site)
            kind = self._kind(call, hit.call_line, queries)
            if function not in self._routes or kind is None or (id(site), id(call)) in seen:
                continue
            seen.add((id(site), id(call)))
            operations.setdefault(function, []).append(
                _Operation(site, call, kind == "write", hit.call_node is not None)
            )
        return operations

    def _kind(self, call, call_line, queries):
        """조회("read"), 수정·삭제("write"), 대상이 아님(None: INSERT)."""
        if not is_execute(call):
            return "read"
        query, _ = query_and_parameters(call)
        query_hit = queries.get((id(query), call_line)) or queries.get((id(query), None))
        words = [
            value[0].text.split(None, 1)[0].lower()
            for value in (query_hit.values if query_hit else ())
            if value[0].kind is Kind.STATIC and value[0].text.strip()
        ]
        if any(word in ("update", "delete") for word in words):
            return "write"
        if words and all(word in ("insert", "replace") for word in words):
            return None
        return "read"

    # ---- 검증: 안전 1~3 ----

    def _is_verified(self, function, operation):
        if self._has_session_condition(operation):
            return True  # 안전 2: 조회 조건에 세션 사용자 값을 포함
        return any(check in (OWNER_CHECK, ADMIN_CHECK) for check in self._checks(function, operation))

    def _rule(self, function, operations):
        """본인만 봐야 하는 페이지라면 걸리는 규칙."""
        checks = {check for operation in operations for check in self._checks(function, operation)}
        if BAD_CHECK in checks:
            return "IDOR-3"
        if ROLE_CHECK in checks:
            return "IDOR-4"
        if LOGIN_CHECK in checks or self._has_login_required(function):
            return "IDOR-2"
        return "IDOR-1"

    def _has_login_required(self, function):
        for decorator in function.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if (self._names.resolve(target) or "").endswith("login_required"):
                return True
        return False

    def _has_session_condition(self, operation):
        """DB 호출의 조건 값에 세션 사용자 값이 들어 있는지."""
        call = operation.call
        if is_execute(call):
            _, parameters = query_and_parameters(call)
            expressions = list(binding_elements(parameters))
        else:
            expressions = [self._chain_top(call)]  # filter_by(...).filter_by(...) 전체
        if operation.inlined:
            # 헬퍼에 값을 넘겨 조회하는 경우: 넘기는 인자에 세션 사용자 값이 있는지도 본다.
            site = operation.site
            expressions += [*site.args, *(keyword.value for keyword in site.keywords)]
        return any(
            self._is_session_user(node, self._conditions.function_of(node))
            for expression in expressions
            for node in iter_nodes(expression)
            if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))
        )

    def _chain_top(self, call):
        """`a.b(...).c(...)`처럼 이어진 호출의 가장 바깥 식."""
        node = call
        while True:
            parent = self._conditions.parent_of(node)
            if isinstance(parent, ast.Attribute) or (isinstance(parent, ast.Call) and parent.func is node):
                node = parent
            else:
                return node

    def _checks(self, function, operation):
        """이 DB 호출을 지키는(또는 지키려던) 검사들의 종류."""
        facts = list(self._conditions.known_at(operation.site))
        if operation.inlined:
            facts += self._conditions.known_at(operation.call)  # 헬퍼 안에서 한 검사
        if not operation.writes:
            # 조회는 결과를 꺼낸 뒤에 소유자를 비교한다: 조회 뒤의 문장들에 걸린 검사를 본다.
            for node in iter_own_nodes(function):
                if isinstance(node, ast.stmt) and node.lineno > operation.site.lineno:
                    facts += self._conditions.known_at(node)
        checks = (self._classify(fact, operation) for fact in facts)
        return [check for check in checks if check is not None]

    def _classify(self, fact, operation):
        """확정된 조건 하나가 이 DB 호출에 대해 어떤 검증인지."""
        test, scope = fact.test, fact.scope
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            operator = test.ops[0]
            left, right = test.left, test.comparators[0]
            sides = [self._operand(left, scope), self._operand(right, scope)]
            if isinstance(operator, (ast.Eq, ast.NotEq)):
                if isinstance(operator, ast.Eq) != fact.holds:
                    return None  # 두 값이 다르다는 조건: 검사를 통과한 쪽이 아니다
                if set(sides) == {SESSION, REQUEST}:
                    # 조회에 쓰는 id 자체와 비교: 그 id가 사용자 조회나 소유자 조건에 쓰일 때만 인정한다.
                    compared = left if sides[0] == REQUEST else right
                    return OWNER_CHECK if self._is_user_condition(compared, operation) else BAD_CHECK
                if SESSION in sides and {ADMIN_VALUE, OTHER_VALUE} & set(sides):
                    session_side = left if sides[0] == SESSION else right
                    if not self._is_role_key(session_side, scope):
                        return None  # `session["lang"] == "ko"`는 역할 검사가 아니다
                return _EQUAL_MEANS.get(frozenset(sides), LOGIN_CHECK if SESSION in sides else None)
            if isinstance(operator, (ast.In, ast.NotIn)) and isinstance(operator, ast.In) == fact.holds:
                values = self._static_strings(right, scope)
                if values:
                    admin_only = all(value.lower() in ADMIN_VALUES for value in values)
                    if sides[0] == SESSION:
                        if not self._is_role_key(left, scope):
                            return None
                        return ADMIN_CHECK if admin_only else ROLE_CHECK
                    if sides[0] == REQUEST and admin_only:
                        return BAD_CHECK
            return LOGIN_CHECK if SESSION in sides else None  # `"user_id" in session` 등
        # 비교가 아닌 조건: current_user.is_admin, session.get("user_id") 등
        side = self._operand(test, scope)
        _, names = _chain(_unwrap(test))
        is_admin_flag = bool(names) and names[-1] == ADMIN_FLAG and fact.holds
        if side == SESSION:
            return ADMIN_CHECK if is_admin_flag else LOGIN_CHECK
        if side == REQUEST and is_admin_flag:
            return BAD_CHECK
        return None

    def _is_role_key(self, node, scope, hops=1):
        """세션 값의 키가 역할 검사로 보는 사전에 있는지 (변수에 담았으면 한 번 따라간다)."""
        root, names = _chain(_unwrap(node))
        if root is None:
            return False
        if names:
            return names[-1].lower() in ROLE_KEYS
        definition = self._source.static.sole_value(root.id, scope) if hops else None
        return definition is not None and self._is_role_key(definition, scope, hops - 1)

    def _is_user_condition(self, compared, operation):
        """비교한 id가 이 DB 호출에서 사용자 테이블 조회나 소유자 컬럼 조건에 쓰이는지."""
        forms = [compared]
        if operation.inlined:
            # 헬퍼 안에서는 넘겨받은 매개변수 이름으로 쓰인다.
            helper = self._conditions.function_of(operation.call)
            parameters = helper.args.posonlyargs + helper.args.args
            forms += [
                ast.Name(id=parameter.arg, ctx=ast.Load())
                for parameter, argument in zip(parameters, operation.site.args)
                if _same_value(argument, compared)
            ]
        if is_execute(operation.call):
            return self._sql_uses_user(operation.call, forms)
        return self._orm_uses_user(operation.call, forms)

    def _sql_uses_user(self, call, forms):
        query, parameters = query_and_parameters(call)
        scope = self._conditions.function_of(call)
        parts = self._source.static.literal_parts(query, scope) if query is not None else None
        if not parts or not all(isinstance(part, str) for part in parts):
            return False
        text = "".join(parts)
        table = _TABLE.search(text)
        in_user_table = table is not None and table.group(1).lower() in USER_TABLES
        if isinstance(parameters, ast.Dict):
            named = {match.group(2) or match.group(3): match.group(1) for match in _NAMED.finditer(text)}
            columns = [named.get(string_value(key)) for key in parameters.keys]
        else:
            columns = [match.group(1) for match in _POSITIONAL.finditer(text)]
        return any(
            any(_same_value(element, form) for form in forms)
            and (in_user_table or (column is not None and _bare_column(column) in self._owner_fields))
            for element, column in zip(binding_elements(parameters), columns)
        )

    def _orm_uses_user(self, call, forms):
        uses = lambda node: any(_same_value(node, form) for form in forms)
        root, _ = _chain(call.func.value)
        models = [root, *call.args]
        if any(isinstance(model, ast.Name) and model.id.lower() in USER_TABLES for model in models) and any(
            uses(argument) for argument in (*call.args, *(keyword.value for keyword in call.keywords))
        ):
            return True
        if any(
            keyword.arg and keyword.arg.lower() in self._owner_fields and uses(keyword.value)
            for keyword in call.keywords
        ):
            return True
        for argument in call.args:  # filter(Post.user_id == uid)
            if isinstance(argument, ast.Compare) and len(argument.ops) == 1:
                sides = (argument.left, argument.comparators[0])
                for this, that in (sides, sides[::-1]):
                    if uses(this) and isinstance(that, ast.Attribute) and that.attr.lower() in self._owner_fields:
                        return True
        return False

    # ---- 식의 종류 ----

    def _operand(self, node, scope):
        node = _unwrap(node)
        parts = self._source.static.literal_parts(node, scope)
        if parts and all(isinstance(part, str) for part in parts):
            return ADMIN_VALUE if "".join(parts).lower() in ADMIN_VALUES else OTHER_VALUE
        if self._is_session_user(node, scope):
            return SESSION
        if self._is_request_value(node, scope):
            return REQUEST
        if self._is_owner_field(node, scope):
            return OWNER_FIELD
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return OTHER_FIELD
        return OTHER

    def _is_session_user(self, node, scope, hops=1):
        """세션 사용자 값인지: session[...], current_user…, g.user… (변수에 담았으면 한 번 따라간다)."""
        root, names = _chain(_unwrap(node))
        if root is None:
            return False
        resolved = self._names.resolve(root)
        if resolved == "flask.session":
            return True
        if resolved == "flask_login.current_user" or root.id == "current_user":
            return True
        if resolved == "flask.g":
            return bool(names) and "user" in split_words(names[0])  # g.user, g.user_id (g.db는 아니다)
        definition = self._source.static.sole_value(root.id, scope) if hops else None
        return definition is not None and self._is_session_user(definition, scope, hops - 1)

    def _is_request_value(self, node, scope, hops=1):
        """요청에서 온 값인지: request.…, 라우트의 URL 변수 (변수에 담았으면 한 번 따라간다)."""
        root, _ = _chain(_unwrap(node))
        if root is None:
            return False
        if self._names.resolve(root) == "flask.request":
            return True
        if scope in self._routes and root.id in {argument.arg for argument in scope.args.args}:
            return True
        definition = self._source.static.sole_value(root.id, scope) if hops else None
        return definition is not None and self._is_request_value(definition, scope, hops - 1)

    def _is_owner_field(self, node, scope, hops=1):
        """조회한 객체의 소유자 필드인지: row["user_id"], post.author_id, row[2] (컬럼 순서로 이름을 찾는다)."""
        node = _unwrap(node)
        if isinstance(node, ast.Name):
            definition = self._source.static.sole_value(node.id, scope) if hops else None
            return definition is not None and self._is_owner_field(definition, scope, hops - 1)
        if isinstance(node, ast.Attribute):
            name, holder = node.attr, node.value
        elif isinstance(node, ast.Subscript):
            holder = node.value
            name = string_value(node.slice)
            if name is None:
                if _int_index(node.slice) is None:
                    return False
                name = self._column_name(node, scope)
                if name is None:
                    return True  # 번호로 꺼낸 값의 이름을 찾을 수 없으면 세션 비교만으로 인정한다 (완화)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            name, holder = (string_value(node.args[0]) if node.args else None), node.func.value
        else:
            return False
        if name is None:
            return False
        if name.lower() in self._owner_fields:
            return True
        # 사용자 테이블에서 꺼낸 객체라면 그 id가 곧 소유자다.
        return name.lower() == "id" and self._table_of(holder, scope) in USER_TABLES

    def _static_strings(self, node, scope):
        """문자열 상수만 든 목록(또는 그것에 붙인 이름)이면 그 값들, 아니면 None."""
        if isinstance(node, ast.Name):
            node = self._source.static.sole_value(node.id, scope)
        if not isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return None
        values = []
        for element in node.elts:
            parts = self._source.static.literal_parts(element, scope)
            if not parts or not all(isinstance(part, str) for part in parts):
                return None
            values.append("".join(parts))
        return values

    # ---- 조회한 객체가 어느 테이블의 어떤 컬럼인지 ----

    def _column_name(self, node, scope):
        """`row[2]`의 2번째가 어떤 컬럼인지 SELECT 문(또는 CREATE TABLE)에서 찾는다."""
        index = _int_index(node.slice)
        columns = self._selected(node.value, scope)[1]
        if index is None or columns is None or not -len(columns) <= index < len(columns):
            return None
        return columns[index]

    def _table_of(self, holder, scope):
        return self._selected(holder, scope)[0]

    def _selected(self, holder, scope):
        """holder(조회 결과를 담은 변수)가 나온 (테이블 이름, 컬럼 이름들). 알 수 없으면 None."""
        if not isinstance(holder, ast.Name):
            return None, None
        definition = self._source.static.sole_value(holder.id, scope)
        if definition is None:
            return None, None
        root, names = _chain(definition)
        if root is not None and "query" in names and root.id[:1].isupper():
            return root.id.lower(), None  # ORM: User.query.get(...) → 클래스 이름을 테이블 이름으로 본다
        execute = next((inner for inner in iter_nodes(definition) if is_execute(inner)), None)
        if execute is None and root is not None and scope is not None:
            # cur.execute(...) 뒤에 row = cur.fetchone(): 같은 커서로 그 앞에서 실행한 마지막 쿼리
            earlier = [
                inner
                for inner in iter_own_nodes(scope)
                if is_execute(inner)
                and isinstance(inner.func.value, ast.Name)
                and inner.func.value.id == root.id
                and inner.lineno <= definition.lineno
            ]
            execute = earlier[-1] if earlier else None
        if execute is None:
            return None, None
        query, _ = query_and_parameters(execute)
        parts = self._source.static.literal_parts(query, scope) if query is not None else None
        if parts is None or not all(isinstance(part, str) for part in parts):
            return None, None
        match = _SELECT.match("".join(parts))
        if match is None:
            return None, None
        table = match.group(2).lower()
        if match.group(1).strip() == "*":
            return table, self._schema.columns.get(table)
        return table, [_column_label(column) for column in _split_top_level(match.group(1))]


class _Schema:
    """파일 안의 CREATE TABLE 문에서 테이블별 컬럼 순서와 users를 참조하는 컬럼을 읽는다."""

    def __init__(self, source):
        self.columns = {}  # 테이블 이름 → 컬럼 이름들 (선언 순서)
        self.owner_columns = set()
        for node in iter_nodes(source.tree):
            text = string_value(node)
            if text:
                for match in _CREATE_TABLE.finditer(text):
                    self._read(match.group(1).lower(), _parenthesized(text, match.end()))

    def _read(self, table, body):
        columns = self.columns.setdefault(table, [])
        for definition in _split_top_level(body):
            words = definition.split()
            if not words:
                continue
            first = words[0].strip("`\"'").lower()
            references_users = _REFERENCES_USERS.search(definition) is not None
            if first in _CONSTRAINTS:
                foreign_key = _FOREIGN_KEY.search(definition)
                if foreign_key and references_users:
                    self.owner_columns.update(
                        name.strip(" `\"'").lower() for name in foreign_key.group(1).split(",")
                    )
                continue
            columns.append(first)
            if references_users:
                self.owner_columns.add(first)


def _chain(node):
    """식의 뿌리 이름과 거기서 이어지는 속성·키·메서드 이름들: `g.user["id"]` → (g, ["user", "id"]).

    `session.get("user_id")`는 `session["user_id"]`처럼 키 이름을 남긴다. 뿌리가 이름이 아니면 None.
    """
    names = []
    while True:
        if isinstance(node, ast.Attribute):
            names.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Subscript):
            names.append(string_value(node.slice) or "")
            node = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            key = string_value(node.args[0]) if node.func.attr == "get" and node.args else None
            names.append(key if key is not None else node.func.attr)
            node = node.func.value
        else:
            break
    names.reverse()
    return (node if isinstance(node, ast.Name) else None), names


def _unwrap(node):
    """`int(x)`, `str(x)`처럼 모양만 바꾸는 호출을 벗긴다."""
    while (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("int", "str")
        and node.args
    ):
        node = node.args[0]
    return node


def _same_value(first, second):
    """두 식이 모양을 바꾸는 호출(`int`, `str`)을 빼고 같은 식인지."""
    return ast.dump(_unwrap(first)) == ast.dump(_unwrap(second))


def _bare_column(column):
    """`p.user_id`, `` `user_id` `` → `user_id`."""
    return column.replace("`", "").replace('"', "").split(".")[-1].lower()


def _int_index(node):
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _int_index(node.operand)
        return -value if value is not None else None
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def _parenthesized(text, start):
    """text[start] 바로 앞의 여는 괄호에 짝이 맞는 닫는 괄호까지의 내용."""
    depth = 1
    for index in range(start, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[start:index]
    return text[start:]


def _split_top_level(text):
    """괄호 밖의 쉼표에서 나눈다."""
    pieces, depth, current = [], 0, []
    for character in text:
        if character == "," and depth == 0:
            pieces.append("".join(current))
            current = []
            continue
        depth += (character == "(") - (character == ")")
        current.append(character)
    pieces.append("".join(current))
    return [piece.strip() for piece in pieces if piece.strip()]


def _column_label(column):
    """SELECT 목록의 한 항목이 결과에서 갖는 이름: `p.user_id AS owner` → owner, `p.user_id` → user_id."""
    words = column.replace("`", "").replace('"', "").split()
    return words[-1].split(".")[-1].lower() if words else ""
