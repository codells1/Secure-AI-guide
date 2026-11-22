"""4.9 평문·약한 해시 비밀번호 저장 (password_storage): PW-1 ~ PW-5.

비밀번호 값이 승인된 해시를 거치지 않고 DB 저장 자리까지 가는지 오염 분석으로 추적한다.
"""
import ast
import re

from ..astutil import assignment_pairs, iter_nodes, string_value
from ..dbcalls import binding_elements, is_execute, query_and_parameters
from ..naming import has_word
from ..result import Finding
from ..taint import CLEAN, Kind, Marked, Same, TaintSpec, Update, find_sink_hits, register
from ..taint.values import concat, single, static_text

VULN_ID = "password_storage"

# 출발점: 이 이름 사전에 해당하는 폼 키·변수
PASSWORD_WORDS = ("password", "pw", "passwd", "pwd")
PASSWORD_WORD_KOREAN = "비밀번호"

# 저장 자리의 종류
QUERY = "query"  # INSERT/UPDATE 쿼리 문자열
BINDING = "binding"  # execute()의 2번째 인자(바인딩 값)
ORM = "orm"  # ORM 속성 대입, 모델 생성 인자

# 값에 붙이는 표시
SAFE_RANDOM = "safe_random"  # os.urandom(), secrets.token_*()로 만든 값
GENSALT = "gensalt"  # bcrypt.gensalt()로 만든 값
DB_VALUE = "db_value"  # DB에서 읽은 값 (그 사용자의 저장된 솔트로 인정한다)
HASH_OBJECT = "hash:"  # `hashlib.sha256()`로 만든 해시 객체. 뒤에 방식 이름이 붙는다

SAFE_RANDOM_FUNCTIONS = frozenset(
    {"os.urandom", "secrets.token_bytes", "secrets.token_hex", "secrets.token_urlsafe"}
)
WEAK_HASHES = frozenset({"md5", "sha1"})
APPROVED_HASHES = frozenset(
    {"sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "scrypt"}
)
KEY_DERIVATION_FUNCTIONS = frozenset({"hashlib.pbkdf2_hmac", "hashlib.scrypt"})
DIGEST_METHODS = frozenset({"hexdigest", "digest"})
# 내용을 바꾸지 않고 모양만 바꾸는 호출: 솔트와 비밀번호 조각, 해시 표시를 그대로 둔다.
TRANSPARENT_METHODS = frozenset({"encode", "decode", "hex"})
TRANSPARENT_FUNCTIONS = frozenset(
    {"str", "bytes", "base64.b64encode", "base64.urlsafe_b64encode", "binascii.hexlify"}
)
FETCH_METHODS = frozenset({"fetchone", "fetchall", "fetchmany"})
ORM_READ_METHODS = frozenset({"first", "one", "one_or_none", "all", "get", "first_or_404", "get_or_404"})
RULES_BY_TAG = ("PW-2", "PW-3", "PW-4", "PW-5")

_STORING_QUERY = re.compile(r"\s*(insert|update|replace)\b", re.IGNORECASE)


def is_password_name(name):
    return PASSWORD_WORD_KOREAN in name or has_word(name, PASSWORD_WORDS)


def _is_password_key(node, scope, source):
    """`request.form["password"]`, `data.get("pw")`처럼 비밀번호 이름의 키로 값을 꺼내는 식인지."""
    if isinstance(node, ast.Subscript):
        base, key = node.value, node.slice
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
    ):
        base, key = node.func.value, node.args[0]
    else:
        return False
    text = string_value(key)
    return bool(text) and is_password_name(text) and _is_request_data(base, source)


def _is_request_data(base, source):
    """요청에서 온 값일 수 있는지: `request.…`이거나 함수 안의 변수(`data = request.get_json()` 등).

    `os.environ`, `app.config`처럼 모듈 최상위 이름에서 꺼내는 것은 제외한다.
    """
    root = base
    while isinstance(root, (ast.Attribute, ast.Subscript, ast.Call)):
        root = root.func if isinstance(root, ast.Call) else root.value
    if not isinstance(root, ast.Name):
        return False
    if source.names.resolve(root) == "flask.request":
        return True
    return not source.static.is_module_name(root.id)


def _on_call(call):
    """해시·난수·변환 호출의 결과를 정한다: 정화(CLEAN), 표시(Marked), 그대로(Same), 객체 갱신(Update), 기본 처리(None)."""
    name = call.name
    if _reads_db(call):
        return Same(single(Kind.UNKNOWN, call.node.lineno, {DB_VALUE}))
    constructed = _hash_constructor(call)
    if constructed is not None:
        return Same(_hash_object(*constructed))
    if _is_hash_object(call.receiver):
        if call.method == "update" and call.arguments:
            return Update(concat(call.receiver, call.arguments[0]))
        if call.method in DIGEST_METHODS:
            return _digest(call.receiver)
    if call.method in TRANSPARENT_METHODS and not _has_password_arguments(call):
        return Same(call.receiver)
    if name in TRANSPARENT_FUNCTIONS and call.arguments:
        return Same(call.arguments[0])
    if name in SAFE_RANDOM_FUNCTIONS:
        return Marked(frozenset({SAFE_RANDOM}))
    if name == "bcrypt.gensalt":
        return Marked(frozenset({GENSALT}))
    if not _has_password(call):
        return None
    # 승인된 해시 (스펙 4.9)
    if name == "werkzeug.security.generate_password_hash":
        return CLEAN
    if name == "bcrypt.hashpw":
        salt = call.argument(1, "salt")
        fresh = salt is not None and all(GENSALT in part.tags for value in salt for part in value)
        return CLEAN if fresh else _rule("PW-4")  # 고정 솔트를 넣은 bcrypt.hashpw
    if call.method == "hash" and _is_argon2_hasher(call):
        return CLEAN
    if name == "hashlib.pbkdf2_hmac":
        return _hashlib_outcome(static_text_of(call.argument(0, "hash_name")), None, call.argument(2, "salt"))
    if name == "hashlib.scrypt":
        return _hashlib_outcome("scrypt", None, call.keywords.get("salt"))
    if _is_passlib(call):
        return _rule("PW-5")
    return None


def _reads_db(call):
    """DB에서 값을 꺼내는 호출인지: `fetchone()` 등, ORM 조회(`User.query….first()`, `db.session.get(...)`)."""
    if call.method in FETCH_METHODS:
        return True
    if call.method in ORM_READ_METHODS and "query" in _attribute_names(call.node.func.value):
        return True
    return bool(call.name) and call.name.endswith(".session.get") and not call.name.startswith("flask.")


def _attribute_names(node):
    """`User.query.filter_by(...)` → ["filter_by", "query"]처럼 이어진 속성 이름들."""
    names = []
    while isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        if isinstance(node, ast.Attribute):
            names.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            node = node.value
    return names


def _hash_constructor(call):
    """`hashlib.sha256(data)`, `hashlib.new("md5", data)`이면 (방식, 넣은 값), 아니면 None."""
    name = call.name
    if not name or not name.startswith("hashlib.") or name in KEY_DERIVATION_FUNCTIONS:
        return None
    if name == "hashlib.new":
        return static_text_of(call.argument(0, "name")), call.argument(1, "data")
    return name.removeprefix("hashlib."), call.argument(0, "data") or call.keywords.get("string")


def _hash_object(algorithm, data):
    """해시 객체의 값: 방식을 적은 표시 조각 + 지금까지 넣은 값들."""
    marker = single(Kind.UNKNOWN, tags={HASH_OBJECT + (algorithm or "")})
    return concat(marker, data) if data is not None else marker


def _hash_tags(part):
    return [tag for tag in part.tags if tag.startswith(HASH_OBJECT)]


def _is_hash_object(group):
    return group is not None and any(_hash_tags(part) for value in group for part in value)


def _digest(receiver):
    """`h.hexdigest()`: 해시 객체에 넣은 값들을 보고 결과를 정한다."""
    if not any(part.kind is Kind.TAINTED for value in receiver for part in value):
        return Same(receiver)  # 비밀번호가 아닌 값의 해시
    algorithms = sorted(
        {tag.removeprefix(HASH_OBJECT) for value in receiver for part in value for tag in _hash_tags(part)}
    )
    data = tuple(tuple(part for part in value if not _hash_tags(part)) for value in receiver)
    for algorithm in algorithms:
        outcome = _hashlib_outcome(algorithm, data, None)
        if outcome != CLEAN:
            return outcome
    return CLEAN


def _hashlib_outcome(algorithm, data, salt):
    """hashlib 해시의 결과. data는 해시에 넣은 값(솔트가 섞여 있을 수 있다), salt는 따로 준 솔트 인자."""
    if algorithm in WEAK_HASHES:
        return _rule("PW-2")  # 솔트가 있어도 위험
    if algorithm not in APPROVED_HASHES:
        return _rule("PW-5")
    if salt is not None:
        return CLEAN if _has_safe_salt(salt) else _rule("PW-4")
    if data is None:
        return _rule("PW-3")
    if _has_safe_salt(data):
        return CLEAN
    salted = any(part.kind is not Kind.TAINTED for value in data for part in value)
    return _rule("PW-4" if salted else "PW-3")


def _rule(rule_id):
    return Marked(frozenset({rule_id}))


def _has_safe_salt(group):
    """모든 갈래에 안전한 난수로 만든 조각이나 DB에서 읽은 그 사용자의 솔트가 섞여 있는지."""
    return all(any({SAFE_RANDOM, DB_VALUE} & part.tags for part in value) for value in group)


def _has_password(call):
    groups = [call.receiver or (), *call.arguments, *call.keywords.values()]
    return any(part.kind is Kind.TAINTED for group in groups for value in group for part in value)


def _has_password_arguments(call):
    groups = [*call.arguments, *call.keywords.values()]
    return any(part.kind is Kind.TAINTED for group in groups for value in group for part in value)


def static_text_of(group):
    return static_text(group) if group is not None else None


def _is_argon2_hasher(call):
    """`argon2.PasswordHasher().hash(pw)` 또는 `ph = PasswordHasher()` 뒤의 `ph.hash(pw)`인지."""
    receiver = call.node.func.value
    if isinstance(receiver, ast.Name):
        receiver = call.source.static.sole_value(receiver.id, call.scope)
    return isinstance(receiver, ast.Call) and call.source.names.resolve(receiver.func) == "argon2.PasswordHasher"


def _is_passlib(call):
    """`pbkdf2_sha256.hash(pw)` 또는 `ctx = CryptContext(...)` 뒤의 `ctx.hash(pw)`인지."""
    if (call.name or "").startswith("passlib."):
        return True
    if call.method not in ("hash", "encrypt"):
        return False
    receiver = call.node.func.value
    if isinstance(receiver, ast.Name):
        receiver = call.source.static.sole_value(receiver.id, call.scope)
    return isinstance(receiver, ast.Call) and (call.source.names.resolve(receiver.func) or "").startswith("passlib.")


def _store_sites(source):
    """DB에 저장되는 값이 적힌 식들을 고른다 (스펙 4.9 도착점): (값 식, 자리 종류, 저장하는 호출·문장)."""
    classes = {node.name for node in source.tree.body if isinstance(node, ast.ClassDef)}
    for node in iter_nodes(source.tree):
        if isinstance(node, ast.Call):
            if is_execute(node):
                query, parameters = query_and_parameters(node)
                if query is not None:
                    yield query, QUERY, node
                for element in binding_elements(parameters):
                    yield element, BINDING, node
            elif isinstance(node.func, ast.Name) and node.func.id in classes:
                # 모델 생성 인자: User(password=pw). 같은 파일에 정의된 클래스만 모델로 본다.
                for keyword in node.keywords:
                    if keyword.arg and is_password_name(keyword.arg):
                        yield keyword.value, ORM, node
        for target, value in assignment_pairs(node):
            if isinstance(target, ast.Attribute) and is_password_name(target.attr):
                yield value, ORM, node  # ORM 속성 대입: user.password = pw


def _stored_values(source):
    for value, role, _ in _store_sites(source):
        yield value, role


SPEC = register(
    TaintSpec(
        vuln_id=VULN_ID,
        sinks=(),
        source_attributes=frozenset(),
        source_calls=frozenset(),
        url_variables=False,
        probes=_stored_values,
        extra_source=_is_password_key,
        source_names=is_password_name,
        on_call=_on_call,
        sticky_tags=frozenset({DB_VALUE}),
    )
)


def check(source):
    hits = find_sink_hits(source, SPEC)
    queries = {(id(hit.node), hit.call_line): hit for hit in hits if hit.role == QUERY}
    sites = {id(value): site for value, _, site in _store_sites(source)}
    query_of = {}  # id(쿼리·바인딩 식) → 그 execute 호출의 쿼리 식
    for node in iter_nodes(source.tree):
        if is_execute(node):
            query, parameters = query_and_parameters(node)
            for expression in (query, *binding_elements(parameters)):
                if expression is not None:
                    query_of[id(expression)] = query

    findings = []
    for hit in hits:
        if hit.role != ORM and not _stores(hit, query_of, queries):
            continue  # INSERT/UPDATE가 아닌 쿼리 (SELECT 등)
        store_line = sites[id(hit.node)].lineno  # 보고하는 줄은 DB에 저장하는 줄이다
        for value in hit.values:
            for part in value:
                if part.kind is Kind.TAINTED:
                    # 같은 파일의 헬퍼가 넘겨받은 값을 저장하면 호출한 줄에서 라우트마다 보고한다 (스펙 4.9, 3.5).
                    line = hit.call_line if hit.call_line in part.trail else store_line
                    findings.append(Finding(line, _rule_of(part), hit.path_to(part, line)))
    return findings


def _stores(hit, query_of, queries):
    """이 값이 쓰인 execute()가 INSERT/UPDATE 쿼리를 실행하는지."""
    query = query_of.get(id(hit.node))
    query_hit = queries.get((id(query), hit.call_line)) or queries.get((id(query), None))
    if query_hit is None:
        return False
    return any(
        value[0].kind is Kind.STATIC and _STORING_QUERY.match(value[0].text) for value in query_hit.values
    )


def _rule_of(part):
    """해시를 거치며 붙은 표시가 있으면 그 규칙, 없으면 해시 없이 저장한 것이다."""
    return next((rule_id for rule_id in RULES_BY_TAG if rule_id in part.tags), "PW-1")
