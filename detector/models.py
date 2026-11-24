"""흐름 분석이 쓰는 뜻풀이: 이름·속성·호출·비교가 값과 사실을 어떻게 바꾸는지 (스펙 3.1, 3.2, 4장)."""
import ast
import re
import string
from dataclasses import dataclass, replace

from .values import (
    EXTERNAL,
    NOCONST,
    PASSWORD,
    UPLOAD,
    S,
    T,
    U,
    Value,
    boolean,
    collection_of,
    const,
    join,
    merge,
    merge_all,
    of_taints,
    static,
    tainted,
    unknown,
)
from .words import (
    ADMIN_VALUES,
    is_admin_key,
    is_counter_name,
    is_time_name,
    is_owner_field,
    is_password_name,
    is_role_key,
)

REQUEST_MAPS = frozenset({"args", "form", "values", "json", "files", "cookies", "headers", "view_args"})
REQUEST_VALUES = frozenset({"data", "url", "full_path", "query_string"})
SPECIAL_NAMES = {
    "flask.request": ("request",),
    "flask.session": ("session",),
    "flask.g": ("g",),
    "flask_login.current_user": ("current_user",),
}
LOGIN_DECORATORS = frozenset({"flask_login.login_required", "flask_login.utils.login_required"})
SAFE_ERROR_ATTRIBUTES = frozenset({"code", "name", "description"})  # HTTP 오류에 미리 정해진 값 (스펙 4.7)

SAME_TEXT_METHODS = frozenset(
    {"strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize", "casefold", "swapcase", "encode",
     "decode", "zfill", "center", "ljust", "rjust", "expandtabs", "removeprefix", "removesuffix", "hex", "copy"}
)
FORMAT_CHECK_METHODS = frozenset({"isdigit", "isdecimal", "isnumeric", "isalnum", "isalpha"})
# 첫 인자의 내용이 그대로 결과가 되는 함수 (둘째 인자부터는 인코딩 이름 같은 설정이다)
TRANSPARENT_FUNCTIONS = frozenset(
    {"str", "bytes", "bytearray", "repr", "format", "list", "tuple", "set", "frozenset", "sorted", "reversed",
     "iter", "next", "enumerate", "dict",
     "base64.b64encode", "base64.urlsafe_b64encode", "base64.b64decode", "binascii.hexlify", "binascii.unhexlify",
     "html.escape", "markupsafe.escape", "markupsafe.Markup", "flask.escape", "flask.Markup", "re.escape",
     "urllib.parse.quote", "urllib.parse.quote_plus", "urllib.parse.unquote",
     "os.path.basename", "os.path.dirname", "os.path.abspath", "os.path.normpath", "os.path.realpath",
     "os.path.expanduser", "os.fspath", "copy.copy", "copy.deepcopy", "json.loads", "json.dumps", "shlex.split"}
)
# 모든 인자의 내용이 결과에 섞이는 함수
MIXING_FUNCTIONS = frozenset({"zip", "map", "filter", "urllib.parse.urljoin", "itertools.chain"})
CLEAN_FUNCTIONS = frozenset(
    {"len", "bool", "type", "id", "hash", "isinstance", "issubclass", "abs", "round", "ord", "range", "print",
     "any", "all", "sum", "min", "max", "callable", "hasattr", "flask.flash", "flask.url_for", "flask.redirect",
     "time.time", "time.sleep", "datetime.datetime.now", "datetime.datetime.utcnow"}
)
DB_READ_METHODS = frozenset(
    {"fetchone", "fetchall", "fetchmany", "first", "one", "one_or_none", "all", "scalar", "scalars",
     "first_or_404", "get_or_404", "scalar_one", "scalar_one_or_none"}
)
SAFE_RANDOM = frozenset({"os.urandom", "secrets.token_bytes", "secrets.token_hex", "secrets.token_urlsafe",
                         "secrets.randbits", "secrets.choice"})
WEAK_HASHES = frozenset({"md5", "sha1", "md4"})
APPROVED_HASHES = frozenset({"sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512"})
SAFE_SALT_MARKS = frozenset({"saferandom", "db", "gensalt"})
KEPT_MARKS = frozenset({"exception", "session", "db", "global"})

_PERCENT = re.compile(r"%(?:\((\w+)\))?[#0\- +]*\d*(?:\.\d+)?[sdrfiuxXeEgGc]")
_SAFE_PATTERN = re.compile(r"\^?(?:\[[A-Za-z0-9_\-\\wd]+\]|\\w|\\d)(?:[+*]|\{\d+(?:,\d*)?\})?\$?")


@dataclass
class Call:
    node: ast.Call
    name: str | None
    method: str | None
    receiver: Value | None
    args: list
    kwargs: dict
    env: object
    line: int
    class_name: str | None = None

    def arg(self, position, keyword=None):
        if keyword and keyword in self.kwargs:
            return self.kwargs[keyword]
        return self.args[position] if position is not None and position < len(self.args) else None


# ---------------------------------------------------------------------- 값 만들기
def reference(dotted):
    if dotted in SPECIAL_NAMES:
        return Value(obj=SPECIAL_NAMES[dotted])
    return Value(obj=("ref", dotted))


def _nonstatic(values):
    """값들에 든 고정이 아닌 조각을 한 갈래로 모은다."""
    atoms = []
    for value in values:
        for taint in sorted(value.taints(), key=lambda t: (t.origin, t.part, t.state)):
            if T(taint) not in atoms:
                atoms.append(T(taint))
        marks = value.marks(deep=True)
        if marks and U(frozenset(marks)) not in atoms:
            atoms.append(U(frozenset(marks)))
        elif not value.is_static and not value.taints() and U() not in atoms and not marks:
            atoms.append(U())
    return (tuple(atoms) or (S(""),),)


def sequence(items):
    consts = [item.const for item in items]
    constant = tuple(consts) if all(item is not NOCONST for item in consts) else NOCONST
    return Value(alts=_nonstatic(items), const=constant, items=tuple(items))


def mapping(pairs):
    keys = [key for key, _ in pairs]
    known = all(key is not NOCONST and _hashable(key) for key in keys)
    values = [value for _, value in pairs]
    constant = NOCONST
    if known and all(value.const is not NOCONST for value in values):
        constant = {key: value.const for key, value in pairs}
    return Value(alts=_nonstatic(values), const=constant, fields=tuple(pairs) if known else None)


def _hashable(item):
    try:
        hash(item)
    except TypeError:
        return False
    return True


def unpack(value, count):
    if value.items is not None and len(value.items) == count:
        return list(value.items)
    return [Value(alts=value.alts)] * count


def element_of(fx, value):
    """반복문이 꺼내는 원소 하나의 값."""
    kind = value.obj[0] if value.obj else None
    if kind == "uploads":
        return value.obj[1]
    if kind == "reqmap":
        return _request_value(fx, value.obj[1], "", 0)
    if value.items is not None:
        return merge_all(value.items) if value.items else unknown()
    if isinstance(value.const, (tuple, list, set, frozenset, dict)):
        return merge_all(const(item) for item in value.const) if value.const else unknown()
    if value.fields is not None:
        return merge_all(const(key) for key, _ in value.fields) if value.fields else unknown()
    if "cursor" in value.marks():
        return unknown("db")
    return Value(alts=value.alts)


def never_empty(value):
    """비어 있지 않은 것이 확실한 상수 모음인지 (`for word in ["|", ";"]:`)."""
    if value.items is not None:
        return len(value.items) > 0
    return isinstance(value.const, (tuple, list, set, frozenset, dict)) and len(value.const) > 0


def percent_format(fx, template, right, line):
    """`"… %s …" % 값`: 틀의 고정 글자 사이에 값을 끼운다."""
    arguments = list(right.items) if right.items is not None else [right]
    pieces, position, used = [], 0, 0
    for match in _PERCENT.finditer(template):
        pieces.append(static(template[position:match.start()].replace("%%", "%")))
        if match.group(1) and right.fields is not None:
            pieces.append((right.field(match.group(1)) or unknown()).plain())
        else:
            pieces.append(arguments[used].plain() if used < len(arguments) else unknown())
            used += 1
        position = match.end()
    pieces.append(static(template[position:].replace("%%", "%")))
    return join(pieces, fx.here, line)


def _format_method(fx, template, call):
    pieces, auto = [], 0
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError:
        return None
    for literal, field, _spec, _conversion in parsed:
        pieces.append(static(literal))
        if field is None:
            continue
        head = re.split(r"[.\[]", field, maxsplit=1)[0]
        if head == "":
            value, auto = call.arg(auto), auto + 1
        elif head.isdigit():
            value = call.arg(int(head))
        else:
            value = call.kwargs.get(head)
        pieces.append((value or unknown()).plain())
    return join(pieces, fx.here, call.line)


def _request_value(fx, which, key, line):
    if which == "files":
        return tainted(fx.new_taint({UPLOAD}, line, key=key, via=which))
    labels = {EXTERNAL} | ({PASSWORD} if key and is_password_name(key) else set())
    return tainted(fx.new_taint(labels, line, key=key, via=which))


def _retag(taints, **changes):
    return of_taints({replace(taint, **changes) for taint in taints})


# ---------------------------------------------------------------------- 속성과 첨자
def attribute(fx, node, base, env):
    name = node.attr
    kind = base.obj[0] if base.obj else None
    if kind == "request":
        if name in REQUEST_MAPS:
            return Value(obj=("reqmap", name))
        if name in REQUEST_VALUES:
            return tainted(fx.new_taint({EXTERNAL}, node.lineno, key=name, via=name))
        return unknown("request_meta")
    if kind == "reqmap":
        return base
    if kind in ("session", "current_user"):
        return unknown("session", f"key:{name}")
    if kind == "g":
        return unknown("session", f"key:{name}") if "user" in name.lower() else unknown("g")
    if kind == "ref":
        return Value(obj=("ref", f"{base.obj[1]}.{name}"))
    uploads = [taint for taint in base.taints(deep=False) if taint.has(UPLOAD)]
    if uploads:
        part = {"filename": "filename", "name": "filename", "content_type": "ctype", "mimetype": "ctype",
                "content_length": "size"}.get(name)
        if part:
            return _retag(uploads, labels=frozenset({EXTERNAL}), part=part, key=name)
        return base.plain()
    marks = base.marks()
    if "exception" in marks:
        return unknown("http_error") if name in SAFE_ERROR_ATTRIBUTES else unknown("exception")
    if "db" in marks:
        return unknown("db", f"field:{name}")
    if "session" in marks:
        return unknown("session", f"key:{name}")
    taints = base.taints(deep=False)
    if taints:
        return of_taints(taints)
    return unknown(*(marks & KEPT_MARKS))


def subscript(fx, node, base, key, env):  # noqa: C901 - 값 종류별 분기
    kind = base.obj[0] if base.obj else None
    key_const = key.const if key is not None else NOCONST
    key_text = key_const if isinstance(key_const, str) else ""
    if kind == "reqmap":
        return _request_value(fx, base.obj[1], key_text, node.lineno)
    if kind in ("session", "current_user", "g"):
        return unknown("session", f"key:{key_text}")
    if kind == "ref":
        return unknown("env") if base.obj[1] == "os.environ" else unknown()
    if kind == "split" and isinstance(key_const, int):
        return _split_piece(base, key_const)
    if key is None:
        return base.plain()
    if fx.is_global_store(node.value, env):
        return unknown("global")
    if base.items is not None and isinstance(key_const, int) and -len(base.items) <= key_const < len(base.items):
        return base.items[key_const]
    if base.fields is not None or isinstance(base.const, dict):
        return _lookup(base, key, None)
    marks = base.marks()
    if "db" in marks:
        return unknown("db", *([f"field:{key_text}"] if key_text else []))
    if "exception" in marks:
        return unknown("exception")
    if "session" in marks:
        return unknown("session", f"key:{key_text}")
    taints = base.taints(deep=False)
    if taints:
        if key_text and is_password_name(key_text):
            return _retag(taints, labels=frozenset({EXTERNAL, PASSWORD}), key=key_text)
        return of_taints(taints)
    return unknown(*(marks & KEPT_MARKS))


def _split_piece(base, index):
    """`name.rsplit(".", 1)[-1]`은 확장자, `[0]`은 확장자를 뗀 이름이다."""
    separator, pieces = base.obj[1], base.obj[2]
    taints = base.taints(deep=False)
    if separator != ".":
        return of_taints(taints) if taints else unknown()
    last = index in (-1, pieces - 1) if pieces else index == -1
    part = "ext" if last or (not pieces and index == 1) else "stem" if index == 0 else ""
    return _retag(taints, part=part) if part else of_taints(taints)


def _lookup(base, key, default):
    """상수 dict에서 꺼낸 값. 키를 모르면 들어 있는 값들 가운데 하나다 (허용 목록에서 고르기)."""
    if base.fields is not None:
        entries = [(name, value) for name, value in base.fields]
    else:
        entries = [(name, const(value)) for name, value in base.const.items()]
    if key.const is not NOCONST:
        for name, value in entries:
            if name == key.const:
                return value
        return default if default is not None else unknown()
    choices = [value for _, value in entries] + ([default] if default is not None else [])
    return merge_all(choices) if choices else unknown()


# ---------------------------------------------------------------------- 호출
def default_result(call, opaque=True):
    """뜻을 모르는 호출: 인자에 든 추적 값은 결과에도 남는다. 비밀번호는 '확인할 수 없는 처리'를 거친 것이 된다."""
    sources = ([call.receiver] if call.receiver is not None else []) + call.args + list(call.kwargs.values())
    taints, marks = set(), set()
    for value in sources:
        taints |= {taint for taint in value.taints() if not taint.has(UPLOAD)}
        if value.has_mark("exception", deep=True):
            marks.add("exception")
    if opaque:
        taints = {
            replace(taint, state="PW-5") if taint.has(PASSWORD) and not taint.state else taint for taint in taints
        }
    result = of_taints(taints, *marks) if taints or marks else unknown()
    return replace(result, obj=("instance", call.name)) if call.name else result


def call(fx, c):  # noqa: C901 - 호출 종류별 분기
    receiver, method, name = c.receiver, c.method, c.name
    kind = receiver.obj[0] if receiver is not None and receiver.obj else None

    # ---- 요청, 세션 ----
    if kind == "request":
        if method == "get_json":
            return Value(obj=("reqmap", "json"))
        if method == "get_data":
            return tainted(fx.new_taint({EXTERNAL}, c.line, key="data", via="data"))
        return unknown()
    if kind == "reqmap":
        return _reqmap_call(fx, c, receiver.obj[1])
    if kind in ("session", "current_user", "g"):
        key = c.args[0].const if c.args and isinstance(c.args[0].const, str) else ""
        return unknown("session", f"key:{key}") if method in ("get", "pop", "setdefault") else unknown()

    # ---- 올린 파일, 해시 객체 ----
    if receiver is not None:
        uploads = [taint for taint in receiver.taints(deep=False) if taint.has(UPLOAD)]
        if uploads:
            if method == "read":
                return _retag(uploads, labels=frozenset({EXTERNAL}), part="data")
            return unknown()
    if kind == "hash":
        return _hash_method(fx, c)
    if kind == "instance":
        made = _instance_call(fx, c, receiver.obj[1])
        if made is not None:
            return made
    if kind == "ref" and receiver.obj[1].startswith("passlib.") and method in ("hash", "encrypt", "using"):
        return _password_state(c.args, "PW-5")

    # ---- 이름으로 아는 함수 ----
    if name:
        known = _named_call(fx, c, name)
        if known is not None:
            return known

    # ---- 메서드 ----
    if receiver is not None and method:
        known = _method_call(fx, c)
        if known is not None:
            return known
    if isinstance(c.node.func, ast.Name) and name is None:
        known = _builtin_call(fx, c, c.node.func.id)
        if known is not None:
            return known
    return default_result(c)


def _reqmap_call(fx, c, which):
    method = c.method
    key = c.args[0].const if c.args and isinstance(c.args[0].const, str) else ""
    if method in ("get", "pop", "__getitem__"):
        value = _request_value(fx, which, key, c.line)
        kind = next((kw.value for kw in c.node.keywords if kw.arg == "type"), None)
        if kind is None and len(c.node.args) > 2:
            kind = c.node.args[2]
        if isinstance(kind, ast.Name) and kind.id in ("int", "float"):
            value = value.map_taints(lambda taint: replace(taint, checks=taint.checks | {"num"}))
        return value
    if method == "getlist":
        value = _request_value(fx, which, key, c.line)
        return Value(obj=("uploads", value)) if which == "files" else Value(alts=value.alts)
    if method in ("values", "items", "keys", "lists", "listvalues"):
        value = _request_value(fx, which, "", c.line)
        return Value(obj=("uploads", value)) if which == "files" else Value(alts=value.alts)
    return Value(obj=("reqmap", which))  # to_dict(), copy() 등


def _hash_method(fx, c):
    _, algorithm, data = c.receiver.obj
    if c.method == "update" and c.args:
        updated = Value(obj=("hash", algorithm, join([data, c.args[0].plain()], fx.here, c.line)))
        target = c.node.func.value
        if isinstance(target, ast.Name):
            (c.env.owner_of(target.id) or c.env).set(target.id, updated)
        return const(None)
    if c.method in ("hexdigest", "digest"):
        return _hash_outcome(algorithm, data, None)
    if c.method == "copy":
        return c.receiver
    return unknown()


def _hash_outcome(algorithm, data, salt):
    passwords = [taint for taint in data.taints() if taint.has(PASSWORD)]
    if not passwords:
        return unknown("hash")
    state = _hash_state(algorithm, data, salt)
    if state is None:
        return unknown("hash")
    return _retag(passwords, labels=frozenset({PASSWORD}), state=state)


def _hash_state(algorithm, data, salt):
    """해시 방식과 솔트를 보고 규칙을 정한다 (스펙 4.9). 문제없으면 None."""
    if algorithm in WEAK_HASHES:
        return "PW-2"
    if algorithm not in APPROVED_HASHES and algorithm != "scrypt":
        return "PW-5"
    if salt is not None:
        atoms = [T(taint) for taint in salt.taints()] + list(salt.atoms())
    else:
        atoms = [atom for atom in data.atoms() if not (isinstance(atom, T) and atom.taint.has(PASSWORD))]
    if any(isinstance(atom, U) and atom.marks & SAFE_SALT_MARKS for atom in atoms):
        return None
    if any((isinstance(atom, S) and atom.text) or (isinstance(atom, U) and "weakrandom" in atom.marks)
           for atom in atoms):
        return "PW-4"
    if any(not isinstance(atom, S) for atom in atoms):
        return None  # 어디서 온 솔트인지 코드로 알 수 없다
    return "PW-3"


def _password_state(values, state):
    taints = set()
    for value in values:
        taints |= {taint for taint in value.taints() if taint.has(PASSWORD)}
    if not taints:
        return unknown("hash")
    return _retag(taints, labels=frozenset({PASSWORD}), state=state)


def _instance_call(fx, c, made_by):
    if made_by == "argon2.PasswordHasher":
        if c.method == "hash":
            return unknown("hash")
        if c.method == "verify":
            c.env.facts |= _verified(c.arg(0), c.arg(1))
            return boolean(_verified(c.arg(0), c.arg(1)))
    if made_by.startswith("flask_bcrypt.") and c.method == "generate_password_hash":
        return unknown("hash")
    if made_by.startswith("flask_bcrypt.") and c.method == "check_password_hash":
        return boolean(_verified(c.arg(0), c.arg(1)))
    if made_by.startswith("passlib.") and c.method in ("hash", "encrypt"):
        return _password_state(c.args, "PW-5")
    if made_by.startswith("passlib.") and c.method == "verify":
        return boolean(_verified(c.arg(1), c.arg(0)))
    if made_by == "pathlib.Path":
        return replace(default_result(c, opaque=False), obj=("instance", "pathlib.Path"))
    return None


def _verified(stored, given):
    """저장된 값과 입력한 비밀번호를 대조했다는 사실."""
    facts = {("auth", "verified")}
    if stored is not None and stored.has_mark("db", deep=True):
        facts.add(("authz", "credential"))
    return frozenset(facts)


def _named_call(fx, c, name):  # noqa: C901 - 함수별 분기
    args = c.args
    first = args[0] if args else None
    if name in ("os.getenv", "os.environ.get"):
        return unknown("env")
    if name in SAFE_RANDOM:
        return unknown("saferandom")
    if name.startswith("random.") or name in ("uuid.uuid1",):
        return unknown("weakrandom")
    if name == "bcrypt.gensalt":
        return unknown("gensalt")
    if name in ("traceback.format_exc", "traceback.format_exception"):
        return unknown("exception", "traceback")
    if name in ("werkzeug.security.generate_password_hash",):
        method = c.arg(1, "method")
        text = (method.text or "").lower() if method is not None else ""
        if "plain" in text:
            return first.plain() if first is not None else unknown()
        if "md5" in text or "sha1" in text:
            return _password_state(args[:1], "PW-2")
        return unknown("hash")
    if name == "werkzeug.security.check_password_hash":
        return boolean(_verified(c.arg(0, "pwhash"), c.arg(1, "password")))
    if name == "bcrypt.checkpw":
        return boolean(_verified(c.arg(1), c.arg(0)))
    if name == "bcrypt.hashpw":
        salt = c.arg(1, "salt")
        if salt is not None and salt.is_static and salt.text:
            return _password_state(args[:1], "PW-4")
        return unknown("hash")
    if name == "hmac.compare_digest" or name == "secrets.compare_digest":
        return boolean(_password_compare(fx, c.node, c.arg(0), c.arg(1), c.env, record=True))
    if name.startswith("passlib."):
        return _password_state(args, "PW-5")
    if name == "hashlib.pbkdf2_hmac":
        algorithm = (first.text or "").lower().replace("-", "") if first is not None else ""
        state_algorithm = algorithm if algorithm in WEAK_HASHES | APPROVED_HASHES else "?"
        data = c.arg(1, "password") or unknown()
        salt = c.arg(2, "salt") or static("")
        return _hash_outcome(state_algorithm, data, salt)
    if name == "hashlib.scrypt":
        return _hash_outcome("scrypt", c.arg(0, "password") or unknown(), c.arg(None, "salt") or static(""))
    if name.startswith("hashlib."):
        algorithm = name.split(".", 1)[1]
        if algorithm == "new":
            algorithm = (first.text or "?").lower().replace("-", "") if first is not None else "?"
            data = c.arg(1, "data")
        else:
            data = c.arg(0, "data") or c.kwargs.get("string")
        return Value(obj=("hash", algorithm, (data or static("")).plain()))
    crypto = re.fullmatch(r"(?:Crypto|Cryptodome)\.Hash\.(\w+)\.new", name)
    if crypto:
        algorithm = crypto.group(1).lower().replace("sha3_", "sha3_").replace("sha3-", "sha3_")
        return Value(obj=("hash", algorithm, (c.arg(0, "data") or static("")).plain()))
    if name == "os.path.join" or name == "posixpath.join" or name == "ntpath.join":
        pieces = []
        for index, part in enumerate(args):
            if index:
                pieces.append(static("/"))
            pieces.append(part.plain())
        return join(pieces, fx.here, c.line)
    if name == "os.path.splitext" and first is not None:
        taints = first.taints(deep=False)
        if not taints:
            return sequence((unknown(), unknown()))
        return Value(alts=first.alts, items=(_retag(taints, part="stem"), _retag(taints, part="ext")))
    if name in ("werkzeug.utils.secure_filename", "werkzeug.secure_filename") and first is not None:
        return first.map_taints(lambda taint: replace(taint, checks=taint.checks | {"secure_name"}))
    if name in ("werkzeug.security.safe_join", "werkzeug.utils.safe_join", "flask.safe_join"):
        merged = merge_all(arg.plain() for arg in args) if args else unknown()
        return merged.map_taints(lambda taint: replace(taint, checks=taint.checks | {"safe_join"}))
    if name == "shlex.quote" and first is not None:
        return first.map_taints(lambda taint: replace(taint, checks=taint.checks | {"quote"}))
    if name == "re.sub" and len(args) >= 3:
        return _removed(args[2], _pattern_characters(args[0]) if args[1].text == "" else None)
    if name in ("re.fullmatch", "re.match") and len(args) >= 2:
        pattern = args[0].text
        anchored = name == "re.fullmatch" or (pattern or "").endswith("$")
        if pattern and anchored and _SAFE_PATTERN.fullmatch(pattern):
            return boolean({("v", "format", taint.origin, taint.part) for taint in args[1].taints(deep=False)})
        return boolean()
    if name == "pathlib.Path":
        return replace(default_result(c, opaque=False), obj=("instance", "pathlib.Path"))
    if name in TRANSPARENT_FUNCTIONS:
        return first.plain() if first is not None else unknown()
    if name in MIXING_FUNCTIONS:
        return merge_all(arg.plain() for arg in args) if args else unknown()
    if name in CLEAN_FUNCTIONS:
        return unknown()
    return None


def _builtin_call(fx, c, name):
    args = c.args
    if name in ("int", "float") and args:
        if isinstance(args[0].const, (int, float, str)) and not args[0].taints():
            try:
                return const(int(args[0].const) if name == "int" else float(args[0].const))
            except (TypeError, ValueError):
                return unknown()
        return args[0].map_taints(lambda taint: replace(taint, checks=taint.checks | {"num"}))
    if name == "dict":
        if not args:
            return mapping([(key, value.plain()) for key, value in c.kwargs.items()])
        return args[0].plain()
    if name == "open":
        return unknown("file")
    if name in TRANSPARENT_FUNCTIONS:
        return args[0].plain() if args else unknown()
    if name in MIXING_FUNCTIONS:
        return merge_all(arg.plain() for arg in args) if args else unknown()
    if name in CLEAN_FUNCTIONS or name in ("abort", "exit", "quit", "input"):
        return unknown()
    if name in ("getattr",) and args:
        return args[0].plain()
    return None


def _method_call(fx, c):  # noqa: C901 - 메서드별 분기
    receiver, method, args = c.receiver, c.method, c.args
    target = c.node.func.value
    first = args[0] if args else None
    marks = receiver.marks()

    # 서버의 변수에 두는 저장소 (모듈 최상위 dict·list)
    if fx.is_global_store(target, c.env):
        if method in ("append", "add", "update", "extend", "insert", "setdefault"):
            from .flow import AssignEvent

            stored = merge_all(arg.plain() for arg in args) if args else unknown()
            fx.record(AssignEvent, c.node, c.env, target=target, value=stored, kind="mutate")
            return unknown("global")
        return unknown("global")

    if method in DB_READ_METHODS:
        return unknown("db")
    if method == "get" and _is_orm_get(c.node.func):
        return unknown("db")
    if method in ("execute", "executemany", "executescript", "cursor"):
        return unknown("cursor")
    if "exception" in marks:
        return unknown("exception")
    if "db" in marks:
        key = first.const if first is not None and isinstance(first.const, str) else ""
        return unknown("db", *([f"field:{key}"] if key and method == "get" else []))
    if "file" in marks:
        return unknown("filedata") if method in ("read", "readline", "readlines") else unknown("file")

    # dict에서 꺼내기
    if method == "get" and first is not None and (receiver.fields is not None or isinstance(receiver.const, dict)):
        return _lookup(receiver, first, args[1].plain() if len(args) > 1 else const(None))
    if method in ("values", "items", "keys") and receiver.fields is not None:
        return merge_all(value for _, value in receiver.fields) if receiver.fields else unknown()

    # 리스트·dict에 넣기: 그 변수에 값이 섞인다
    if method in ("append", "add", "extend", "insert", "update", "setdefault") and isinstance(target, ast.Name):
        current = c.env.get(target.id)
        if current is not None and args:
            added = merge_all(arg.plain() for arg in args)
            combined = Value(alts=merge(Value(alts=current.alts), Value(alts=_nonstatic([added]))).alts)
            (c.env.owner_of(target.id) or c.env).set(target.id, combined)
        return const(None)

    # 문자열
    taints = receiver.taints(deep=False)
    text = receiver.text
    if method in SAME_TEXT_METHODS:
        if text is not None and not args and method not in ("encode", "decode", "hex", "copy"):
            try:
                return static(getattr(text, method)())
            except (AttributeError, TypeError, ValueError):
                return receiver.plain()
        return receiver.plain()
    if method == "replace" and len(args) >= 2:
        if text is not None and args[0].text is not None and args[1].text is not None:
            return static(text.replace(args[0].text, args[1].text))
        removed = set(args[0].texts() or ()) if args[1].text == "" else None
        return _removed(receiver, removed)
    if method in ("split", "rsplit", "partition", "rpartition"):
        separator = first.text if first is not None else None
        limit = args[1].const if len(args) > 1 and isinstance(args[1].const, int) else None
        pieces = 3 if "partition" in method else (limit + 1 if limit is not None else 0)
        return Value(alts=receiver.alts, obj=("split", separator, pieces))
    if method == "join" and first is not None:
        return Value(alts=_nonstatic([first]))
    if method == "format":
        if text is not None:
            formatted = _format_method(fx, text, c)
            if formatted is not None:
                return formatted
        return default_result(c, opaque=False)
    if method == "endswith" and first is not None and taints:
        if collection_of(first) is not None or first.text is not None:
            return boolean({("v", "allow", taint.origin, "ext") for taint in taints})
        return boolean()
    if method in FORMAT_CHECK_METHODS and taints:
        return boolean({("v", "format", taint.origin, taint.part) for taint in taints})
    if method in ("startswith", "isspace", "islower", "isupper", "istitle", "isidentifier", "isascii", "count",
                  "find", "index", "rfind", "rindex", "__contains__"):
        return boolean()
    if method in ("items", "values", "keys", "get", "pop", "copy", "splitlines", "strip") and taints:
        return of_taints(taints)
    return None


def _is_orm_get(func):
    """`User.query.get(…)`, `db.session.get(User, …)` 형태인지."""
    names = []
    node = func.value
    while isinstance(node, (ast.Attribute, ast.Call)):
        if isinstance(node, ast.Attribute):
            names.append(node.attr)
            node = node.value
        else:
            node = node.func
    return "query" in names or (names[:1] == ["session"] and isinstance(node, ast.Name))


def _removed(value, characters):
    """지운 문자들을 값에 적는다. 무엇을 지웠는지 모르면 값은 그대로다."""
    if not characters:
        return value.plain()
    return value.map_taints(lambda taint: replace(taint, removed=taint.removed | frozenset(characters)))


def _pattern_characters(pattern):
    """`[|;&]` 같은 문자 클래스 하나로 된 정규식이 지우는 문자들. 그 밖의 정규식은 None."""
    text = pattern.text
    if not text:
        return None
    match = re.fullmatch(r"\[((?:\\.|[^\]\\])+)\]\+?", text)
    if not match:
        return None
    characters, body, index = set(), match.group(1), 0
    while index < len(body):
        if body[index] == "\\" and index + 1 < len(body):
            index += 1
        characters.add(body[index])
        index += 1
    return characters


# ---------------------------------------------------------------------- 비교
def truth(value):
    """`if 값:`에서 값이 참일 때·거짓일 때 확정되는 사실."""
    if value.obj and value.obj[0] in ("session", "current_user"):
        return set(), set()
    if "session" in value.marks():
        keys = value.mark_values("key:")
        if any(is_admin_key(key) for key in keys):
            return {("authz", "admin")}, set()
        return {("authz", "login")}, set()
    return set(), set()


def _side(value):
    """비교식의 한쪽이 무엇인지 (스펙 4.5)."""
    marks = value.marks()
    if "session" in marks:
        return "session"
    if any(taint.has(EXTERNAL) for taint in value.taints(deep=False)):
        return "request"
    if "db" in marks:
        fields = value.mark_values("field:")
        return "owner_field" if not fields or any(is_owner_field(field) for field in fields) else "field"
    if value.const is not NOCONST and value.is_static:
        if isinstance(value.const, str) and value.const.lower() in ADMIN_VALUES:
            return "admin_value"
        return "value"
    return "other"


_AUTHZ = {
    frozenset({"session", "owner_field"}): "owner",
    frozenset({"session", "request"}): "owner",
    frozenset({"session", "admin_value"}): "admin",
    frozenset({"session", "value"}): "role",
    frozenset({"session", "field"}): "bad",
    frozenset({"owner_field", "request"}): "bad",
    frozenset({"request", "admin_value"}): "bad",
}


def _authz(left, right):
    sides = (_side(left), _side(right))
    kind = _AUTHZ.get(frozenset(sides))
    if kind == "role":
        session_side = left if sides[0] == "session" else right
        other = right if sides[0] == "session" else left
        keys = session_side.mark_values("key:")
        if any(is_admin_key(key) for key in keys) and other.const not in (False, 0, None, ""):
            return "admin"
        if not any(is_role_key(key) for key in keys):
            return None  # 역할과 관계없는 세션 값 비교
    return kind


def compare(fx, node, operator, left, right, env):  # noqa: C901 - 비교 종류별 분기
    """비교식이 참일 때·거짓일 때 확정되는 사실 (wt, wf)."""
    wt, wf = set(), set()
    negative = isinstance(operator, (ast.NotIn, ast.NotEq, ast.IsNot))
    hit, miss = (wf, wt) if negative else (wt, wf)

    if isinstance(operator, (ast.In, ast.NotIn)):
        store = fx.is_global_store(node.comparators[0], env)
        if not store and collection_of(right) is not None:
            hit.update(("v", "allow", taint.origin, taint.part) for taint in left.taints(deep=False))
        if right.obj and right.obj[0] == "session" and isinstance(left.const, str):
            hit.add(("authz", "admin" if is_admin_key(left.const) else "login"))
    elif isinstance(operator, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
        for one, other in ((left, right), (right, left)):
            if other.is_static and other.const is not NOCONST and not isinstance(other.const, bool):
                if other.const is not None:
                    hit.update(("v", "allow", taint.origin, taint.part) for taint in one.taints(deep=False))
                elif "session" in one.marks():
                    miss.add(("authz", "login"))  # `g.user is None`이 거짓이면 로그인한 것이다
        kind = _authz(left, right)
        if kind:
            hit.add(("authz", kind))
        hit.update(_password_compare(fx, node, left, right, env, record=True))
    elif isinstance(operator, (ast.Gt, ast.GtE, ast.Lt, ast.LtE)):
        fact = _limit(fx, node, operator, left, right, env)
        if fact:
            over_when_true = fact[1]
            (wf if over_when_true else wt).add(fact[0])
    return wt, wf


def _password_compare(fx, node, left, right, env, record):
    """요청에서 받은 비밀번호(또는 그 해시)를 저장된 값과 `==`로 대조하는 곳 (스펙 4.10)."""
    from .flow import CompareEvent

    if left is None or right is None:
        return frozenset()
    for given, stored in ((left, right), (right, left)):
        passwords = [taint for taint in given.taints(deep=False) if taint.has(PASSWORD)]
        if not passwords or any(taint.has(PASSWORD) or taint.has(EXTERNAL) for taint in stored.taints()):
            continue
        if stored.is_static and stored.const in ("", None, b""):
            continue
        facts = _verified(stored, given)
        if record:
            fx.record(CompareEvent, node, env, kind="password", info={"stored_static": stored.is_static})
        return facts
    return frozenset()


def _names_in(fx, node):
    names = set()
    for inner in ast.walk(node):
        if isinstance(inner, ast.Name):
            names.add(inner.id)
            assigned = fx.last_expr.get(inner.id)
            if assigned is not None:
                for deeper in ast.walk(assigned):
                    if isinstance(deeper, ast.Name):
                        names.add(deeper.id)
                    elif isinstance(deeper, ast.Attribute):
                        names.add(deeper.attr)
                    elif isinstance(deeper, ast.Constant) and isinstance(deeper.value, str):
                        names.add(deeper.value)
        elif isinstance(inner, ast.Attribute):
            names.add(inner.attr)
        elif isinstance(inner, ast.Constant) and isinstance(inner.value, str):
            names.add(inner.value)
    return names


def _limit(fx, node, operator, left, right, env):
    """실패 횟수를 숫자와 비교하는 곳이면 (사실, 참일 때 한도를 넘은 것인지), 아니면 None (스펙 4.10)."""
    from .flow import CompareEvent

    def stored_in(value):
        marks = value.marks()
        if "session" in marks or any(taint.via == "cookies" for taint in value.taints(deep=False)):
            return "client"
        if marks & {"db", "global"}:
            return "server"
        return None

    def number(value):
        return value.const if isinstance(value.const, int) and not isinstance(value.const, bool) else None

    counter_left = stored_in(left) is not None and number(left) is None
    counter_right = stored_in(right) is not None and number(right) is None
    if counter_left == counter_right:
        return None
    names = _names_in(fx, node)
    if not any(is_counter_name(name) for name in names) or any(is_time_name(name) for name in names):
        return None  # 횟수 비교가 아니다 (경과 시간 비교 등)
    counter, limit = (left, right) if counter_left else (right, left)
    kind = type(operator)
    if not counter_left:  # `한도 <= 횟수`는 `횟수 >= 한도`와 같다
        kind = {ast.Gt: ast.Lt, ast.GtE: ast.LtE, ast.Lt: ast.Gt, ast.LtE: ast.GtE}[kind]
    value = number(limit)
    allowed = None if value is None else value + (1 if kind in (ast.Gt, ast.LtE) else 0)
    store = stored_in(counter)
    fact = ("limit", allowed, store)
    fx.record(CompareEvent, node, env, kind="limit", info={"allowed": allowed, "store": store})
    return fact, kind in (ast.Gt, ast.GtE)
