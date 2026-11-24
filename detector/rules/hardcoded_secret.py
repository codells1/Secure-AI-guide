"""4.8 하드코딩된 시크릿 (hardcoded_secret): KEY-1, KEY-2, KEY-3, KEY-4.

흐름을 따라가지 않고 코드의 모양만 본다. 수정 피드백의 가리기(fixer/masking.py)가
`secret_values()`와 `literal_nodes()`로 가릴 자리를 찾는다.
"""
import ast
import re
from dataclasses import dataclass

from ..result import Finding
from ..source import iter_nodes_with_scope
from ..words import PASSWORD_KOREAN, is_secret_name, split_words

VULN_ID = "hardcoded_secret"
COMMENT_RULE = "KEY-4"
ENV_READERS = frozenset({"os.getenv", "os.environ.get"})
CONFIG_SETTERS = frozenset({"update", "from_mapping"})

# 주석(KEY-4): 비밀 이름 또는 '비밀번호' 뒤에 `:`나 `=`(`==` 제외)가 오고 그 뒤에 값이 있는 형태.
# 키워드와 구분자 사이의 따옴표·대괄호는 허용한다: `# app.config["SECRET_KEY"] = "abc"`
_FOLLOWS = r"[\"'\]\s]*[:=](?!=)\s*(\S.*)$"
_NAME_VALUE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)" + _FOLLOWS)
_KOREAN_VALUE = re.compile("(?:" + "|".join(PASSWORD_KOREAN) + ")" + _FOLLOWS)
_HANGUL = re.compile(r"[ㄱ-ㆎ가-힣]")
_CODE = re.compile(r"[(\[]|^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")


@dataclass(frozen=True)
class Secret:
    rule_id: str
    node: ast.AST  # 코드에 적힌 값. 보고하는 줄은 이 노드의 줄이다
    scope: ast.AST | None


def check(source):
    findings = [Finding(secret.node.lineno, secret.rule_id) for secret in secret_values(source)]
    findings.extend(Finding(comment.line, COMMENT_RULE) for comment in source.comments if _comment_has_secret(comment.text))
    return findings


def secret_values(source):
    """코드에 적힌 비밀 값들 (KEY-1 ~ KEY-3). 같은 값은 한 번만."""
    found, seen = [], set()

    def add(rule_id, node, scope):
        if (rule_id, id(node)) not in seen:
            seen.add((rule_id, id(node)))
            found.append(Secret(rule_id, node, scope))

    for node, scope in iter_nodes_with_scope(source.tree):
        for rule_id, value in _slots(node):
            if source.static.is_hardcoded(value, scope):
                add(rule_id, value, scope)
                continue
            # 환경변수에서 읽더라도 기본값이 리터럴이면 그 값이 비밀 자리에 들어간다
            default = _env_default(source, value)
            if default is not None and source.static.is_hardcoded(default, scope):
                add("KEY-3", default, scope)
        if isinstance(node, ast.Call):
            default = _env_default(source, node)
            name = node.args[0] if node.args else None
            if (
                default is not None
                and isinstance(name, ast.Constant)
                and isinstance(name.value, str)
                and is_secret_name(name.value)
                and source.static.is_hardcoded(default, scope)
            ):
                add("KEY-3", default, scope)
        elif isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            for named, literal in ((node.left, node.comparators[0]), (node.comparators[0], node.left)):
                if _is_password_like(_expression_name(named)) and _is_literal(literal):
                    if source.static.is_hardcoded(literal, scope):
                        add("KEY-2", literal, scope)
    return found


def literal_nodes(source, node, scope, _seen=()):
    """값 노드에서 실제로 글자가 적힌 자리들: 문자열·bytes 리터럴과 f-string. 이름은 대입된 값까지 따라간다."""
    if isinstance(node, ast.Constant):
        return [node] if isinstance(node.value, (str, bytes)) and node.value else []
    found = [node] if isinstance(node, ast.JoinedStr) else []
    if isinstance(node, ast.Name):
        if node.id in _seen:
            return []
        for value, value_scope in source.static.assigned_values(node.id, scope) or ():
            found += literal_nodes(source, value, value_scope, (*_seen, node.id))
        return found
    for child in ast.iter_child_nodes(node):
        if isinstance(node, ast.JoinedStr) and isinstance(child, ast.Constant):
            continue  # f-string 안의 글자는 f-string 전체를 가릴 때 함께 가려진다
        found += literal_nodes(source, child, scope, _seen)
    return found


def _slots(node):
    """비밀 값이 들어가는 자리: (리터럴이 들어 있으면 걸릴 규칙, 그 자리의 값 노드)."""
    for target, value in _assignment_pairs(node):
        if _is_secret_key(target):
            yield "KEY-1", value  # app.secret_key = ..., app.config["SECRET_KEY"] = ...
        elif isinstance(target, ast.Name):
            if is_secret_name(target.id):
                yield "KEY-2", value  # 변수: DB_PASSWORD = ...
        elif isinstance(target, ast.Attribute):
            if is_secret_name(target.attr):
                yield "KEY-2", value  # 속성: user.password = ...
        elif isinstance(target, ast.Subscript):
            if is_secret_name(_string(target.slice) or ""):
                yield "KEY-2", value  # dict 키: config["DB_PASSWORD"] = ...
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if key is not None and is_secret_name(_string(key) or ""):
                yield "KEY-2", value  # dict 키: {"password": ...}
    elif isinstance(node, ast.Call):
        config = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in CONFIG_SETTERS
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "config"
        )
        for keyword in node.keywords:
            if keyword.arg == "SECRET_KEY" and config:
                yield "KEY-1", keyword.value  # app.config.update(SECRET_KEY=...)
            elif keyword.arg and is_secret_name(keyword.arg):
                yield "KEY-2", keyword.value  # 키워드 인자: connect(password=...)


def _assignment_pairs(node):
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if (
                isinstance(target, (ast.Tuple, ast.List))
                and isinstance(node.value, (ast.Tuple, ast.List))
                and len(target.elts) == len(node.value.elts)
            ):
                yield from zip(target.elts, node.value.elts)
            else:
                yield target, node.value
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        yield node.target, node.value


def _is_secret_key(target):
    """대입 대상이 Flask 세션 서명 키인지 (KEY-1)."""
    if isinstance(target, ast.Attribute):
        return target.attr == "secret_key"
    if isinstance(target, ast.Subscript):
        holder = target.value
        is_config = (isinstance(holder, ast.Attribute) and holder.attr == "config") or (
            isinstance(holder, ast.Name) and holder.id == "config"
        )
        return is_config and _string(target.slice) == "SECRET_KEY"
    return False


def _env_default(source, node):
    """node가 `os.getenv(이름, 기본값)`·`os.environ.get(이름, 기본값)`이면 기본값 노드, 아니면 None."""
    if isinstance(node, ast.Call) and source.names.resolve(node.func) in ENV_READERS:
        for keyword in node.keywords:
            if keyword.arg == "default":
                return keyword.value
        if len(node.args) > 1:
            return node.args[1]
    return None


def _expression_name(node):
    """비교식 한쪽의 이름: 변수, 속성, 문자열 키, `.get("키")`."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _string(node.slice) or ""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
        return _string(node.args[0]) or ""
    return ""


def _is_password_like(name):
    """비교로 하드코딩을 볼 때는 `key` 한 단어 이름을 뺀다 (`if key == "name"` 같은 코드가 많다)."""
    return bool(name) and is_secret_name(name) and split_words(name) != ["key"]


def _is_literal(node):
    return isinstance(node, (ast.Constant, ast.JoinedStr))


def _string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _comment_has_secret(text):
    """주석 속 `키워드 + (: 또는 =) + 값` (KEY-4). 값이 설명 문장이나 코드면 해당하지 않는다."""
    values = [match.group(1) for match in _KOREAN_VALUE.finditer(text)]
    values += [match.group(2) for match in _NAME_VALUE.finditer(text) if is_secret_name(match.group(1))]
    return any(_looks_like_secret(value) for value in values)


def _looks_like_secret(value):
    value = value.strip()
    if value[:1] in ("'", '"'):
        return len(value) > 2 or (len(value) == 2 and value[0] != value[1])
    token = value.split()[0].rstrip(",.;)")
    if not token or _HANGUL.search(token) or _CODE.search(token):
        return False
    if token in ("None", "True", "False"):
        return False
    # 따옴표가 없는 값은 숫자나 기호가 섞여 있을 때만 비밀 값으로 본다 (`admin1234`, `tok-0000`)
    return any(character.isdigit() or not (character.isalnum() or character == "_") for character in token)
