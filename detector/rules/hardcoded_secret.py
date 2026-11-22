"""4.8 하드코딩된 시크릿 (hardcoded_secret): KEY-1, KEY-2, KEY-3, KEY-4."""
import ast
import re

from ..astutil import assignment_pairs, call_argument, iter_nodes_with_scope, string_value
from ..naming import has_word
from ..result import Finding

VULN_ID = "hardcoded_secret"

# 이름 사전 (스펙 4.8). 이름을 단어로 나눴을 때 사전 단어가 그대로 들어 있으면 해당한다.
SECRET_WORDS = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "key")
# 주석(KEY-4)에서만 함께 쓰는 한글 키워드
COMMENT_WORDS = ("비밀번호",)
ENV_READERS = frozenset({"os.getenv", "os.environ.get"})

# 키워드 뒤에 `:` 또는 `=`(`==` 제외)가 오고 그 뒤에 값이 있는 형태.
# 키워드와 구분자 사이의 따옴표·대괄호는 허용한다: `# app.config["SECRET_KEY"] = "abc"`
_VALUE_FOLLOWS = r"[\"'\]\s]*[:=](?!=)(?=\s*\S)"
_NAME_WITH_VALUE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)" + _VALUE_FOLLOWS)
_COMMENT_WORD_WITH_VALUE = re.compile(
    "(?:" + "|".join(re.escape(word) for word in COMMENT_WORDS) + ")" + _VALUE_FOLLOWS
)


def check(source):
    findings = []
    for node, scope in iter_nodes_with_scope(source.tree):
        for rule_id, value in _secret_slots(node, source.names):
            findings.extend(_slot_findings(source, rule_id, value, scope))
        if isinstance(node, ast.Call):
            findings.extend(_env_name_findings(source, node, scope))
    findings.extend(_comment_findings(source.comments))
    return findings


def is_secret_name(name):
    """이름이 이름 사전에 해당하는지."""
    return has_word(name, SECRET_WORDS)


def _secret_slots(node, names):
    """비밀 값이 들어가는 자리를 찾아 (리터럴이 들어 있으면 걸릴 규칙, 그 자리의 값 노드)를 돌려준다."""
    for target, value in assignment_pairs(node):
        if _is_secret_key(target, names):
            yield "KEY-1", value  # app.secret_key = ..., app.config["SECRET_KEY"] = ...
        elif isinstance(target, ast.Name):
            if is_secret_name(target.id):
                yield "KEY-2", value  # 변수: DB_PASSWORD = ...
        elif isinstance(target, ast.Attribute):
            if is_secret_name(target.attr):
                yield "KEY-2", value  # 속성: user.password = ...
        elif isinstance(target, ast.Subscript):
            if is_secret_name(string_value(target.slice) or ""):
                yield "KEY-2", value  # dict 키: config["DB_PASSWORD"] = ...
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if is_secret_name(string_value(key) or ""):
                yield "KEY-2", value  # dict 키: {"password": ...}
    elif isinstance(node, ast.Call):
        for keyword in node.keywords:
            if keyword.arg and is_secret_name(keyword.arg):
                yield "KEY-2", keyword.value  # 키워드 인자: connect(password=...)


def _is_secret_key(target, names):
    """대입 대상이 Flask 세션 서명 키인지 (KEY-1)."""
    if isinstance(target, ast.Attribute):
        return target.attr == "secret_key" and names.is_app(target.value)
    if isinstance(target, ast.Subscript):
        return names.is_app_config(target.value) and string_value(target.slice) == "SECRET_KEY"
    return False


def _slot_findings(source, rule_id, value, scope):
    if _is_hardcoded(source, value, scope):
        return [Finding(value.lineno, rule_id)]
    # 환경변수에서 읽더라도 기본값이 리터럴이면 그 값이 비밀 자리에 들어간다.
    default = _env_default(source, value)
    if default is not None and _is_hardcoded(source, default, scope):
        return [Finding(default.lineno, "KEY-3")]
    return []


def _env_name_findings(source, call, scope):
    """이름 사전에 해당하는 환경변수를 리터럴 기본값과 함께 읽는 호출 (KEY-3)."""
    default = _env_default(source, call)
    if default is None:
        return []
    env_name = string_value(call_argument(call, 0, "key"))
    if env_name and is_secret_name(env_name) and _is_hardcoded(source, default, scope):
        return [Finding(default.lineno, "KEY-3")]
    return []


def _env_default(source, node):
    """node가 `os.getenv(이름, 기본값)`·`os.environ.get(이름, 기본값)`이면 기본값 노드, 아니면 None."""
    if isinstance(node, ast.Call) and source.names.resolve(node.func) in ENV_READERS:
        return call_argument(node, 1, "default")
    return None


def _is_hardcoded(source, node, scope):
    """코드에 적어 둔 값인지: 비어 있지 않은 문자열·bytes 리터럴 또는 그것들로만 만든 정적 문자열(3.4)."""
    parts = source.static.literal_parts(node, scope)
    return parts is not None and any(parts)


def _comment_findings(comments):
    """주석 속 `키워드 + (: 또는 =) + 값` (KEY-4)."""
    findings = []
    for comment in comments:
        if _COMMENT_WORD_WITH_VALUE.search(comment.text) or any(
            is_secret_name(match.group(1)) for match in _NAME_WITH_VALUE.finditer(comment.text)
        ):
            findings.append(Finding(comment.line, "KEY-4"))
    return findings
