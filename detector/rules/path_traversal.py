"""4.4 경로 조작 (path_traversal): PATH-1."""
import ast

from ..astutil import iter_nodes_with_scope
from ..result import Finding
from ..taint import Kind, Sink, TaintSpec, find_sink_hits, register

VULN_ID = "path_traversal"

# KISA 예시 형태: 파일명에서 이 세 문자를 모두 지워야 정화로 인정한다.
REMOVED_CHARACTERS = frozenset({".", "/", "\\"})
# 세 문자를 지운 뒤 이 메서드를 거쳐도 정화가 유지된다.
KEEPS_REMOVAL = frozenset({"strip", "lower", "upper"})
PATH_METHODS = frozenset({"open", "read_text", "read_bytes", "write_text", "write_bytes"})


def _tag_removed_characters(call):
    """`name.replace(".", "")`나 `re.sub(r"[./\\\\]", "", name)`이 지우는 문자를 표시로 붙인다."""
    if call.keywords or len(call.texts) < 2 or call.texts[1] != "" or not call.texts[0]:
        return frozenset()  # 지우는 것이 아니거나, count 등으로 일부만 지운다
    if call.method == "replace" and len(call.texts) == 2:
        return frozenset({call.texts[0]}) & REMOVED_CHARACTERS
    if call.name == "re.sub" and len(call.texts) == 3:
        return _class_members(call.texts[0]) & REMOVED_CHARACTERS
    return frozenset()


def _class_members(pattern):
    """`[./\\\\]`처럼 문자 클래스 하나로 된 정규식이 지우는 글자들.

    학생이 쓴 정규식을 실행하지 않고 글자만 읽는다. 다른 모양의 정규식은 인정하지 않는다.
    """
    body = pattern.rstrip("+*")
    if not (body.startswith("[") and body.endswith("]")) or body.startswith("[^"):
        return frozenset()
    inner = body[1:-1]
    members = set()
    index = 0
    while index < len(inner):
        if inner[index] == "\\" and index + 1 < len(inner):
            index += 1  # 이스케이프된 글자: `\\` → `\`, `\.` → `.`
        members.add(inner[index])
        index += 1
    return frozenset(members)


def _is_path_object(node, scope, source, seen=frozenset()):
    """`Path(...)`, `Path("d") / name`, `Path(a).joinpath(b)`이거나 그것을 담은 변수인지."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _is_path_object(node.left, scope, source, seen)
    if isinstance(node, ast.Name):
        if node.id in seen:
            return False
        definition = source.static.sole_value(node.id, scope)
        return definition is not None and _is_path_object(definition, scope, source, seen | {node.id})
    if isinstance(node, ast.Call):
        if (source.names.resolve(node.func) or "").startswith("pathlib.Path"):
            return True
        return isinstance(node.func, ast.Attribute) and _is_path_object(node.func.value, scope, source, seen)
    return False


def _path_objects(source):
    """`Path(...)`의 파일을 읽고 쓰는 메서드를 부르는 대상 식들."""
    for node, scope in iter_nodes_with_scope(source.tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in PATH_METHODS
            and _is_path_object(node.func.value, scope, source)
        ):
            yield node.func.value, "path_object"


SPEC = register(
    TaintSpec(
        vuln_id=VULN_ID,
        sinks=(
            Sink(function="open", arg=0, keywords=("file",)),
            Sink(function="os.open", arg=0, keywords=("path",)),
            Sink(function="flask.send_file", arg=0, keywords=("path_or_file",)),
            # send_from_directory(고정 폴더, 이름): 폴더 자리에 사용자 입력이 오면 안전한 형태가 아니다.
            Sink(function="flask.send_from_directory", arg=0, keywords=("directory",)),
        ),
        sanitizers=frozenset({"werkzeug.utils.secure_filename"}),
        propagators=frozenset({"os.path.join", "pathlib.Path"}),
        tagger=_tag_removed_characters,
        probes=_path_objects,
        tag_keeping_methods=KEEPS_REMOVAL,
        division_joins=True,
    )
)


def check(source):
    findings = []
    for hit in find_sink_hits(source, SPEC):
        for value in hit.values:
            for part in value:
                if part.kind is Kind.TAINTED and not REMOVED_CHARACTERS <= part.tags:
                    findings.append(Finding(hit.report_line, "PATH-1", hit.path(part)))
    return findings
