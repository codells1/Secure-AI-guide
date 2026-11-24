"""4.4 경로 조작 (path_traversal): PATH-1."""
from ..values import UPLOAD
from .common import covered, externals, flow_finding, is_builtin_call

VULN_ID = "path_traversal"

# 첫 인자가 경로인 함수
PATH_FUNCTIONS = frozenset(
    {"io.open", "codecs.open", "os.remove", "os.unlink", "os.rmdir", "os.listdir", "os.mkdir", "os.makedirs",
     "os.rename", "os.replace", "os.scandir", "shutil.rmtree", "shutil.copy", "shutil.copy2", "shutil.copyfile",
     "shutil.move", "flask.send_file"}
)
PATH_METHODS = frozenset(
    {"open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir", "mkdir", "iterdir"}
)
# Python 가이드 p.18~19: 경로순회에 쓰이는 문자. 셋을 모두 지워야 인정한다
PATH_CHARACTERS = frozenset({"/", "\\", "."})
SAFE_CHECKS = frozenset({"num", "secure_name", "safe_join"})


def _paths(event):
    """이 호출이 파일 경로를 받는 자리면 그 경로 값들."""
    if is_builtin_call(event, "open") or event.name in PATH_FUNCTIONS:
        return [value for value in (event.arg(0, "file"), event.arg(None, "path"), event.arg(None, "path_or_file"),
                                    event.arg(None, "src"), event.arg(None, "dst")) if value is not None]
    if event.method == "save" and event.receiver is not None:
        if any(taint.has(UPLOAD) for taint in event.receiver.taints(deep=False)):
            target = event.arg(0, "dst")
            return [target] if target is not None else []
    if event.instance == "pathlib.Path" and event.method in PATH_METHODS:
        return [event.receiver]
    return []


def check(source):
    program = source.flow
    findings = []
    for event in program.calls:
        for path in _paths(event):
            for taint in externals(path):
                if (
                    covered(taint, event.facts, ("allow", "format"))
                    or taint.checks & SAFE_CHECKS
                    or PATH_CHARACTERS <= taint.removed
                ):
                    continue
                findings.append(flow_finding(program, event, taint, "PATH-1"))
    return findings
