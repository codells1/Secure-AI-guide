"""4.2 OS 명령어 삽입 (os_command_injection): CMD-1, CMD-2."""
from .common import covered, externals, flow_finding

VULN_ID = "os_command_injection"

SHELL_FUNCTIONS = frozenset({"os.system", "os.popen"})
SUBPROCESS_FUNCTIONS = frozenset(
    {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
     "subprocess.getoutput", "subprocess.getstatusoutput"}
)
# Python 가이드 p.29, p.32가 지우라고 한 문자들
SHELL_CHARACTERS = frozenset("|;&:><`\\!")


def check(source):
    program = source.flow
    findings = []
    for event in program.calls:
        if event.name in SHELL_FUNCTIONS:
            command, shell = event.arg(0, "command") or event.arg(None, "cmd"), False
        elif event.name in SUBPROCESS_FUNCTIONS:
            command = event.arg(0, "args") or event.arg(None, "cmd")
            flag = event.kwargs.get("shell")
            shell = flag is not None and flag.const is True
        else:
            continue
        for taint in externals(command):
            if covered(taint, event.facts, ("allow", "format")) or "num" in taint.checks:
                continue  # 허용 목록·형식 검사·숫자 변환을 거친 값
            filtered = "quote" in taint.checks or SHELL_CHARACTERS <= taint.removed
            if not filtered:
                findings.append(flow_finding(program, event, taint, "CMD-1"))
            elif shell:
                findings.append(flow_finding(program, event, taint, "CMD-2"))
    return findings
