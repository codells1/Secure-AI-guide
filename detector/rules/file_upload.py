"""4.3 위험한 형식 파일 업로드 (file_upload): UP-1, UP-2."""
from ..result import Finding
from ..values import UPLOAD

VULN_ID = "file_upload"

# (규칙, 저장 전에 허용 목록으로 확인해야 하는 것)
REQUIRED = (("UP-1", "ext"), ("UP-2", "ctype"))


def check(source):
    program = source.flow
    findings = []
    for event in program.calls:
        if event.method != "save" or event.receiver is None:
            continue
        for upload in sorted(
            (taint for taint in event.receiver.taints(deep=False) if taint.has(UPLOAD)), key=lambda t: t.origin
        ):
            line = program.report_line(event, upload)
            for rule_id, part in REQUIRED:
                if ("v", "allow", upload.origin, part) not in event.facts:
                    findings.append(Finding(line, rule_id))
    return findings
