"""판정 결과 형식 (스펙 6장)과 규칙별 메시지 (부록 A)."""
from dataclasses import dataclass

SAFE = "안전"
VULNERABLE = "위험"

# 부록 A의 문구 그대로다. 단계가 끝날 때마다 그 단계에서 구현한 규칙을 추가한다.
MESSAGES = {
    "SQL-1": "사용자가 입력한 값이 SQL 문장 안에 그대로 들어가요. 값은 `?` 자리로 따로 넘겨야 해요.",
    "SQL-2": "정렬 기준에 사용자가 입력한 값이 그대로 들어가요. 미리 정해 둔 목록에서만 고르게 해야 해요.",
    "SQL-3": "SQL 문장을 문자열로 이어 붙여 만들고 있어요. 문장은 고정하고 값은 `?` 자리로 넘겨야 해요.",
    "SSTI-1": "사용자가 입력한 값이 템플릿 원본에 들어가요. 템플릿은 고정하고 값은 변수로 넘겨야 해요.",
    "SSTI-2": "사용자가 입력한 값으로 템플릿 파일을 고르고 있어요. 미리 정해 둔 목록에서만 고르게 해야 해요.",
    "SSTI-3": "템플릿 문법을 지우는 방식으로는 막을 수 없어요. 템플릿은 고정하고 값은 변수로 넘겨야 해요.",
    "SSTI-4": "템플릿 원본을 코드 밖의 값으로 만들고 있어요. 템플릿은 고정하고 값은 변수로 넘겨야 해요.",
    "UP-1": "올린 파일의 확장자를 허용 목록으로 확인하지 않아요.",
    "UP-2": "올린 파일의 형식(Content-Type)을 확인하지 않아요.",
    "PATH-1": "사용자가 입력한 값이 파일 경로에 그대로 들어가요. `../`로 다른 폴더의 파일을 열 수 있어요.",
    "IDOR-1": "주소의 번호만 바꾸면 다른 사람의 정보를 볼 수 있어요. 로그인한 사람의 것인지 확인해야 해요.",
    "IDOR-2": "로그인했는지만 확인하고, 본인의 정보인지는 확인하지 않아요.",
    "IDOR-3": "본인 확인에 사용자가 바꿀 수 있는 값을 쓰고 있어요. 세션에 저장된 로그인 정보와 비교해야 해요.",
    "IDOR-4": "회원인지만 확인하고, 본인의 정보인지는 확인하지 않아요.",
    "SSRF-1": "사용자가 입력한 주소로 서버가 직접 요청을 보내요. 미리 정해 둔 주소만 쓰게 해야 해요.",
    "DBG-1": "디버그 모드가 켜져 있어요. 브라우저에서 서버 코드를 실행할 수 있는 디버거가 열려요.",
    "DBG-2": "디버그 모드가 꺼져 있는지 코드에서 확인할 수 없어요. `debug=False`로 고정해야 해요.",
    "ERR-1": "오류 내용이 사용자 화면에 그대로 보여요. 정해 둔 안내 문구만 보여 줘야 해요.",
    "ERR-2": "오류 추적 정보(traceback)를 출력하고 있어요. 배포 전에 지워야 해요.",
    "KEY-1": "세션 서명 키(SECRET_KEY)가 코드에 그대로 적혀 있어요. 환경변수에서 읽어야 해요.",
    "KEY-2": "비밀번호나 키가 코드에 그대로 적혀 있어요. 환경변수에서 읽어야 해요.",
    "KEY-3": "환경변수가 없을 때 쓰는 기본값에 비밀 값이 적혀 있어요.",
    "KEY-4": "주석에 비밀번호나 키가 적혀 있어요. 배포 전에 지워야 해요.",
    "PW-1": "비밀번호를 그대로 저장하고 있어요. 해시로 바꿔서 저장해야 해요.",
    "PW-2": "취약한 것으로 알려진 해시 방식(MD5·SHA-1)을 쓰고 있어요.",
    "PW-3": "솔트 없이 해시하고 있어요. 같은 비밀번호는 같은 값이 되어 쉽게 알아낼 수 있어요.",
    "PW-4": "모든 사용자에게 같은 솔트를 쓰거나, 예측 가능한 난수로 솔트를 만들고 있어요.",
    "PW-5": "이 프로그램이 확인할 수 있는 해시 방식이 아니에요. 안내된 방식으로 바꿔야 해요.",
    "LOGIN-1": "로그인 실패 횟수를 제한하지 않아요. 비밀번호를 계속 바꿔 넣어 볼 수 있어요.",
    "LOGIN-2": "로그인 실패 허용 횟수가 너무 많거나 코드에서 확인할 수 없어요. 5번 이내로 제한해야 해요.",
    "LOGIN-3": "실패 횟수를 공격자가 지울 수 있는 곳(세션·쿠키)에 저장하고 있어요.",
    "LOGIN-4": "잠긴 계정도 비밀번호만 맞으면 로그인돼요. 잠금 확인을 먼저 해야 해요.",
}


@dataclass(frozen=True)
class Finding:
    """규칙 하나가 걸린 줄. 줄 번호는 1부터, 줄 단위로만 보고한다 (스펙 3.5)."""

    line: int
    rule_id: str
    path: tuple = ()  # 출발점 → 도착점까지 거친 줄. 오염 분석이 아닌 규칙은 비워 둔다


def vuln_result(vuln_id, findings, acknowledged=False, needs_user_input=None):
    """취약점 하나의 결과 항목을 만든다. findings가 비면 안전이다.

    needs_user_input이 있고 아직 찾은 것이 없으면 판정 전 질문이라 verdict는 None이다 (IDOR).
    찾은 것이 있으면 판정은 위험이고 질문은 판정 뒤에 묻는다 (SSRF). 스펙 5장.
    """
    unique = {}  # 같은 줄의 같은 규칙은 한 번만 (먼저 찾은 것), 줄 순서대로
    for finding in findings:
        unique.setdefault((finding.line, finding.rule_id), finding)
    verdict = VULNERABLE if unique else SAFE
    return {
        "vuln_id": vuln_id,
        "verdict": None if needs_user_input and not unique else verdict,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "line": finding.line,
                "path": list(finding.path) or [finding.line],
                "message": MESSAGES[finding.rule_id],
            }
            for _, finding in sorted(unique.items())
        ],
        "needs_user_input": needs_user_input,
        "acknowledged": acknowledged,
    }
