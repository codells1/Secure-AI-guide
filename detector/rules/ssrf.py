"""4.6 서버사이드 요청 위조 (ssrf): SSRF-1."""
from ..result import Finding
from ..taint import Kind, Sink, TaintSpec, find_sink_hits, register

VULN_ID = "ssrf"
QUESTION = "사용자가 준 주소로 서버가 꼭 요청해야 하는 기능인가요?"

CLIENTS = ("requests", "httpx")
CLIENT_OBJECTS = ("requests.Session", "httpx.Client")
URL_FIRST_FUNCTIONS = ("get", "post", "put", "patch", "delete", "head", "options")  # f(url, ...)

# 도착점: 요청을 보내는 함수(모듈 함수와 Session·Client 객체의 메서드)의 URL 인자
SPEC = register(
    TaintSpec(
        vuln_id=VULN_ID,
        sinks=(
            *(
                Sink(function=f"{client}.{function}", arg=0, keywords=("url",))
                for client in CLIENTS
                for function in URL_FIRST_FUNCTIONS
            ),
            *(Sink(function=f"{client}.request", arg=1, keywords=("url",)) for client in CLIENTS),
            *(
                Sink(method=function, objects=CLIENT_OBJECTS, arg=0, keywords=("url",))
                for function in URL_FIRST_FUNCTIONS
            ),
            Sink(method="request", objects=CLIENT_OBJECTS, arg=1, keywords=("url",)),
            Sink(function="urllib.request.urlopen", arg=0, keywords=("url",)),
        ),
    )
)


def check(source):
    """사용자 입력이 URL 자리에 도달하면 위험하다.

    상수 URL과 비교해 통과한 값(스펙 3.6), 상수 목록에서 꺼낸 URL은 엔진에서 이미 '고정 선택' 값이 되어
    여기 오지 않는다. 도메인 비교, startswith, 블랙리스트, 자작 검사 함수는 값을 바꾸지 못하므로 오염이 남는다.
    """
    findings = []
    for hit in find_sink_hits(source, SPEC):
        for value in hit.values:
            for part in value:
                if part.kind is Kind.TAINTED:
                    findings.append(Finding(hit.report_line, "SSRF-1", hit.path(part)))
    return findings


def evaluate(source, user_input):
    """(findings, needs_user_input). 판정은 위험 그대로이고, 응답이 없으면 질문을 함께 내려 준다 (스펙 5장)."""
    findings = check(source)
    answer = user_input.get(VULN_ID)
    answered = isinstance(answer, dict) and "dynamic_request_needed" in answer
    if findings and not answered:
        return findings, {"type": "ssrf_dynamic_request", "question": QUESTION}
    return findings, None


def is_acknowledged(user_input):
    """학생이 "사용자가 준 주소로 서버가 꼭 요청해야 하는 기능"이라고 답했는지 (스펙 5장).

    판정은 위험 그대로 두고 확인 표시만 한다.
    """
    answer = user_input.get("ssrf")
    return isinstance(answer, dict) and answer.get("dynamic_request_needed") is True
