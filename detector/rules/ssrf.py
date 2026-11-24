"""4.6 서버사이드 요청 위조 (ssrf): SSRF-1."""
import re

from ..values import EXTERNAL, S, T
from .common import covered, flow_finding

VULN_ID = "ssrf"
QUESTION = "사용자가 준 주소로 서버가 꼭 요청해야 하는 기능인가요?"

CLIENTS = ("requests", "httpx")
CLIENT_OBJECTS = frozenset({"requests.Session", "requests.sessions.Session", "httpx.Client", "httpx.AsyncClient"})
URL_FIRST = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})  # f(url, ...)
URL_FIRST_FUNCTIONS = frozenset(
    {f"{client}.{function}" for client in CLIENTS for function in URL_FIRST}
    | {"urllib.request.urlopen", "urllib.request.Request"}
)
URL_SECOND_FUNCTIONS = frozenset({f"{client}.request" for client in CLIENTS})  # f(method, url, ...)

# 주소의 `scheme://호스트/`까지가 코드에 적혀 있으면 요청이 가는 서버는 고정이다
_FIXED_HOST = re.compile(r"\s*[A-Za-z][A-Za-z0-9+.\-]*://[^/?#\s]+[/?#]")


def _url(event):
    if event.name in URL_FIRST_FUNCTIONS:
        return event.arg(0, "url")
    if event.name in URL_SECOND_FUNCTIONS:
        return event.arg(1, "url")
    if event.instance in CLIENT_OBJECTS:
        if event.method in URL_FIRST:
            return event.arg(0, "url")
        if event.method == "request":
            return event.arg(1, "url")
    return None


def check(source):
    program = source.flow
    findings = []
    for event in program.calls:
        url = _url(event)
        if url is None:
            continue
        for alt in url.alts:
            head = []
            for atom in alt:
                if not isinstance(atom, S):
                    break
                head.append(atom.text)
            if _FIXED_HOST.match("".join(head)):
                continue
            for atom in alt:
                if isinstance(atom, T) and atom.taint.has(EXTERNAL) and not covered(atom.taint, event.facts):
                    findings.append(flow_finding(program, event, atom.taint, "SSRF-1"))
    return findings


def evaluate(source, user_input):
    """(findings, needs_user_input). 판정은 위험 그대로이고, 응답이 없으면 질문을 함께 내려 준다 (스펙 5.2)."""
    findings = check(source)
    answer = user_input.get(VULN_ID)
    answered = isinstance(answer, dict) and "dynamic_request_needed" in answer
    if findings and not answered:
        return findings, {"type": "ssrf_dynamic_request", "question": QUESTION}
    return findings, None


def is_acknowledged(user_input):
    """학생이 "꼭 필요한 기능"이라고 답했는지. 판정은 위험 그대로 두고 확인 표시만 한다."""
    answer = user_input.get(VULN_ID)
    return isinstance(answer, dict) and answer.get("dynamic_request_needed") is True
