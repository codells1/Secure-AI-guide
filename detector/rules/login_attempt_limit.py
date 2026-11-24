"""4.10 로그인 보안: 반복된 인증시도 제한 (login_attempt_limit): LOGIN-1 ~ LOGIN-4.

요청에서 받은 비밀번호를 확인하는 라우트마다, 실패 횟수를 세어 제한하는지 본다.
비밀번호 확인과 횟수 비교는 models.py가 사건과 사실로 남긴다.
"""
import ast
import re

from ..result import Finding

VULN_ID = "login_attempt_limit"

MAX_ALLOWED = 5  # 진단가이드 p.110 "로그인 시도횟수를 3~5번 이내로 제한"
VERIFIED = ("auth", "verified")
_RATE = re.compile(r"\s*(\d+)\s*(?:per|/)\s*(?:\d+\s*)?([A-Za-z]+)")


def check(source):
    program = source.flow
    findings = []
    for route in program.routes:
        fn = route.fn
        verifications = _verifications(program, fn)
        if not verifications:
            continue  # 비밀번호를 확인하는 라우트가 아니다
        limiter = _limiter(fn)
        if limiter is not None:
            line, allowed, unit_ok = limiter
            if allowed is None or allowed > MAX_ALLOWED or not unit_ok:
                findings.append(Finding(line, "LOGIN-2"))
            continue
        limits = [event for event in program.compares if event.entry is fn and event.kind == "limit"]
        if not limits:
            findings.append(Finding(fn.lineno, "LOGIN-1"))
            continue
        for event in limits:
            allowed = event.info["allowed"]
            if allowed is None or allowed > MAX_ALLOWED:
                findings.append(Finding(event.entry_line, "LOGIN-2"))
        if any(event.info["store"] == "client" for event in limits):
            findings.append(Finding(_increment_line(program, fn) or limits[0].entry_line, "LOGIN-3"))
        for line, facts in verifications:
            if not any(fact[0] == "limit" for fact in facts):
                findings.append(Finding(line, "LOGIN-4"))  # 잠금 확인을 거치지 않고 비밀번호를 확인한다
    return findings


def _verifications(program, fn):
    """이 라우트에서 비밀번호를 확인하는 곳들: (줄, 그 지점에서 통과한 검사)."""
    found = []
    for event in program.calls:
        if event.entry is fn and VERIFIED in event.result.wt:
            found.append((event.entry_line, event.facts))
    for event in program.compares:
        if event.entry is fn and event.kind == "password":
            found.append((event.entry_line, event.facts))
    return found


def _limiter(fn):
    """`@limiter.limit("5 per minute")`가 붙어 있으면 (줄, 허용 횟수, 단위가 초가 아닌지)."""
    for decorator in fn.decorator_list:
        if not (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "limit"
        ):
            continue
        rate = decorator.args[0] if decorator.args else None
        text = rate.value if isinstance(rate, ast.Constant) and isinstance(rate.value, str) else ""
        match = _RATE.match(text)
        if not match:
            return decorator.lineno, None, True
        return decorator.lineno, int(match.group(1)), not match.group(2).lower().startswith("sec")
    return None


def _increment_line(program, fn):
    """세션·쿠키에 횟수를 적는 줄."""
    for event in program.assigns:
        if event.entry is not fn or not isinstance(event.target, (ast.Subscript, ast.Attribute)):
            continue
        holder = program.value(event.target.value)
        if holder is not None and holder.obj == ("session",):
            return event.entry_line
    for event in program.calls:
        if event.entry is fn and event.method == "set_cookie":
            return event.entry_line
    return None
