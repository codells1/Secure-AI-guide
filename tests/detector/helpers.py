"""탐지 모듈 테스트가 같이 쓰는 도우미."""
import textwrap

from detector import analyze

# IDOR은 학생이 답해야 판정한다. 후보 라우트를 모두 "본인만 봐야 한다"고 답한 상태로 검사한다.
ALL_PRIVATE = {"idor": {"public_functions": []}}

HEAD = "from flask import Flask, request, render_template, session, abort, jsonify\n\napp = Flask(__name__)\n\n\n"


def block(text):
    """들여쓰기를 정리한 코드 조각."""
    return textwrap.dedent(text).strip("\n")


def flask_app(body, imports="", *more):
    """Flask 앱의 머리말을 붙인 코드. body와 more의 조각은 들여쓰기를 따로 정리해 차례로 붙인다."""
    pieces = "\n\n\n".join(block(piece) for piece in (body, *more))
    return (imports + "\n" if imports else "") + HEAD + pieces + "\n"


def _item(code, vuln_id, user_input):
    result = analyze(code, user_input)
    assert result["ok"], result.get("error")
    return next(item for item in result["results"] if item["vuln_id"] == vuln_id)


def rules(code, vuln_id, user_input=ALL_PRIVATE):
    """그 취약점에 걸린 규칙들 (정렬된 목록)."""
    return sorted({finding["rule_id"] for finding in _item(code, vuln_id, user_input)["findings"]})


def lines(code, vuln_id, user_input=ALL_PRIVATE):
    """그 취약점의 (규칙, 줄) 목록."""
    return [(finding["rule_id"], finding["line"]) for finding in _item(code, vuln_id, user_input)["findings"]]


def verdict(code, vuln_id, user_input=ALL_PRIVATE):
    return _item(code, vuln_id, user_input)["verdict"]


def risky(code, user_input=ALL_PRIVATE):
    """안전이 아닌 항목: vuln_id → 규칙들."""
    result = analyze(code, user_input)
    assert result["ok"], result.get("error")
    return {
        item["vuln_id"]: sorted({finding["rule_id"] for finding in item["findings"]})
        for item in result["results"]
        if item["verdict"] != "안전"
    }
