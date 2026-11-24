from dotenv import load_dotenv
from flask import Flask, current_app, jsonify, render_template, request

import guided
from detector import analyze
from fixer import recheck
from fixer import service as fix_service
from fixer.cards import CardError

load_dotenv()

app = Flask(__name__)
# 너무 큰 요청은 받지 않는다 (학생이 올리는 .py 파일 하나면 충분한 크기).
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
# 응답의 한글과 항목 순서를 탐지 모듈이 준 그대로 내보낸다.
app.json.ensure_ascii = False
app.json.sort_keys = False

BAD_REQUEST_MESSAGE = "검사할 코드를 받지 못했어요."
FAILED_MESSAGE = "검사하지 못했어요. 파일을 다시 올려 주세요."


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_code():
    """올린 코드를 탐지 모듈로 검사해 결과를 돌려준다.

    코드는 이 요청을 처리하는 동안 메모리에서 읽기만 하고, 파일·DB·로그에 남기지 않는다.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("code"), str):
        return _error(BAD_REQUEST_MESSAGE, 400)
    user_input = data.get("user_input")
    if user_input is not None and not isinstance(user_input, dict):
        return _error(BAD_REQUEST_MESSAGE, 400)
    try:
        result = analyze(data["code"], user_input)
    except Exception:
        # 오류 내용에는 학생 코드가 섞일 수 있으므로 화면에도 로그에도 남기지 않는다.
        app.logger.error("ANALYZE-01")
        return _error(FAILED_MESSAGE, 500)
    if result.get("ok"):
        result = {**result, "groups": _fix_groups(data["code"], result), "guided": _guided(data["code"], result)}
    return jsonify(result)


def _fix_groups(code, result):
    """수정 피드백을 요청할 묶음 목록. 여기서 문제가 생겨도 탐지 결과는 그대로 돌려준다."""
    try:
        return fix_service.describe_groups(code, result)
    except Exception:
        app.logger.error("GROUPS-01")
        return []


def _guided(code, result):
    """위험 항목의 유도질문 5개와 정답. 여기서 문제가 생겨도 탐지 결과는 그대로 돌려준다 (질문 없이 진행한다)."""
    try:
        return guided.describe(code, result)
    except Exception:
        app.logger.error("GUIDED-01")
        return {}


def _error(message, status):
    return jsonify(ok=False, error={"line": None, "message": message}), status


@app.route("/api/fix", methods=["POST"])
def api_fix():
    """수정 묶음 하나의 쉬운 설명, 수정 전후 비교, 프롬프트를 돌려준다 (FixResult).

    가린 코드를 Claude API로 보낸다. 코드와 결과는 파일·DB·로그에 남기지 않는다.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("code"), str):
        return jsonify(error="invalid_request"), 400
    user_input, group, filename = body.get("user_input"), body.get("group"), body.get("filename")
    if (user_input is not None and not isinstance(user_input, dict)) or not isinstance(group, dict) \
            or not isinstance(group.get("group_id"), str) or not isinstance(filename, (str, type(None))):
        return jsonify(error="invalid_request"), 400
    try:
        found = fix_service.find_group(body["code"], user_input, group["group_id"])
        if found is None:
            return jsonify(error="group_not_found"), 409  # 코드가 바뀌어 그 묶음이 더는 없다
        client = current_app.config.get("FIX_CLIENT")  # 테스트에서 가짜 클라이언트를 넣는 자리
        return jsonify(fix_service.fix_group(body["code"], filename, found, user_input, client))
    except CardError:
        return jsonify(error="rule_not_ready"), 503
    except ValueError:
        return jsonify(error="invalid_code"), 400
    except Exception:
        # 오류 내용에는 학생 코드가 섞일 수 있으므로 화면에도 로그에도 남기지 않는다.
        app.logger.error("FIX-01")
        return jsonify(error="failed"), 500


@app.route("/api/recheck", methods=["POST"])
def api_recheck():
    """고친 코드를 다시 검사하고 이전 결과와 비교한다 (해결됨·아직 위험·새로 생김).

    Claude API는 부르지 않는다. 이전 결과는 저장해 두지 않고 브라우저가 보낸 것을 쓴다.
    피드백이 필요한 묶음은 브라우저가 /api/fix를 따로 부른다.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("code"), str) \
            or not isinstance(body.get("prev_code"), str) or not recheck.valid_results(body.get("prev_results")):
        return jsonify(error="invalid_request"), 400
    user_input = body.get("user_input")
    if user_input is not None and not isinstance(user_input, dict):
        return jsonify(error="invalid_request"), 400
    try:
        result = analyze(body["code"], user_input)
        if not result.get("ok"):
            return jsonify(result)  # 문법 오류: /analyze와 같은 모양으로 알려 준다
        comparison = recheck.compare(body["prev_results"], result["results"], body["prev_code"], body["code"])
    except ValueError:
        return jsonify(error="invalid_request"), 400  # 이전 코드를 해석할 수 없다
    except Exception:
        app.logger.error("RECHECK-01")
        return jsonify(error="failed"), 500
    return jsonify({**result, "comparison": comparison, "groups": _fix_groups(body["code"], result)})


if __name__ == "__main__":
    app.run(debug=False)