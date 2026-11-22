from flask import Flask, jsonify, render_template, request

from detector import analyze

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
    return jsonify(result)


def _error(message, status):
    return jsonify(ok=False, error={"line": None, "message": message}), status


if __name__ == "__main__":
    app.run(debug=False)
