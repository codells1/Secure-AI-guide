import anthropic
from dotenv import load_dotenv
from flask import Flask, current_app, jsonify, render_template, request

from fixer.service import RuleNotReady, generate_fix, load_rule

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
# 탐지 모듈(analyze) 기반 V1~V3 검증 함수를 연결할 자리.
# None이면 검증되지 않은 코드가 나가지 않도록 /api/fix는 API를 호출하지 않고 503을 돌려준다.
app.config["FIX_VERIFIER"] = None


def _valid_finding(finding):
    return (
        isinstance(finding, dict)
        and all(isinstance(finding.get(k), str) for k in ("vuln_id", "rule_id", "message"))
        and type(finding.get("line")) is int
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/fix", methods=["POST"])
def api_fix():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("code"), str) \
            or not _valid_finding(body.get("finding")):
        return jsonify(error="invalid_request"), 400

    verifier = current_app.config["FIX_VERIFIER"]
    if verifier is None:
        return jsonify(error="detector_not_connected"), 503
    try:
        load_rule(body["finding"]["vuln_id"], body["finding"]["rule_id"])
        client = current_app.config.get("FIX_CLIENT") or anthropic.Anthropic()
        return jsonify(generate_fix(client, verifier, body["code"], body["finding"],
                                    body.get("user_input")))
    except RuleNotReady:
        return jsonify(error="rule_not_ready"), 503
    except ValueError:
        return jsonify(error="invalid_code"), 400


if __name__ == "__main__":
    app.run(debug=True)
