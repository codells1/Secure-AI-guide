"""6단계: API 호출과 서비스 흐름 (fix_spec 6장, 7장). 가짜 클라이언트만 쓴다 (실제 API 호출 없음).

실행: python -m unittest discover -s tests -t .
"""
import json
import os
import unittest
from types import SimpleNamespace
from unittest import mock

import anthropic

from detector import analyze
from detector.result import MESSAGES
from fixer import llm_client, service
from fixer.cards import load_card
from fixer.grouping import make_groups
from fixer.masking import MaskingError

CODE = '''import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = "example-key-0000"


@app.route("/search")
def search():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT name FROM students WHERE name = '{name}'").fetchall()
    return jsonify(rows)
'''
HEAD = '@app.route("/search")\ndef search():\n    name = request.args.get("name", "")\n    conn = sqlite3.connect("app.db")\n'
GOOD = HEAD + '    rows = conn.execute("SELECT name FROM students WHERE name = ?", (name,)).fetchall()\n    return jsonify(rows)'
STILL_BAD = HEAD + '''    rows = conn.execute("SELECT name FROM students WHERE name = '%s'" % name).fetchall()\n    return jsonify(rows)'''
INSTRUCTION = "search 함수의 execute()에서 name을 ? 자리로 넘겨줘."
USAGE = {"input_tokens": 900, "output_tokens": 300, "cache_creation_input_tokens": 600, "cache_read_input_tokens": 0}


def reply(fixed_code=GOOD, stop_reason="end_turn", text=None, usage=USAGE, **overrides):
    data = {
        "problem": "search 함수가 name을 SQL 문장에 그대로 넣어요.",
        "impact": "다른 학생의 정보가 보일 수 있어요.",
        "how_to_fix": "name을 ? 자리로 따로 넘기면 돼요.",
        "fixed_code": fixed_code,
        "added_top_level": [],
        "fix_instruction": INSTRUCTION,
        **overrides,
    }
    return SimpleNamespace(
        stop_reason=stop_reason,
        # 생각(thinking) 블록이 글 블록보다 앞에 올 수 있다.
        content=[SimpleNamespace(type="thinking", thinking=""),
                 SimpleNamespace(type="text", text=json.dumps(data, ensure_ascii=False) if text is None else text)],
        usage=SimpleNamespace(**usage),
    )


def api_error(kind, status_code=None):
    error = kind.__new__(kind)  # SDK 예외는 요청 객체가 있어야 만들 수 있어서 틀만 만든다
    if status_code is not None:
        error.status_code = status_code
    return error


class FakeClient:
    """messages.create()가 미리 정해 둔 응답을 차례로 돌려준다. 받은 요청은 모두 기록한다."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **request):
        self.requests.append(request)
        item = self.replies.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def group_of(code, vuln_id, user_input=None):
    return next(group for group in make_groups(analyze(code, user_input), code) if group.vuln_id == vuln_id)


def run(client, code=CODE, vuln_id="sql_injection", user_input=None):
    return service.run_group(code, "app.py", group_of(code, vuln_id, user_input), user_input, client)


def blocks(request):
    return request["messages"][0]["content"]


class ServiceFlowTest(unittest.TestCase):
    def assert_has_diff_and_prompt(self, result):
        """작업 지시 절대 규칙 9: ②와 ③은 항상 함께 있다."""
        self.assertTrue(result["diff"]["before"].strip())
        self.assertIn("after", result["diff"])
        self.assertIn("다음 조건대로 고쳐줘.", result["prompt"])
        self.assertIn("[지금 코드]", result["prompt"])

    def test_first_attempt_passes(self):
        client = FakeClient(reply())
        result, attempts = run(client)
        self.assertEqual(len(client.requests), 1)
        self.assertEqual(attempts, [{"passed": True, "failed": [], "usage": USAGE}])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["group_id"], "sql_injection:8-13")
        self.assertEqual(result["rule_ids"], ["SQL-1"])
        self.assertEqual(result["messages"], [MESSAGES["SQL-1"]])
        self.assertEqual(result["explanation"]["problem"], "search 함수가 name을 SQL 문장에 그대로 넣어요.")
        self.assertEqual(result["explanations"], [result["explanation"]])
        self.assertEqual(result["diff"], {
            "before": "\n".join(CODE.split("\n")[7:13]),
            "after": GOOD,
            "added_top_level": [],
            "is_general_example": False,
        })
        self.assertEqual(result["target_code"], result["diff"]["before"])
        self.assertIn("\n   " + INSTRUCTION + "\n2. ", result["prompt"])
        (reference,) = result["references"]
        self.assertEqual((reference["rule_id"], reference["source"], reference["pages"]), ("SQL-1", "KISA 「SQL 삽입」", "9~11"))
        self.assertTrue(reference["excerpt"] and reference["excerpt_source"] and reference["easy"])  # 근거 문장과 쉬운 풀이
        self.assertNotIn(reference["excerpt"], json.dumps(client.requests, ensure_ascii=False))  # 원문은 모델에 넣지 않는다
        self.assertEqual([item["question"] for item in result["concepts"]], ["'SQL 문장'이 뭐예요?"])  # 카드의 고정 문장
        self.assertEqual(result["usage"], {**USAGE, "calls": 1})
        self.assert_has_diff_and_prompt(result)
        json.dumps(result)  # 프론트엔드로 보낼 수 있는 값만 들어 있다

    def test_retry_then_pass(self):
        client = FakeClient(reply(STILL_BAD), reply())
        result, attempts = run(client)
        self.assertEqual([(a["passed"], a["failed"]) for a in attempts], [(False, ["V2"]), (True, [])])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["diff"]["after"], GOOD)
        self.assertEqual(result["usage"]["calls"], 2)
        self.assertEqual(result["usage"]["input_tokens"], 1800)
        first, second = client.requests
        self.assertNotIn("<retry>", blocks(first)[1]["text"])
        retry = blocks(second)[1]["text"]
        self.assertIn("<retry>앞선 수정은 다음 검증을 통과하지 못했다.\n- V2: 고친 범위 안에 같은 취약점이 남아 있다.", retry)
        self.assertIn("- SQL-1: " + MESSAGES["SQL-1"], retry)
        self.assertTrue(retry.endswith("다시 고친다.</retry>"))
        self.assertEqual(blocks(first)[0], blocks(second)[0])  # 학생 코드 블록은 그대로다 (캐시에서 읽는다)

    def test_two_failures_fall_back_to_the_general_example(self):
        client = FakeClient(reply(STILL_BAD), reply(STILL_BAD))
        result, attempts = run(client)
        card = load_card("sql_injection", ["SQL-1"])
        self.assertEqual(len(client.requests), 2)
        self.assertEqual([a["passed"] for a in attempts], [False, False])
        self.assertEqual(result["status"], "fallback")
        self.assertEqual(result["diff"], {**card.examples[0], "added_top_level": [], "is_general_example": True})
        self.assertEqual(result["explanation"]["problem"], card.fallback_explanations[0]["problem"])
        self.assertNotIn(INSTRUCTION, result["prompt"])
        self.assertIn("1. 다음 방식으로 고칠 것: " + card.allowed_fixes[0] + "\n2. ", result["prompt"])
        self.assertIn("def search():", result["prompt"])  # 프롬프트에는 그래도 학생의 (가린) 코드가 들어간다
        self.assert_has_diff_and_prompt(result)

    def test_abnormal_responses_are_retried_then_fall_back(self):
        incomplete = json.dumps({"problem": "p", "impact": "i", "how_to_fix": "h"})
        failures = {
            "refusal": reply(stop_reason="refusal", text=""),
            "max_tokens": reply(stop_reason="max_tokens", text='{"problem": "잘린'),
            "bad_json": reply(text="JSON이 아님"),
            "bad_json (빠진 항목)": reply(text=incomplete),
            "bad_json (빈 설명)": reply(problem="  "),
            "timeout": api_error(anthropic.APITimeoutError),
            "connection_error": api_error(anthropic.APIConnectionError),
            "api_error_429": api_error(anthropic.RateLimitError, 429),
            "api_error_500": api_error(anthropic.APIStatusError, 500),
        }
        for label, failure in failures.items():
            reason = label.split(" ")[0]
            with self.subTest(label, then="통과"):
                client = FakeClient(failure, reply())
                result, attempts = run(client)
                self.assertEqual((attempts[0]["passed"], attempts[0]["failed"]), (False, [reason]))
                self.assertEqual(result["status"], "ok")
                self.assert_has_diff_and_prompt(result)
            with self.subTest(label, then="대체 예시"):
                client = FakeClient(failure, failure)
                result, attempts = run(client)
                self.assertEqual(len(client.requests), 2)
                self.assertEqual(result["status"], "fallback")
                self.assertTrue(result["diff"]["is_general_example"])
                self.assert_has_diff_and_prompt(result)

    def test_retry_note_for_abnormal_responses(self):
        client = FakeClient(reply(stop_reason="max_tokens", text="{"), reply())
        run(client)
        self.assertIn("<retry>앞선 응답이 너무 길어서 중간에 잘렸다.", blocks(client.requests[1])[1]["text"])
        client = FakeClient(api_error(anthropic.APITimeoutError), reply())
        run(client)
        self.assertEqual(client.requests[0]["messages"], client.requests[1]["messages"])  # 같은 요청을 다시 보낸다

    def test_v1_and_v3_are_reported_to_the_model(self):
        broken = HEAD + "    rows = conn.execute(\n    return jsonify(rows)"
        leaking = (HEAD.replace('    conn = sqlite3', '    try:\n        conn = sqlite3')
                   + '        rows = conn.execute("SELECT name FROM students WHERE name = ?", (name,)).fetchall()\n'
                   + "    except Exception as e:\n        return str(e), 500\n    return jsonify(rows)")
        client = FakeClient(reply(broken), reply(leaking))
        result, attempts = run(client)
        self.assertEqual([a["failed"] for a in attempts], [["V1"], ["V3"]])
        self.assertEqual(result["status"], "fallback")
        self.assertRegex(blocks(client.requests[1])[1]["text"], r"- V1: 고친 코드를 끼워 넣으면 문법 오류가 난다\. \(fixed_code의 \d번째 줄 근처\)")

    def test_secret_values_never_leave_and_never_show(self):
        client = FakeClient(reply())
        result, _ = run(client)
        sent = json.dumps(client.requests, ensure_ascii=False)
        self.assertNotIn("example-key-0000", sent)
        self.assertIn('5: app.config[\\"SECRET_KEY\\"] = \\"***\\"', sent)
        self.assertNotIn("example-key-0000", json.dumps(result, ensure_ascii=False))

        client = FakeClient(reply('app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]', added_top_level=["import os", "import sqlite3"]))
        result, _ = run(client, vuln_id="hardcoded_secret")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["diff"]["before"], 'app.config["SECRET_KEY"] = "***"')
        self.assertEqual(result["diff"]["added_top_level"], ["import os"])  # 이미 있는 import는 보여 주지 않는다
        self.assertIn('app.config["SECRET_KEY"] = "***"\n```', result["prompt"])
        self.assertIn("app.py 파일 5번째 줄에", result["prompt"])

    def test_masking_failure_sends_nothing_and_shows_no_student_code(self):
        client = FakeClient(reply())
        with mock.patch.object(service, "mask", side_effect=MaskingError("가리지 못했습니다.")):
            result, attempts = run(client)
        self.assertEqual((client.requests, attempts), ([], []))
        self.assertEqual(result["status"], "fallback")
        self.assertEqual(result["target_code"], "")
        self.assertEqual(result["usage"]["calls"], 0)
        shown = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("SELECT name FROM students", shown)  # 학생 코드에만 있는 줄
        self.assertNotIn("SECRET_KEY", shown)
        self.assertIn(service.CODE_NOT_SHOWN, result["prompt"])
        self.assert_has_diff_and_prompt(result)

    def test_group_with_two_rules(self):
        card = load_card("file_upload", ["UP-1", "UP-2"])
        code = card.examples[0]["after"].replace(
            '    ext = file.filename.rsplit(".", 1)[-1].lower()\n    if ext not in ALLOWED_EXTENSIONS:\n        abort(400)\n'
            '    if file.mimetype not in ALLOWED_TYPES:\n        abort(400)\n', "")
        group = group_of(code, "file_upload")
        self.assertEqual(group.rule_ids, ("UP-1", "UP-2"))
        unchanged = "\n".join(code.split("\n")[group.target_range[0] - 1:group.target_range[1]])
        client = FakeClient(reply(unchanged), reply(unchanged))  # 고치지 않은 응답: 두 규칙이 그대로 남는다
        failing = service.run_group(code, "app.py", group, None, client)[0]
        detail = blocks(client.requests[0])[1]["text"]
        self.assertEqual(detail.count("<finding>"), 2)  # 묶음의 finding마다 한 줄
        self.assertEqual(detail.count("<example>"), 2)
        self.assertEqual(len(client.requests), 2)  # 묶음 하나에 호출은 시도당 1회
        self.assertEqual(failing["status"], "fallback")
        self.assertEqual([item["rule_id"] for item in failing["explanations"]], ["UP-1", "UP-2"])  # 규칙마다 설명
        self.assertEqual(failing["messages"], [MESSAGES["UP-1"], MESSAGES["UP-2"]])

    def test_student_answers_are_used_for_verification(self):
        card = load_card("idor", ["IDOR-1"])
        before, after = card.examples[0]["before"], card.examples[0]["after"]
        answers = {"idor": {"public_functions": []}}
        group = group_of(before, "idor", answers)
        fixed = "\n".join(after.split("\n")[group.target_range[0] - 1:])
        result = service.fix_group(before, "app.py", group, answers, FakeClient(reply(fixed)))
        self.assertEqual(result["status"], "ok")

    def test_removed_comment_is_an_empty_after(self):
        code = CODE.replace("app = Flask(__name__)\n", "app = Flask(__name__)\n# password: example-pass-0000\n")
        group = next(g for g in make_groups(analyze(code), code) if g.rule_ids == ("KEY-4",))
        result = service.fix_group(code, "app.py", group, None, FakeClient(reply("")))
        self.assertEqual((result["status"], result["diff"]["before"], result["diff"]["after"]), ("ok", "# (가린 주석)", ""))

    def test_code_with_a_syntax_error_is_rejected(self):
        group = group_of(CODE, "sql_injection")
        with self.assertRaises(ValueError):
            service.fix_group("def broken(:\n", "app.py", group, None, FakeClient())


class RequestShapeTest(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient(reply())
        with mock.patch.dict(os.environ):
            os.environ.pop("FIX_MODEL", None)
            run(self.client)
        (self.request,) = self.client.requests

    def test_settings(self):
        self.assertEqual(self.request["model"], "claude-opus-5-5")
        self.assertEqual(self.request["max_tokens"], 4000)
        self.assertEqual(self.request["system"], llm_client.SYSTEM_PROMPT)
        self.assertEqual(self.request["output_config"], {"format": {"type": "json_schema", "schema": llm_client.SCHEMA}})
        self.assertEqual(self.request["timeout"], 60.0)
        self.assertEqual(sorted(self.request), ["max_tokens", "messages", "model", "output_config", "system", "timeout"])

    def test_model_can_be_changed_with_the_environment(self):
        client = FakeClient(reply())
        with mock.patch.dict(os.environ, {"FIX_MODEL": "claude-sonnet-5-5"}):
            run(client)
        self.assertEqual(client.requests[0]["model"], "claude-sonnet-5-5")

    def test_message_blocks_are_in_fixed_order_with_the_code_cached(self):
        (message,) = self.request["messages"]
        self.assertEqual(message["role"], "user")
        code_block, detail_block = message["content"]
        self.assertEqual(code_block["cache_control"], {"type": "ephemeral"})
        self.assertNotIn("cache_control", detail_block)
        self.assertTrue(code_block["text"].startswith("<student_code>\n1: import sqlite3\n2: from flask"))
        self.assertTrue(code_block["text"].endswith("\n13:     return jsonify(rows)\n</student_code>"))
        detail = detail_block["text"]
        self.assertTrue(detail.startswith(f"<finding>규칙: SQL-1 / 12번째 줄 / {MESSAGES['SQL-1']}</finding>\n"
                                          "<target_range>8~13번째 줄</target_range>\n<key_sentence>"))
        order = [detail.index(tag) for tag in ("<finding>", "<target_range>", "<key_sentence>", "<allowed_fixes>",
                                               "<forbidden_fixes>", "<example><before>", "</before><after>")]
        self.assertEqual(order, sorted(order))

    def test_system_prompt_and_schema_follow_the_spec(self):
        prompt = llm_client.SYSTEM_PROMPT
        self.assertTrue(prompt.startswith("너는 중·고등학생이 만든 Flask 코드의 보안 수정 예시와 쉬운 설명을 만든다.\n"))
        self.assertIn("- 취약점이 있는지 없는지는 판단하지 않는다. <finding>은 이미 확인된 결과다.\n", prompt)
        self.assertIn('- "***"와 "(가린 주석)"은 가려 둔 값이다. 원래 값을 추측하거나 채워 넣지 않는다.\n', prompt)
        # 설명 작성 규칙은 feedback_ui_task 4장: 괄호 풀이 없이 1~2문장, impact 첫 문장은 가장 큰 피해
        self.assertIn("- problem, impact, how_to_fix는 각각 1~2문장으로, 중학생이 이해할 수 있는 한국어 해요체로 쓴다.\n", prompt)
        self.assertIn("- 전문 용어는 괄호로 풀이하지 않는다. 처음부터 쉬운 말로 바꿔 쓴다.\n", prompt)
        self.assertIn("- impact: 첫 문장에 가장 큰 피해를 쓴다 (화면에서 첫 문장을 굵게 보여준다).\n", prompt)
        self.assertNotIn("같은 문장 안에서 쉬운 말로 풀어 쓴다", prompt)
        self.assertEqual(len(prompt.split("\n")), 18)
        self.assertEqual(llm_client.SCHEMA["required"],
                         ["problem", "impact", "how_to_fix", "fixed_code", "added_top_level", "fix_instruction"])
        self.assertIs(llm_client.SCHEMA["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
