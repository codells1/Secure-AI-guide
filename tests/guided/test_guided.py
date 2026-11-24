"""유도질문: 채점표, 질문 문구, /analyze 응답. LLM과 실제 API는 쓰지 않는다.

실행: python -m unittest discover -s tests -t .
"""
import json
import unittest
from pathlib import Path
from unittest import mock

import app as webapp
import guided
from detector import analyze
from detector.result import MESSAGES
from fixer.cards import card_files, rule_ids_of

ROOT = Path(__file__).resolve().parent.parent.parent
YES, NO, SKIP = True, False, None

# 작업 지시 3.2의 채점표 초안 (규칙 → ①~⑤의 정답)
TABLE = {
    ("SQL-1", "SQL-2", "SQL-3"): [YES, SKIP, YES, NO, SKIP],
    # 2번 항목(OS 명령어 삽입)은 팀 채점표에 없어 새로 정한 초안이다. 탐지 모듈의 규칙 뜻에 맞췄다:
    # CMD-1은 검증하지 않은 입력이 명령어에 들어간 것(목록으로 넘겨도 걸린다), CMD-2는 글자를 지운 입력을 shell=True로 실행한 것
    ("CMD-1",): [YES, SKIP, YES, SKIP, SKIP],
    ("CMD-2",): [YES, SKIP, SKIP, NO, SKIP],
    ("UP-1", "UP-2"): [YES, SKIP, SKIP, NO, SKIP],
    ("PATH-1",): [YES, SKIP, YES, NO, SKIP],
    ("IDOR-1", "IDOR-2", "IDOR-3", "IDOR-4"): [YES, SKIP, YES, NO, SKIP],
    ("SSRF-1",): [YES, SKIP, YES, NO, SKIP],
    ("DBG-1",): [YES, YES, SKIP, SKIP, SKIP],
    ("DBG-2",): [YES, SKIP, SKIP, SKIP, SKIP],
    ("ERR-1",): [YES, SKIP, YES, NO, SKIP],
    ("ERR-2",): [YES, SKIP, SKIP, NO, SKIP],
    ("KEY-1", "KEY-2", "KEY-4"): [YES, SKIP, YES, NO, SKIP],
    ("KEY-3",): [YES, SKIP, YES, SKIP, SKIP],
    ("PW-1", "PW-2"): [YES, SKIP, YES, SKIP, SKIP],
    ("PW-3", "PW-4"): [YES, SKIP, NO, NO, SKIP],
    ("PW-5",): [YES, SKIP, SKIP, SKIP, SKIP],
    ("LOGIN-1",): [YES, SKIP, YES, NO, SKIP],
    ("LOGIN-2", "LOGIN-3", "LOGIN-4"): [YES, SKIP, SKIP, SKIP, SKIP],
}

# 작업 지시 2장의 유도질문 v5 가운데 ③번 질문 (따로 적어 둔 것 말고는 문구를 그대로 쓰는지 확인한다)
THIRD_QUESTIONS = {
    "sql_injection": "입력이 DB 명령어에 그대로 이어 붙여지나요?",
    # 2번 항목을 SSTI에서 OS 명령어 삽입으로 바꿨다. 팀 문서에 없던 항목이라 질문 5개는 새로 쓴 초안이다 (2026-11-24)
    "os_command_injection": "사용자가 입력한 글자가 실행할 명령어 안에 그대로 들어가나요?",
    "file_upload": "아주 큰 파일도 크기 제한 없이 올라가나요?",
    "path_traversal": "입력한 이름이 폴더 경로에 그대로 붙여지나요?",
    "idor": "번호만으로 자료를 바로 꺼내 보여주나요?",
    "ssrf": "입력한 주소면 어디든 그대로 접속하나요?",
    "debug_error_exposure": "오류 내용이 화면에 그대로 나오나요?",
    "hardcoded_secret": "코드나 주석에 비밀값이 글자 그대로 적혀 있나요?",
    # 팀 문구("비밀번호를 그대로, 또는 MD5·SHA-1로 저장하나요?")를 학생이 알기 쉽게 풀어 쓴 것이다 (2026-11-24)
    "password_storage": "비밀번호를 입력받은 글자 그대로 저장하거나, 쉽게 풀리는 오래된 방식(MD5, SHA-1)으로 바꿔서 저장하나요?",
    "login_attempt_limit": "몇 번이든 다시 시도할 수 있나요?",
}

IDOR_CODE = '''import sqlite3

from flask import Flask, jsonify
from flask_login import login_required

app = Flask(__name__)


@app.route("/order/<int:order_id>")
def view_order(order_id):
    db = sqlite3.connect("shop.db")
    row = db.execute("SELECT id, user_id, item FROM orders WHERE id = ?", (order_id,)).fetchone()
    return jsonify(item=row[2])


@app.route("/receipt/<int:order_id>")
@login_required
def view_receipt(order_id):
    db = sqlite3.connect("shop.db")
    row = db.execute("SELECT id, user_id, price FROM orders WHERE id = ?", (order_id,)).fetchone()
    return jsonify(price=row[2])
'''


def read(name):
    return json.loads((ROOT / "guided" / name).read_text(encoding="utf-8"))


class AnswerKeyTest(unittest.TestCase):
    def test_every_rule_is_scored_as_the_table_says(self):
        for rule_ids, answers in TABLE.items():
            for rule_id in rule_ids:
                with self.subTest(rule_id):
                    self.assertEqual(guided.expected_answers([rule_id]), answers)

    def test_the_table_covers_every_rule_of_the_detector(self):
        in_table = {rule_id for rule_ids in TABLE for rule_id in rule_ids}
        self.assertEqual(in_table, set(MESSAGES))
        self.assertEqual(set(read("answer_keys.json")["rules"]), set(MESSAGES))

    def test_rules_of_one_item_are_scored_only_where_they_agree(self):
        # DBG-1의 ②는 "예"지만 ERR-1은 채점하지 않는다. ③④는 ERR-1만 채점한다
        self.assertEqual(guided.expected_answers(["DBG-1", "ERR-1"]), [YES, SKIP, SKIP, SKIP, SKIP])
        # PW-1의 ③은 "예", PW-3의 ③은 "아니오"라서 채점하지 않는다
        self.assertEqual(guided.expected_answers(["PW-1", "PW-3"]), [YES, SKIP, SKIP, SKIP, SKIP])
        self.assertEqual(guided.expected_answers(["KEY-1", "KEY-1", "KEY-4"]), [YES, SKIP, YES, NO, SKIP])

    def test_unknown_rules_are_not_scored(self):
        self.assertEqual(guided.expected_answers(["SQL-1", "NEW-9"]), [SKIP] * 5)
        self.assertEqual(guided.expected_answers([]), [SKIP] * 5)

    def test_both_files_are_marked_as_drafts(self):
        self.assertIs(read("answer_keys.json")["_review"], True)
        self.assertIs(read("questions.json")["_review"], True)


class QuestionFileTest(unittest.TestCase):
    def setUp(self):
        self.items = read("questions.json")["items"]

    def test_there_are_five_questions_for_each_checklist_item(self):
        self.assertEqual(sorted(self.items), card_files())
        for vuln_id, questions in self.items.items():
            with self.subTest(vuln_id):
                self.assertEqual(len(questions), 5)
                self.assertEqual(questions[2]["question"], THIRD_QUESTIONS[vuln_id])

    def test_every_scored_question_has_its_own_hint_and_reveal(self):
        keys = read("answer_keys.json")["rules"]
        for vuln_id, questions in self.items.items():
            for rule_id in rule_ids_of(vuln_id):
                for number, answer in enumerate(keys[rule_id], 1):
                    if answer is None:
                        continue
                    with self.subTest(rule_id=rule_id, question=number):
                        item = questions[number - 1]
                        hint, reveal = item["hint"][answer], item["reveal"][answer]
                        self.assertIn("{lines}번째 줄", hint)
                        self.assertNotIn("정답", hint)  # 힌트는 정답을 직접 말하지 않는다
                        self.assertTrue(reveal.startswith(f"정답은 '{answer}'예요."))
                        for text in (hint, reveal):
                            self.assertNotRegex(text, r"\([^)]*\)")  # 괄호 풀이를 쓰지 않는다


class DescribeTest(unittest.TestCase):
    def describe(self, code, user_input=None):
        return guided.describe(code, analyze(code, user_input))

    def test_only_risky_items_get_questions(self):
        code = (ROOT / "static" / "example_app.py").read_text(encoding="utf-8")
        described = self.describe(code)
        self.assertEqual(sorted(described), ["debug_error_exposure", "hardcoded_secret", "sql_injection"])
        for questions in described.values():
            self.assertEqual([sorted(item) for item in questions], [["answer", "hint", "question", "reveal"]] * 5)
        self.assertEqual([item["answer"] for item in described["sql_injection"]], [YES, SKIP, YES, NO, SKIP])
        self.assertEqual([item["answer"] for item in described["debug_error_exposure"]], [YES, YES, SKIP, SKIP, SKIP])
        self.assertEqual(self.describe("x = 1\n"), {})

    def test_line_numbers_are_filled_in(self):
        described = self.describe(IDOR_CODE, {"idor": {"public_functions": []}})
        questions = described["idor"]
        self.assertEqual([item["answer"] for item in questions], [YES, SKIP, YES, NO, SKIP])  # IDOR-1과 IDOR-2
        self.assertTrue(questions[3]["hint"].startswith("12, 20번째 줄을 보세요."))
        self.assertEqual((questions[1]["hint"], questions[1]["reveal"]), ("", ""))  # 채점하지 않는 질문
        for item in questions:  # 채우지 못한 자리가 남지 않는다
            self.assertNotRegex(item["hint"] + item["reveal"], r"\{\w+\}")

    def test_a_question_before_the_verdict_gets_no_questions_yet(self):
        self.assertEqual(self.describe(IDOR_CODE), {})  # 라우트 질문에 답하기 전에는 판정이 없다

    def test_lines_are_written_as_ranges(self):
        self.assertEqual(guided.format_lines([21, 19, 20, 25, 25]), "19–21, 25")
        self.assertEqual(guided.format_lines([]), "")
        findings = [{"line": 62, "path": [60, 21, 62]}, {"line": 63, "path": [63]}]
        self.assertEqual(guided.detected_lines(findings), [21, 60, 62, 63])

    def test_text_without_its_own_wording_falls_back_to_the_general_one(self):
        questions = {"fallback": {"hint": "{lines}번째 줄을 다시 살펴보세요.", "reveal": "정답은 '{answer}'예요."},
                     "items": {"idor": [{"question": f"질문 {number}"} for number in range(1, 6)]}}
        with mock.patch.object(guided, "_questions", return_value=questions):
            third = self.describe(IDOR_CODE, {"idor": {"public_functions": []}})["idor"][2]
        self.assertEqual(third, {"question": "질문 3", "answer": YES,
                                 "hint": "12, 20번째 줄을 다시 살펴보세요.", "reveal": "정답은 '예'예요."})

    def test_function_names_can_be_used_in_the_text(self):
        questions = {"fallback": {"hint": "{func} 함수를 보세요.", "reveal": "정답은 '{answer}'예요."},
                     "items": {"idor": [{"question": f"질문 {number}"} for number in range(1, 6)]}}
        with mock.patch.object(guided, "_questions", return_value=questions):
            first = self.describe(IDOR_CODE, {"idor": {"public_functions": []}})["idor"][0]
        self.assertEqual(first["hint"], "view_order, view_receipt 함수를 보세요.")


class AnalyzeEndpointTest(unittest.TestCase):
    def setUp(self):
        self.client = webapp.app.test_client()
        self.code = (ROOT / "static" / "example_app.py").read_text(encoding="utf-8")

    def test_analysis_comes_with_the_questions(self):
        body = self.client.post("/analyze", json={"code": self.code}).get_json()
        self.assertEqual(sorted(body["guided"]), ["debug_error_exposure", "hardcoded_secret", "sql_injection"])
        self.assertEqual(body["guided"]["sql_injection"][2]["question"], THIRD_QUESTIONS["sql_injection"])

    def test_detection_result_survives_a_failure_in_the_questions(self):
        with mock.patch.object(guided, "describe", side_effect=RuntimeError("boom")):
            body = self.client.post("/analyze", json={"code": self.code}).get_json()
        self.assertEqual((body["ok"], len(body["results"]), body["guided"]), (True, 10, {}))


if __name__ == "__main__":
    unittest.main()
