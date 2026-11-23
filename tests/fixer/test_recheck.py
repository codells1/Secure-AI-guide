"""8단계: 재점검 비교 (fix_spec 9장). 실제 API 호출 없음.

실행: python -m unittest discover -s tests -t .
"""
import unittest
from unittest import mock

import app as webapp
from detector import analyze
from fixer import llm_client
from fixer.cards import load_card
from fixer.recheck import NEW, RESOLVED, STILL, compare, valid_results
from tests.fixer.test_service_fake_llm import CODE, FakeClient

BAD_LINE = '''    rows = conn.execute(f"SELECT name FROM students WHERE name = '{name}'").fetchall()\n'''
GOOD_LINE = '    rows = conn.execute("SELECT name FROM students WHERE name = ?", (name,)).fetchall()\n'
FIXED = CODE.replace(BAD_LINE, GOOD_LINE)
DEBUG_TAIL = '\n\nif __name__ == "__main__":\n    app.run(debug=True)\n'
TWO_QUERIES = CODE.replace(BAD_LINE, BAD_LINE + BAD_LINE.replace("rows =", "more ="))


def results(code, user_input=None):
    return analyze(code, user_input)["results"]


def compared(before, after):
    return [(item["rule_id"], item["function_name"], item["status"], item["line"])
            for item in compare(results(before), results(after), before, after)]


class CompareTest(unittest.TestCase):
    def test_unchanged_code_is_still_risky(self):
        self.assertEqual(compared(CODE, CODE), [("SQL-1", "search", STILL, 12), ("KEY-1", "<module>", STILL, 5)])

    def test_fixed_finding_is_resolved(self):
        self.assertEqual(compared(CODE, FIXED), [("SQL-1", "search", RESOLVED, None), ("KEY-1", "<module>", STILL, 5)])

    def test_lines_added_above_do_not_change_the_result(self):
        moved = "# 메모 한 줄\n# 메모 두 줄\n" + CODE
        self.assertEqual(compared(CODE, moved), [("SQL-1", "search", STILL, 14), ("KEY-1", "<module>", STILL, 7)])

    def test_new_vulnerability_is_new(self):
        self.assertEqual(compared(CODE, CODE + DEBUG_TAIL), [
            ("SQL-1", "search", STILL, 12), ("DBG-1", "<module>", NEW, 17), ("KEY-1", "<module>", STILL, 5)])
        self.assertEqual(compared(FIXED, CODE), [("SQL-1", "search", NEW, 12), ("KEY-1", "<module>", STILL, 5)])

    def test_same_key_is_compared_by_count(self):
        self.assertEqual(compared(TWO_QUERIES, CODE)[:2], [("SQL-1", "search", STILL, 12), ("SQL-1", "search", RESOLVED, None)])
        self.assertEqual(compared(CODE, TWO_QUERIES)[:2], [("SQL-1", "search", STILL, 12), ("SQL-1", "search", NEW, 13)])

    def test_renamed_function_shows_as_resolved_and_new(self):
        renamed = CODE.replace("def search():", "def find():")
        self.assertEqual(compared(CODE, renamed)[:2], [("SQL-1", "find", NEW, 12), ("SQL-1", "search", RESOLVED, None)])

    def test_items_carry_the_detector_message(self):
        item = compare(results(CODE), results(FIXED), CODE, FIXED)[0]
        self.assertEqual(sorted(item), ["function_name", "line", "message", "rule_id", "status", "vuln_id"])
        self.assertTrue(item["message"].startswith("사용자가 입력한 값이 SQL 문장 안에"))

    def test_previous_results_must_look_like_detector_results(self):
        self.assertTrue(valid_results(results(CODE)))
        self.assertTrue(valid_results([]))
        for bad in (None, "x", [1], [{"vuln_id": "a"}], [{"vuln_id": "a", "findings": [{"rule_id": "SQL-1", "line": "3"}]}]):
            self.assertFalse(valid_results(bad), bad)
        with self.assertRaises(ValueError):
            compare(results(CODE), results(CODE), "def broken(:\n", CODE)


class RecheckEndpointTest(unittest.TestCase):
    def setUp(self):
        self.client = webapp.app.test_client()
        self.fake = FakeClient()
        webapp.app.config["FIX_CLIENT"] = self.fake
        self.addCleanup(webapp.app.config.pop, "FIX_CLIENT", None)
        patcher = mock.patch.object(llm_client, "default_client", side_effect=AssertionError("실제 API 호출 금지"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def recheck(self, code, before=CODE, **changes):
        answers = changes.get("user_input") if isinstance(changes.get("user_input"), dict) else {}
        first = self.client.post("/analyze", json={"code": before, "user_input": answers}).get_json()
        body = {"code": code, "prev_results": first["results"], "prev_code": before, "user_input": {}, **changes}
        return first, self.client.post("/api/recheck", json=body)

    def test_returns_results_comparison_and_groups_without_calling_the_api(self):
        _, response = self.recheck(FIXED)
        body = response.get_json()
        self.assertEqual((response.status_code, list(body)), (200, ["ok", "results", "comparison", "groups"]))
        self.assertEqual([(item["rule_id"], item["status"]) for item in body["comparison"]], [("SQL-1", RESOLVED), ("KEY-1", STILL)])
        self.assertEqual([group["group_id"] for group in body["groups"]], ["hardcoded_secret:5-5"])
        self.assertEqual(self.fake.requests, [])

    def test_unchanged_group_keeps_the_same_code_even_when_lines_move(self):
        first, response = self.recheck("# 메모\n\n" + CODE)
        moved = response.get_json()
        self.assertEqual({item["status"] for item in moved["comparison"]}, {STILL})
        content = lambda groups: [(g["vuln_id"], g["rule_ids"], g["target_code"]) for g in groups]  # noqa: E731
        self.assertEqual(content(moved["groups"]), content(first["groups"]))  # 브라우저는 이 내용이 같으면 다시 요청하지 않는다
        self.assertNotEqual([g["group_id"] for g in moved["groups"]], [g["group_id"] for g in first["groups"]])

    def test_partly_changed_function_has_different_code(self):
        first, response = self.recheck(CODE.replace('    return jsonify(rows)', '    print(len(rows))\n    return jsonify(rows)'))
        changed = response.get_json()
        self.assertEqual([item["status"] for item in changed["comparison"]], [STILL, STILL])
        sql_before = next(g for g in first["groups"] if g["vuln_id"] == "sql_injection")
        sql_after = next(g for g in changed["groups"] if g["vuln_id"] == "sql_injection")
        self.assertNotEqual(sql_after["target_code"], sql_before["target_code"])  # 이 묶음은 새로 요청하게 된다

    def test_syntax_error_and_bad_requests(self):
        _, broken = self.recheck("def broken(:\n")
        self.assertEqual((broken.status_code, broken.get_json()["ok"], broken.get_json()["error"]["line"]), (200, False, 1))
        for label, changes in {
            "이전 코드 없음": {"prev_code": None},
            "이전 결과 모양이 다름": {"prev_results": [{"vuln_id": 1}]},
            "이전 코드를 해석할 수 없음": {"prev_code": "def broken(:\n"},
            "user_input이 dict가 아님": {"user_input": "x"},
        }.items():
            with self.subTest(label):
                _, response = self.recheck(CODE, **changes)
                self.assertEqual((response.status_code, response.get_json()), (400, {"error": "invalid_request"}))
        self.assertEqual(self.client.post("/api/recheck", json={}).status_code, 400)

    def test_student_answers_are_kept_so_questions_are_not_asked_again(self):
        idor = load_card("idor", ["IDOR-1"]).examples[0]["before"]
        answers = {"idor": {"public_functions": []}}
        _, response = self.recheck("# 메모\n" + idor, before=idor, user_input=answers)
        body = response.get_json()
        answer = next(item for item in body["results"] if item["vuln_id"] == "idor")
        self.assertEqual((answer["verdict"], answer["needs_user_input"]), ("위험", None))  # 다시 묻지 않는다
        self.assertEqual([(item["rule_id"], item["status"]) for item in body["comparison"]], [("IDOR-1", STILL)])


if __name__ == "__main__":
    unittest.main()
