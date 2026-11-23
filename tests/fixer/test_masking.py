"""2단계: 민감정보 가리기 (fix_spec 4장). 비밀값은 모두 가짜 값이다.

실행: python -m unittest discover -s tests -t .
"""
import ast
import unittest

from detector import analyze
from fixer.masking import MASK_COMMENT, MaskingError, mask

HEADER = '''import os
import pymysql
from flask import Flask

app = Flask(__name__)
'''
# 머리말 뒤에 붙인 첫 줄의 위치: 목록에서는 FIRST번째 칸, 줄 번호로는 FIRST + 1번째 줄
FIRST = HEADER.count("\n")


def secret_findings(code):
    for result in analyze(code)["results"]:
        if result["vuln_id"] == "hardcoded_secret":
            return [(finding["rule_id"], finding["line"]) for finding in result["findings"]]
    raise AssertionError("hardcoded_secret 결과가 없다")


def verdicts(code):
    return {result["vuln_id"]: result["verdict"] for result in analyze(code)["results"]}


class MaskingTest(unittest.TestCase):
    def masked(self, code, expected_rules):
        """가린 코드를 돌려준다. 그 전에 모든 케이스에 공통인 조건을 확인한다."""
        before = secret_findings(code)
        self.assertEqual(sorted({rule for rule, _ in before}), sorted(expected_rules))
        result = mask(code, analyze(code))
        ast.parse(result)  # 가린 뒤 파싱 성공
        self.assertEqual(result.count("\n"), code.count("\n"))  # 줄 수 그대로
        # 가린 코드에서 KEY-1~3은 같은 줄에서 탐지되고 KEY-4는 사라진다
        self.assertEqual(secret_findings(result), [item for item in before if item[0] != "KEY-4"])
        return result

    def assert_only_lines_changed(self, code, result, changed):
        pairs = zip(code.split("\n"), result.split("\n"))
        different = [number for number, (old, new) in enumerate(pairs, 1) if old != new]
        self.assertEqual(different, changed)

    def test_key1_keeps_key_name(self):
        code = HEADER + 'app.config["SECRET_KEY"] = "abc123secret"\napp.secret_key = "dev-key-0000"\n'
        result = self.masked(code, ["KEY-1"])
        self.assertIn('app.config["SECRET_KEY"] = "***"', result)
        self.assertIn('app.secret_key = "***"', result)
        self.assertNotIn("abc123secret", result)
        self.assertNotIn("dev-key-0000", result)

    def test_key2_variable_keyword_and_dict_value(self):
        code = HEADER + (
            'DB_PASSWORD = "p@ss-0000"\n'
            'conn = pymysql.connect(host="localhost", user="root", password="abc12345")\n'
            'settings = {"api_key": "sk-test-0000", "name": "demo"}\n'
        )
        result = self.masked(code, ["KEY-2"])
        self.assertIn('DB_PASSWORD = "***"', result)
        self.assertIn('pymysql.connect(host="localhost", user="root", password="***")', result)
        self.assertIn('{"api_key": "***", "name": "demo"}', result)
        for secret in ("p@ss-0000", "abc12345", "sk-test-0000"):
            self.assertNotIn(secret, result)

    def test_key3_masks_only_the_default(self):
        code = HEADER + (
            'DB_PASSWORD = os.getenv("DB_PASSWORD", "fallback-0000")\n'  # 값이 들어가는 이름으로 걸린다
            'value = os.environ.get("API_TOKEN", "tok-0000")\n'  # 환경변수 이름으로 걸린다
        )
        result = self.masked(code, ["KEY-3"])
        self.assertIn('DB_PASSWORD = os.getenv("DB_PASSWORD", "***")', result)
        self.assertIn('value = os.environ.get("API_TOKEN", "***")', result)
        self.assertNotIn("fallback-0000", result)
        self.assertNotIn("tok-0000", result)

    def test_key4_comment_line_and_trailing_comment(self):
        code = HEADER + (
            "# 관리자 비밀번호: admin1234\n"
            'retries = 3  # password = "abc-0000"\n'
            "# 그냥 설명하는 주석\n"
        )
        result = self.masked(code, ["KEY-4"])
        lines = result.split("\n")
        self.assertEqual(lines[FIRST], MASK_COMMENT)
        self.assertEqual(lines[FIRST + 1], "retries = 3  " + MASK_COMMENT)
        self.assertEqual(lines[FIRST + 2], "# 그냥 설명하는 주석")
        self.assertNotIn("admin1234", result)
        self.assertNotIn("abc-0000", result)

    def test_korean_before_the_value_uses_byte_offsets(self):
        code = HEADER + (
            'settings = {"이름": "홍길동", "password": "비밀번호1234"}  # 한글 설명\n'
            '안내 = "가나다"; DB_PASSWORD = "한글pw0000"\n'
        )
        result = self.masked(code, ["KEY-2"])
        lines = result.split("\n")
        self.assertEqual(lines[FIRST], 'settings = {"이름": "홍길동", "password": "***"}  # 한글 설명')
        self.assertEqual(lines[FIRST + 1], '안내 = "가나다"; DB_PASSWORD = "***"')

    def test_multi_line_call_changes_only_the_value_line(self):
        code = HEADER + (
            "conn = pymysql.connect(\n"
            '    host="localhost",\n'
            '    password="abc12345",\n'
            ")\n"
        )
        result = self.masked(code, ["KEY-2"])
        self.assert_only_lines_changed(code, result, [FIRST + 3])  # 세 번째로 붙인 줄
        self.assertEqual(result.split("\n")[FIRST + 2], '    password="***",')

    def test_value_on_the_next_line(self):
        code = HEADER + 'app.config["SECRET_KEY"] = (\n    "abc123secret"\n)\n'
        result = self.masked(code, ["KEY-1"])
        self.assert_only_lines_changed(code, result, [FIRST + 2])  # 값이 있는 두 번째 줄
        self.assertEqual(result.split("\n")[FIRST + 1], '    "***"')

    def test_value_spanning_lines_keeps_line_numbers(self):
        code = HEADER + (
            "API_TOKEN = (\n"
            '    "tok-part-one"\n'
            '    "tok-part-two"\n'
            ")\n"
            'NOTE_PASSWORD = """first-0000\nsecond-0000"""\n'
            'after = "unchanged"\n'
        )
        result = self.masked(code, ["KEY-2"])
        for secret in ("tok-part-one", "tok-part-two", "first-0000", "second-0000"):
            self.assertNotIn(secret, result)
        self.assertEqual(result.split("\n")[FIRST + 6], 'after = "unchanged"')

    def test_joined_values_and_fstring(self):
        code = HEADER + (
            'PART = "0000"\n'
            'API_KEY = "sk-" + "test-1111"\n'
            'SECRET_TOKEN = f"tok-{PART}"\n'
        )
        result = self.masked(code, ["KEY-2"])
        lines = result.split("\n")
        self.assertEqual(lines[FIRST], 'PART = "***"')  # f-string이 쓰는 이름도 대입된 곳에서 가린다
        self.assertEqual(lines[FIRST + 1], 'API_KEY = "***" + "***"')
        self.assertEqual(lines[FIRST + 2], 'SECRET_TOKEN = "***"')

    def test_value_reached_through_a_plain_variable(self):
        code = HEADER + (
            'pw = "plain-0000"\n'
            "\n"
            "\n"
            "def connect():\n"
            '    return pymysql.connect(host="localhost", password=pw)\n'
        )
        result = self.masked(code, ["KEY-2"])
        self.assertNotIn("plain-0000", result)
        self.assert_only_lines_changed(code, result, [FIRST + 1])  # 값이 대입된 줄만 바뀐다
        self.assertEqual(result.split("\n")[FIRST], 'pw = "***"')

    def test_bytes_value(self):
        code = HEADER + 'app.secret_key = b"bytes-secret-0000"\n'
        result = self.masked(code, ["KEY-1"])
        self.assertIn('app.secret_key = "***"', result)

    def test_all_rules_together_keep_other_verdicts(self):
        code = HEADER + (
            'app.config["SECRET_KEY"] = "abc123secret"\n'
            "# token: tok-comment-0000\n"
            'conn = pymysql.connect(host="localhost", password=os.getenv("DB_PW", "fallback-0000"))\n'
            'API_KEY = "sk-test-0000"\n'
            "\n"
            "\n"
            '@app.route("/")\n'
            "def index():\n"
            '    return "ok"\n'
            "\n"
            "\n"
            'if __name__ == "__main__":\n'
            "    app.run(debug=True)\n"
        )
        result = self.masked(code, ["KEY-1", "KEY-2", "KEY-3", "KEY-4"])
        for secret in ("abc123secret", "tok-comment-0000", "fallback-0000", "sk-test-0000"):
            self.assertNotIn(secret, result)
        self.assertEqual(verdicts(result), verdicts(code))  # 다른 취약점의 판정은 그대로
        self.assert_only_lines_changed(code, result, [FIRST + 1, FIRST + 2, FIRST + 3, FIRST + 4])

    def test_nothing_to_mask_returns_the_code_with_unified_newlines(self):
        code = HEADER + '@app.route("/")\ndef index():\n    return "ok"\n'
        self.assertEqual(mask(code, analyze(code)), code)
        windows = "﻿" + code.replace("\n", "\r\n")
        self.assertEqual(mask(windows, analyze(windows)), code)

    def test_windows_newlines_are_masked_the_same(self):
        code = HEADER + 'DB_PASSWORD = "p@ss-0000"\n'
        windows = code.replace("\n", "\r\n")
        self.assertEqual(mask(windows, analyze(windows)), mask(code, analyze(code)))

    def test_refuses_instead_of_returning_unmasked_code(self):
        code = HEADER + 'DB_PASSWORD = "p@ss-0000"\n'
        other = HEADER + "\n\n" + 'DB_PASSWORD = "p@ss-0000"\n'
        with self.assertRaises(MaskingError) as caught:
            mask(code, analyze(other))  # 다른 코드의 탐지 결과: 줄이 맞지 않는다
        self.assertNotIn("p@ss-0000", str(caught.exception))
        broken = "def broken(:\n"
        with self.assertRaises(MaskingError):
            mask(broken, analyze(broken))


if __name__ == "__main__":
    unittest.main()
