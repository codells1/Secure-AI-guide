"""5단계: ③ 프롬프트 템플릿 (fix_spec 8장).

실행: python -m unittest discover -s tests -t .
"""
import re
import unittest

from detector import analyze
from detector.result import MESSAGES
from fixer.cards import card_files, load_card, rule_ids_of
from fixer.grouping import MODULE, Group, make_groups, range_text
from fixer.masking import mask
from fixer.prompt_template import build_prompt

TARGET = '@app.route("/search")\ndef search():\n    return "ok"'
INSTRUCTION = "search 함수의 execute()에서 name을 ? 자리로 넘겨줘."
CONDITIONS = [
    "2. 이 취약점과 관련 없는 기능은 바꾸지 말 것",
    "3. 고친 코드 전체와 새로 필요한 import를 보여줄 것",
    "4. 무엇을 바꿨는지, 기존 기능이 그대로 동작하는지 확인하는 방법을 설명할 것",
    "5. 고친 뒤, 고친 코드에 같은 취약점이 남아 있는지 스스로 다시 검토하고, 남아 있으면 한 번 더 고칠 것",
    "6. 프로젝트의 다른 파일도 볼 수 있다면, 같은 문제가 있는 곳을 함께 알려줄 것",
]


def group_for(vuln_id, rule_ids, function_name="search", line=5):
    findings = tuple(
        {"rule_id": rule_id, "line": line, "path": [line], "message": MESSAGES[rule_id]} for rule_id in rule_ids
    )
    return Group(f"{vuln_id}:3-8", vuln_id, tuple(rule_ids), findings, (3, 8), function_name)


def prompt_for(vuln_id, rule_ids, target=TARGET, instruction=INSTRUCTION, **kwargs):
    group = group_for(vuln_id, rule_ids, **kwargs)
    return build_prompt("app.py", group, load_card(vuln_id, rule_ids), target, instruction)


class PromptTemplateTest(unittest.TestCase):
    def test_full_text_matches_the_spec(self):
        expected = (
            '내 Flask 프로젝트의 app.py 파일 search 함수에 "SQL 삽입" 보안 취약점이 있어.\n'
            "문제: 사용자가 입력한 값이 SQL 문장 안에 그대로 들어가요. 값은 `?` 자리로 따로 넘겨야 해요.\n"
            "\n"
            "[지금 코드]\n"
            "```python\n"
            + TARGET + "\n"
            "```\n"
            "\n"
            "다음 조건대로 고쳐줘.\n"
            "1. 다음 방식으로 고칠 것: SQL 문장은 고정하고, 값은 `?`(PyMySQL은 `%s`) 자리로 "
            "`execute()`의 두 번째 인자에 넘긴다\n"
            "   " + INSTRUCTION + "\n"
            + "\n".join(CONDITIONS)
        )
        self.assertEqual(prompt_for("sql_injection", ["SQL-1"]), expected)

    def test_no_blank_left_for_any_rule(self):
        count = 0
        for vuln_id in card_files():
            for rule_id in rule_ids_of(vuln_id):
                for instruction in (INSTRUCTION, None):
                    with self.subTest(rule_id=rule_id, instruction=instruction):
                        prompt = prompt_for(vuln_id, [rule_id], instruction=instruction)
                        # 코드·파일 이름에 중괄호가 없으므로, 남아 있으면 채우지 못한 자리다.
                        self.assertNotRegex(prompt, r"[{}]")
                        self.assertNotIn("None", prompt)
                        self.assertIn(f'"{load_card(vuln_id, [rule_id]).name}" 보안 취약점', prompt)
                        self.assertIn("문제: " + MESSAGES[rule_id], prompt)
                        self.assertIn(load_card(vuln_id, [rule_id]).allowed_fixes[0], prompt)
                        self.assertTrue(prompt.endswith("\n".join(CONDITIONS)))
                count += 1
        self.assertEqual(count, 32)

    def test_without_fix_instruction_the_line_is_removed(self):
        for missing in (None, "", "   \n "):
            with self.subTest(missing=missing):
                lines = prompt_for("sql_injection", ["SQL-1"], instruction=missing).split("\n")
                first = next(index for index, line in enumerate(lines) if line.startswith("1. "))
                self.assertEqual(lines[first + 1], CONDITIONS[0])  # 1번 바로 다음이 2번
                self.assertEqual(len(lines), len(prompt_for("sql_injection", ["SQL-1"]).split("\n")) - 1)

    def test_fix_instruction_is_kept_on_one_line(self):
        prompt = prompt_for("sql_injection", ["SQL-1"], instruction="  첫 줄\n둘째 줄  ")
        self.assertIn("\n   첫 줄 둘째 줄\n2. ", prompt)

    def test_fence_is_longer_than_backticks_in_the_code(self):
        cases = {
            'x = "plain"': 3,
            'doc = "``` 코드 ```"': 4,
            'doc = """\n````\nfour\n````\n"""': 5,
            "x = '`one`'": 3,
        }
        for target, length in cases.items():
            with self.subTest(target=target):
                prompt = prompt_for("sql_injection", ["SQL-1"], target=target)
                fence = "`" * length
                lines = prompt.split("\n")
                opened, closed = lines.index(fence + "python"), lines.index(fence)
                self.assertEqual("\n".join(lines[opened + 1:closed]), target)  # 코드 블록이 중간에 끊기지 않는다
                self.assertEqual([line for line in lines if re.fullmatch("`{%d,}(python)?" % length, line)],
                                 [fence + "python", fence])

    def test_location_inside_and_outside_a_function(self):
        self.assertIn("app.py 파일 search 함수에", prompt_for("hardcoded_secret", ["KEY-1"]))
        self.assertIn("app.py 파일 5번째 줄에", prompt_for("hardcoded_secret", ["KEY-1"], function_name=MODULE))

    def test_group_with_several_rules(self):
        upload = prompt_for("file_upload", ["UP-1", "UP-2"])
        self.assertIn("문제: " + MESSAGES["UP-1"] + "\n" + MESSAGES["UP-2"] + "\n\n[지금 코드]", upload)
        self.assertEqual(upload.count("Content-Type 허용 목록"), 1)  # 같은 행의 해결법은 한 번만
        sql = prompt_for("sql_injection", ["SQL-1", "SQL-2"])
        first, second = load_card("sql_injection", ["SQL-1", "SQL-2"]).allowed_fixes
        self.assertIn("1. 다음 방식으로 고칠 것: " + first + " / " + second + "\n", sql)

    def test_braces_in_student_code_are_kept(self):
        target = 'def view():\n    data = {"file": name, "x": f"{location}"}\n    return "{fence}"'
        prompt = prompt_for("sql_injection", ["SQL-1"], target=target)
        self.assertIn(target, prompt)

    def test_file_name_is_cleaned(self):
        group, card = group_for("sql_injection", ["SQL-1"]), load_card("sql_injection", ["SQL-1"])
        for raw, shown in (
            ("C:\\Users\\student\\my app.py", "my app.py"),
            ("project/sub/views.py", "views.py"),
            ("bad\nname\t.py", "badname.py"),
            ("", "app.py"),
            (None, "app.py"),
            ("가" * 300 + ".py", "가" * 100),
        ):
            with self.subTest(raw=raw):
                first_line = build_prompt(raw, group, card, TARGET).split("\n")[0]
                self.assertEqual(first_line, f'내 Flask 프로젝트의 {shown} 파일 search 함수에 "SQL 삽입" 보안 취약점이 있어.')

    def test_with_a_real_group_the_prompt_shows_masked_code(self):
        code = (
            "import pymysql\nfrom flask import Flask\n\napp = Flask(__name__)\n\n\n"
            "def get_db():\n"
            '    return pymysql.connect(host="localhost", password="example-pass-0000")\n'
        )
        result = analyze(code)
        masked = mask(code, result)
        (group,) = make_groups(result, code)
        target = range_text(masked, group.target_range)
        prompt = build_prompt("app.py", group, load_card(group.vuln_id, group.rule_ids), target)
        self.assertIn('app.py 파일 get_db 함수에 "하드코딩된 시크릿" 보안 취약점이 있어.', prompt)
        self.assertIn('def get_db():\n    return pymysql.connect(host="localhost", password="***")\n```', prompt)
        self.assertNotIn("example-pass-0000", prompt)


class RangeTextTest(unittest.TestCase):
    def test_range_text(self):
        code = "a = 1\r\nb = 2\r\nc = 3\r\n"
        self.assertEqual(range_text(code, (2, 3)), "b = 2\nc = 3")
        self.assertEqual(range_text(code, (2, 2)), "b = 2")
        self.assertEqual(range_text(code, (2, 1)), "")  # 빈 범위


if __name__ == "__main__":
    unittest.main()
