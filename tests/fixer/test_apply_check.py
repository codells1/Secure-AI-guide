"""4단계: 고친 코드 끼워 넣기와 V1~V3 검증 (fix_spec 7장).

실행: python -m unittest discover -s tests -t .
"""
import unittest

from detector import analyze
from fixer.apply_check import apply, check, leftover_findings
from fixer.grouping import make_groups

CODE = '''import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/search")
def search():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT name FROM students WHERE name = '{name}'").fetchall()
    return jsonify(rows)


@app.route("/ping")
def ping():
    return "pong"
'''
HEAD = '@app.route("/search")\ndef search():\n    name = request.args.get("name", "")\n'
BAD_QUERY = '''    rows = conn.execute(f"SELECT name FROM students WHERE name = '{name}'").fetchall()\n'''
GOOD_QUERY = '    rows = conn.execute("SELECT name FROM students WHERE name = ?", (name,)).fetchall()\n'
CONNECT = '    conn = sqlite3.connect("app.db")\n'
RETURN = "    return jsonify(rows)\n"
FIXED = HEAD + CONNECT + GOOD_QUERY + RETURN  # 줄 수가 그대로인 올바른 수정


def group_of(code, vuln_id="sql_injection", index=0):
    groups = [group for group in make_groups(analyze(code), code) if group.vuln_id == vuln_id]
    return groups[index]


def lines_of(code, span):
    return code.split("\n")[span[0] - 1:span[1]]


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.group = group_of(CODE)
        self.assertEqual(self.group.target_range, (7, 12))

    def test_same_length_keeps_the_range_and_the_rest(self):
        new_code, new_range = apply(CODE, self.group, FIXED, [])
        self.assertEqual(new_range, (7, 12))
        self.assertEqual(lines_of(new_code, new_range), FIXED.rstrip("\n").split("\n"))
        self.assertEqual(new_code.split("\n")[:6], CODE.split("\n")[:6])
        self.assertEqual(new_code.split("\n")[12:], CODE.split("\n")[12:])

    def test_longer_fix_moves_the_end(self):
        fixed = HEAD + "    if not name:\n        return jsonify([])\n" + CONNECT + GOOD_QUERY + RETURN
        new_code, new_range = apply(CODE, self.group, fixed, [])
        self.assertEqual(new_range, (7, 14))
        self.assertEqual(lines_of(new_code, new_range)[-1], "    return jsonify(rows)")
        self.assertEqual(new_code.split("\n")[16:19], ['@app.route("/ping")', "def ping():", '    return "pong"'])

    def test_shorter_fix_moves_the_end(self):
        fixed = HEAD + '    rows = sqlite3.connect("app.db").execute("SELECT 1").fetchall()\n' + RETURN
        new_code, new_range = apply(CODE, self.group, fixed, [])
        self.assertEqual(new_range, (7, 11))
        self.assertEqual(new_code.split("\n")[13:16], ['@app.route("/ping")', "def ping():", '    return "pong"'])

    def test_blank_edges_and_windows_newlines_are_trimmed(self):
        new_code, new_range = apply(CODE, self.group, "\r\n\r\n" + FIXED.replace("\n", "\r\n") + "\r\n\r\n", [])
        self.assertEqual(new_range, (7, 12))
        self.assertNotIn("\r", new_code)
        self.assertEqual(apply(CODE, self.group, FIXED, [])[0], new_code)

    def test_empty_fix_removes_the_range(self):
        code = 'from flask import Flask\n\napp = Flask(__name__)\n# password: example-0000\nPORT = 5000\n'
        group = group_of(code, "hardcoded_secret")
        self.assertEqual(group.target_range, (4, 4))
        new_code, new_range = apply(code, group, "", [])
        self.assertEqual(new_code, 'from flask import Flask\n\napp = Flask(__name__)\nPORT = 5000\n')
        self.assertEqual(new_range, (4, 3))  # 빈 범위
        self.assertEqual(check(analyze(code), analyze(new_code), group, new_range), [])

    def test_added_lines_go_below_the_last_top_level_import(self):
        added = ["from werkzeug.utils import secure_filename", "LIMIT = 10"]
        new_code, new_range = apply(CODE, self.group, FIXED, added)
        self.assertEqual(new_code.split("\n")[:5], [
            "import sqlite3",
            "from flask import Flask, request, jsonify",
            "from werkzeug.utils import secure_filename",
            "LIMIT = 10",
            "",
        ])
        self.assertEqual(new_range, (9, 14))  # 위에 2줄이 들어가 2줄 밀린다
        self.assertEqual(lines_of(new_code, new_range), FIXED.rstrip("\n").split("\n"))

    def test_lines_that_already_exist_are_not_added_again(self):
        added = ["import sqlite3", "import os", "import os\n", "from flask import Flask, request, jsonify  "]
        new_code, new_range = apply(CODE, self.group, FIXED, added)
        self.assertEqual(new_code.split("\n")[:3], ["import sqlite3", "from flask import Flask, request, jsonify", "import os"])
        self.assertEqual(new_range, (8, 13))

    def test_multi_line_addition_stays_whole(self):
        block = 'SORT_COLUMNS = {\n    "name": "name",\n}'
        code = CODE.replace("app = Flask(__name__)\n", "app = Flask(__name__)\nOTHER = {\n    1: 2,\n}\n")
        new_code, _ = apply(code, group_of(code), FIXED, [block])
        self.assertEqual(new_code.split("\n")[2:5], ["SORT_COLUMNS = {", '    "name": "name",', "}"])  # '}'가 빠지지 않는다

    def test_without_imports_additions_go_to_the_top(self):
        code = 'app = make_app()\napp.config["SECRET_KEY"] = "***"\n'
        group = group_of(code, "hardcoded_secret")
        new_code, new_range = apply(code, group, 'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]', ["import os"])
        self.assertEqual(new_code, 'import os\napp = make_app()\napp.config["SECRET_KEY"] = os.environ["SECRET_KEY"]\n')
        self.assertEqual(new_range, (3, 3))

    def test_import_below_the_range_is_followed_as_lines_shift(self):
        code = 'from flask import Flask\napp = Flask(__name__)\napp.secret_key = "***"\nimport sqlite3\nDB = "app.db"\n'
        group = group_of(code, "hardcoded_secret")
        self.assertEqual(group.target_range, (3, 3))
        fixed = '# 키는 환경변수에서 읽는다\napp.secret_key = os.environ["SECRET_KEY"]'
        new_code, new_range = apply(code, group, fixed, ["import os"])
        self.assertEqual(new_code.split("\n")[2:7], [
            "# 키는 환경변수에서 읽는다",
            'app.secret_key = os.environ["SECRET_KEY"]',
            "import sqlite3",
            "import os",
            'DB = "app.db"',
        ])
        self.assertEqual(new_range, (3, 4))  # 범위 아래에 넣었으므로 밀리지 않는다

    def test_range_outside_the_code_raises(self):
        longer = CODE + "\n" * 30
        outside = group_of(longer)
        with self.assertRaises(ValueError):
            apply("x = 1\n", outside, FIXED, [])


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.group = group_of(CODE)
        self.base = analyze(CODE)

    def run_check(self, fixed, added=()):
        new_code, new_range = apply(CODE, self.group, fixed, list(added))
        after = analyze(new_code)
        return check(self.base, after, self.group, new_range), leftover_findings(self.base, after, self.group, new_range)

    def test_good_fix_passes(self):
        self.assertEqual(self.run_check(FIXED), ([], []))

    def test_v1_syntax_error(self):
        failed, leftover = self.run_check(HEAD + CONNECT + "    rows = conn.execute(\n" + RETURN)
        self.assertEqual((failed, leftover), (["V1"], []))

    def test_v2_vulnerability_left_in_the_range(self):
        filtered = HEAD + '    name = name.replace("\'", "")\n' + CONNECT + BAD_QUERY + RETURN  # 금지된 방식
        failed, leftover = self.run_check(filtered)
        self.assertEqual(failed, ["V2"])
        self.assertEqual([(item["rule_id"], item["line"]) for item in leftover], [("SQL-1", 12)])

    def test_v3_new_vulnerability_elsewhere(self):
        leaking = (HEAD + "    try:\n    " + CONNECT + "    " + GOOD_QUERY
                   + "    except Exception as e:\n        return str(e), 500\n" + RETURN)
        failed, leftover = self.run_check(leaking)
        self.assertEqual(failed, ["V3"])
        self.assertEqual([item["rule_id"] for item in leftover], ["ERR-1"])

    def test_v2_and_v3_together(self):
        both = (HEAD + "    try:\n    " + CONNECT + "    " + BAD_QUERY
                + "    except Exception as e:\n        return str(e), 500\n" + RETURN)
        failed, leftover = self.run_check(both)
        self.assertEqual(failed, ["V2", "V3"])
        self.assertEqual(sorted(item["rule_id"] for item in leftover), ["ERR-1", "SQL-1"])

    def test_v3_also_covers_added_top_level_lines(self):
        failed, _ = self.run_check(FIXED, ['app.config["SECRET_KEY"] = "example-0000"'])
        self.assertEqual(failed, ["V3"])

    def test_v2_ignores_the_same_vulnerability_outside_the_range(self):
        other = CODE + (
            '\n\n@app.route("/other")\ndef other():\n    city = request.args.get("city", "")\n'
            '    return str(sqlite3.connect("app.db").execute("SELECT 1 WHERE c = \'" + city + "\'").fetchall())\n'
        )
        first = group_of(other, index=0)
        new_code, new_range = apply(other, first, FIXED, [])
        after = analyze(new_code)
        self.assertEqual(check(analyze(other), after, first, new_range), [])
        still = [item for item in after["results"] if item["vuln_id"] == "sql_injection"][0]
        self.assertEqual(still["verdict"], "위험")  # 다른 함수의 것은 그 묶음에서 따로 고친다

    def test_v3_does_not_blame_what_was_already_risky(self):
        risky = CODE + '\n\nif __name__ == "__main__":\n    app.run(debug=True)\n'
        group = group_of(risky)
        new_code, new_range = apply(risky, group, FIXED, [])
        self.assertEqual(check(analyze(risky), analyze(new_code), group, new_range), [])


if __name__ == "__main__":
    unittest.main()
