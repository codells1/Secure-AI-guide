"""1단계: 수정 묶음과 target_range (fix_spec 2.1, 6.2).

판정은 실제 analyze()로 받는다. 실행: python -m unittest discover -s tests -t .
"""
import json
import unittest

from detector import analyze
from fixer.grouping import MODULE, function_name, make_groups, target_range

UPLOAD = '''import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    file.save(os.path.join("uploads", "fixed_name.bin"))
    return "ok"
'''

TWO_SQL_ONE_FUNCTION = '''import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    name = request.args.get("name", "")
    city = request.args.get("city", "")
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(f"SELECT id FROM users WHERE name = '{name}'")
    cur.execute("SELECT id FROM users WHERE city = '" + city + "'")
    return "ok"
'''

SQL_AND_COMMAND_ONE_FUNCTION = '''import os, sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    conn = sqlite3.connect("users.db")
    conn.execute(f"SELECT id FROM users WHERE name = '{name}'")
    return str(os.system("echo " + name))
'''

DECORATORS = '''import sqlite3
from functools import wraps
from flask import Flask, request

app = Flask(__name__)


def logged(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        return view(*args, **kwargs)
    return wrapper


@app.route("/a")
@logged
def first():
    name = request.args.get("name", "")
    sqlite3.connect("users.db").execute(f"SELECT id FROM users WHERE name = '{name}'")
    return "ok"


@app.route("/b")
def second():
    name = request.args.get("name", "")
    sqlite3.connect("users.db").execute(f"SELECT id FROM users WHERE name = '{name}'")
    return "ok"
'''

# 비밀값은 모두 가짜 값이다.
MODULE_LEVEL = '''import pymysql
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "abc123secret"
# 관리자 비밀번호: admin1234
conn = pymysql.connect(
    host="localhost",
    user="root",
    password="abc12345",
)


@app.route("/")
def index():
    # password = "inside-comment"
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)
'''

NESTED = '''import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/n")
def outer():
    def inner(name):
        return sqlite3.connect("users.db").execute(f"SELECT id FROM users WHERE name = '{name}'")
    return str(inner(request.args.get("name", "")))
'''

IDOR = '''import sqlite3
from flask import Flask, session, jsonify

app = Flask(__name__)


@app.route("/posts/<int:post_id>")
def show_post(post_id):
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT id, title FROM posts WHERE id = ?", (post_id,)).fetchone()
    return jsonify(row)
'''

SAFE = '''from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "ok"
'''


def groups_of(code, user_input=None):
    return make_groups(analyze(code, user_input), code)


def summary(groups):
    return [(group.group_id, group.rule_ids, group.function_name) for group in groups]


class GroupingTest(unittest.TestCase):
    def test_upload_rules_on_one_line_make_one_group(self):
        (group,) = groups_of(UPLOAD)
        self.assertEqual(group.group_id, "file_upload:7-11")
        self.assertEqual(group.rule_ids, ("UP-1", "UP-2"))
        self.assertEqual([finding["line"] for finding in group.findings], [10, 10])
        self.assertEqual(group.function_name, "upload")

    def test_same_vuln_twice_in_one_function_is_one_group(self):
        (group,) = groups_of(TWO_SQL_ONE_FUNCTION)
        self.assertEqual(group.group_id, "sql_injection:7-15")
        self.assertEqual(group.rule_ids, ("SQL-1",))
        self.assertEqual([finding["line"] for finding in group.findings], [13, 14])

    def test_different_vulns_in_one_function_stay_separate(self):
        groups = groups_of(SQL_AND_COMMAND_ONE_FUNCTION)
        self.assertEqual(summary(groups), [
            ("sql_injection:7-12", ("SQL-1",), "hello"),
            ("os_command_injection:7-12", ("CMD-1",), "hello"),
        ])

    def test_range_starts_at_first_decorator(self):
        groups = groups_of(DECORATORS)
        self.assertEqual([group.target_range for group in groups], [(15, 20), (23, 27)])
        self.assertEqual([group.function_name for group in groups], ["first", "second"])

    def test_module_level_statement_comment_and_order(self):
        groups = groups_of(MODULE_LEVEL)
        self.assertEqual(summary(groups), [
            ("hardcoded_secret:5-5", ("KEY-1",), MODULE),      # 한 줄 문장
            ("hardcoded_secret:6-6", ("KEY-4",), MODULE),      # 주석은 그 줄 하나
            ("hardcoded_secret:7-11", ("KEY-2",), MODULE),     # 여러 줄에 걸친 호출 전체
            ("hardcoded_secret:16-16", ("KEY-4",), "index"),   # 함수 안 주석도 그 줄 하나
            ("debug_error_exposure:20-21", ("DBG-1",), MODULE),  # if 문 전체
        ])

    def test_nested_function_uses_innermost(self):
        (group,) = groups_of(NESTED)
        self.assertEqual((group.target_range, group.function_name), ((9, 10), "inner"))

    def test_only_risky_verdicts_are_grouped(self):
        self.assertEqual(groups_of(SAFE), [])
        # IDOR은 학생이 답하기 전에는 판정이 없다 (verdict None).
        self.assertEqual(groups_of(IDOR), [])
        answered = groups_of(IDOR, {"idor": {"public_functions": []}})
        self.assertEqual(summary(answered), [("idor:7-11", ("IDOR-1",), "show_post")])

    def test_syntax_error_gives_no_groups(self):
        broken = "def broken(:\n    pass\n"
        self.assertEqual(make_groups(analyze(broken), broken), [])

    def test_same_input_same_output(self):
        self.assertEqual(groups_of(MODULE_LEVEL), groups_of(MODULE_LEVEL))

    def test_line_endings_and_bom_do_not_change_groups(self):
        expected = summary(groups_of(MODULE_LEVEL))
        windows = "﻿" + MODULE_LEVEL.replace("\n", "\r\n")
        self.assertEqual(summary(groups_of(windows)), expected)
        self.assertEqual(summary(groups_of(MODULE_LEVEL.replace("\n", "\r"))), expected)

    def test_to_dict_is_json_ready(self):
        (group,) = groups_of(UPLOAD)
        data = json.loads(json.dumps(group.to_dict(), ensure_ascii=False))
        self.assertEqual(data["group_id"], "file_upload:7-11")
        self.assertEqual(data["target_range"], [7, 11])
        self.assertEqual(data["rule_ids"], ["UP-1", "UP-2"])
        self.assertEqual(sorted(data["findings"][0]), ["line", "message", "path", "rule_id"])


class TargetRangeTest(unittest.TestCase):
    def test_function_body_and_decorator_line(self):
        self.assertEqual(target_range(DECORATORS, 19, "SQL-1"), (15, 20))
        self.assertEqual(target_range(DECORATORS, 15, "LOGIN-2"), (15, 20))  # 데코레이터 줄 자체

    def test_outside_function(self):
        self.assertEqual(target_range(MODULE_LEVEL, 10, "KEY-2"), (7, 11))
        self.assertEqual(target_range(MODULE_LEVEL, 21, "DBG-1"), (20, 21))

    def test_comment_rule_is_one_line(self):
        self.assertEqual(target_range(MODULE_LEVEL, 16, "KEY-4"), (16, 16))

    def test_function_name(self):
        self.assertEqual(function_name(MODULE_LEVEL, 16), "index")
        self.assertEqual(function_name(MODULE_LEVEL, 5), MODULE)

    def test_bad_line_or_code_raises_value_error(self):
        for line in (0, 999, "3"):
            with self.assertRaises(ValueError):
                target_range(SAFE, line, "SQL-1")
        with self.assertRaises(ValueError):
            target_range("def broken(:\n", 1, "SQL-1")


if __name__ == "__main__":
    unittest.main()
