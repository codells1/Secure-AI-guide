"""판정 기준 (docs/detection_spec.md) 가운데 가이드 예제로 다 드러나지 않는 부분을 확인한다.

- 결과 형식과 학생 응답 흐름 (스펙 5장, 6장)
- 검증으로 인정하는 것과 인정하지 않는 것 (스펙 3.2)
- 보고하는 줄 (스펙 3.4)
- 실제 학생 코드에서 나왔던 오탐

실행: python -m unittest discover -s tests -t .
"""
import unittest

from detector import analyze
from tests.detector.helpers import ALL_PRIVATE, flask_app, lines, risky, rules, verdict

ORDER = [
    "sql_injection", "os_command_injection", "file_upload", "path_traversal", "idor", "ssrf",
    "debug_error_exposure", "hardcoded_secret", "password_storage", "login_attempt_limit",
]
DB = "import sqlite3\n"


class ResultShapeTest(unittest.TestCase):
    def test_ten_results_in_the_spec_order(self):
        result = analyze("x = 1\n")
        self.assertEqual(list(result), ["ok", "results"])
        self.assertEqual([item["vuln_id"] for item in result["results"]], ORDER)
        for item in result["results"]:
            self.assertEqual(
                (item["verdict"], item["findings"], item["needs_user_input"], item["acknowledged"]),
                ("안전", [], None, False),
            )

    def test_syntax_error_reports_the_line(self):
        result = analyze("x = 1\ndef broken(:\n")
        self.assertEqual((result["ok"], result["error"]["line"]), (False, 2))
        self.assertNotIn("results", result)

    def test_finding_has_line_rule_path_and_message(self):
        code = flask_app('''
            @app.route("/search")
            def search():
                name = request.args.get("name", "")
                conn = sqlite3.connect("app.db")
                return jsonify(conn.execute(f"SELECT * FROM t WHERE name = '{name}'").fetchall())
        ''', DB)
        (finding,) = next(item for item in analyze(code)["results"] if item["vuln_id"] == "sql_injection")["findings"]
        self.assertEqual(sorted(finding), ["line", "message", "path", "rule_id"])
        self.assertEqual((finding["rule_id"], finding["line"], finding["path"]), ("SQL-1", 12, [10, 12]))

    def test_line_endings_and_bom_do_not_change_the_result(self):
        code = flask_app('''
            @app.route("/x")
            def x():
                return str(os.system(request.args["c"]))
        ''', "import os\n")
        expected = analyze(code)
        self.assertEqual(analyze("﻿" + code.replace("\n", "\r\n")), expected)
        self.assertEqual(analyze(code.replace("\n", "\r")), expected)


class QuestionFlowTest(unittest.TestCase):
    NOTE = flask_app('''
        @app.route("/notes/<int:note_id>")
        def show_note(note_id):
            conn = sqlite3.connect("app.db")
            row = conn.execute("SELECT title FROM notes WHERE id = ?", (note_id,)).fetchone()
            return jsonify(row)
    ''', DB)

    def test_idor_asks_before_judging(self):
        item = next(item for item in analyze(self.NOTE)["results"] if item["vuln_id"] == "idor")
        self.assertEqual((item["verdict"], item["findings"]), (None, []))
        self.assertEqual(item["needs_user_input"]["type"], "idor_routes")
        self.assertEqual(item["needs_user_input"]["routes"], [
            {"function": "show_note", "route": "/notes/<int:note_id>", "line": 8},
        ])
        self.assertEqual(analyze(self.NOTE, {})["results"][4], item)  # 빈 응답도 첫 호출과 같다

    def test_idor_answer_decides_the_verdict(self):
        self.assertEqual(lines(self.NOTE, "idor", {"idor": {"public_functions": []}}), [("IDOR-1", 11)])
        self.assertEqual(verdict(self.NOTE, "idor", {"idor": {"public_functions": ["show_note"]}}), "안전")

    def test_ssrf_is_risky_first_and_the_answer_only_adds_a_mark(self):
        code = flask_app('''
            @app.route("/fetch")
            def fetch():
                return requests.get(request.args.get("url", "")).text
        ''', "import requests\n")

        def ssrf(user_input):
            return next(item for item in analyze(code, user_input)["results"] if item["vuln_id"] == "ssrf")

        first = ssrf(None)
        self.assertEqual((first["verdict"], first["acknowledged"]), ("위험", False))
        self.assertEqual(first["needs_user_input"]["type"], "ssrf_dynamic_request")
        yes = ssrf({"ssrf": {"dynamic_request_needed": True}})
        self.assertEqual((yes["verdict"], yes["acknowledged"], yes["needs_user_input"]), ("위험", True, None))
        no = ssrf({"ssrf": {"dynamic_request_needed": False}})
        self.assertEqual((no["verdict"], no["acknowledged"], no["needs_user_input"]), ("위험", False, None))


class ValidationTest(unittest.TestCase):
    """스펙 3.2: 무엇을 검증으로 인정하는가."""

    def command(self, check):
        return flask_app(f'''
            ALLOWED = ["status", "version"]
            CHOICES = {{"a": "status", "b": "version"}}


            def is_ok(value):
                return value in ALLOWED


            def looks_fine(value):
                return len(value) < 10


            @app.route("/run")
            def run():
                name = request.args.get("name", "")
{check}
                return str(os.system("tool " + name))
        ''', "import os\nimport re\n")

    def test_checks_that_count(self):
        for label, check in {
            "허용 목록에 없으면 중단": "    if name not in ALLOWED:\n        abort(400)",
            "허용 목록에 있을 때만": "    if name in ALLOWED:\n        pass\n    else:\n        abort(400)",
            "상수와 같은지 비교": "    if name != \"status\":\n        abort(400)",
            "상수 dict에서 꺼낸 값": "    name = CHOICES.get(name, \"status\")",
            "허용 목록을 보는 같은 파일의 함수": "    if not is_ok(name):\n        abort(400)",
            "숫자 변환": "    name = str(int(name))",
            "형식 검사": "    if not name.isalnum():\n        abort(400)",
            "정규식 형식 검사": "    if not re.fullmatch(r\"[A-Za-z0-9_-]+\", name):\n        abort(400)",
            "shlex.quote": "    import shlex\n    name = shlex.quote(name)",
        }.items():
            with self.subTest(label):
                code = self.command("\n".join("            " + line for line in check.split("\n")))
                self.assertEqual(rules(code, "os_command_injection"), [])

    def test_checks_that_do_not_count(self):
        for label, check in {
            "검사 없음": "    pass",
            "실패해도 계속 진행": "    if name not in ALLOWED:\n        print(\"이상한 값\")",
            "startswith": "    if not name.startswith(\"st\"):\n        abort(400)",
            "블랙리스트": "    if name in [\"rm\", \"del\"]:\n        abort(400)",
            "직접 만든 검사 함수": "    if not looks_fine(name):\n        abort(400)",
            "특수문자 일부만 제거": "    name = name.replace(\";\", \"\").replace(\"|\", \"\")",
            "부분 일치 정규식": "    if not re.search(r\"[a-z]+\", name):\n        abort(400)",
        }.items():
            with self.subTest(label):
                code = self.command("\n".join("            " + line for line in check.split("\n")))
                self.assertEqual(rules(code, "os_command_injection"), ["CMD-1"])

    def test_sql_accepts_only_binding_or_a_fixed_choice(self):
        base = '''
            SORT_COLUMNS = {{"name": "name", "grade": "grade"}}


            @app.route("/students/<int:student_id>")
            def students(student_id):
                sort = request.args.get("sort", "name")
                conn = sqlite3.connect("app.db")
                {query}
                return jsonify(rows)
        '''
        cases = {
            'rows = conn.execute(f"SELECT * FROM s WHERE id = {student_id}").fetchall()': ["SQL-1"],  # 숫자여도 바인딩
            'rows = conn.execute("SELECT * FROM s WHERE id = " + str(int(sort))).fetchall()': ["SQL-1"],
            'rows = conn.execute("SELECT * FROM s ORDER BY " + sort).fetchall()': ["SQL-2"],
            'rows = conn.execute("SELECT * FROM s ORDER BY " + SORT_COLUMNS.get(sort, "name")).fetchall()': [],
            'rows = conn.execute("SELECT * FROM s ORDER BY " + ("name" if sort == "n" else "grade")).fetchall()': [],
            'rows = conn.execute("SELECT * FROM s WHERE id = ?", (student_id,)).fetchall()': [],
            'rows = conn.execute("SELECT * FROM s WHERE id IN (" + ",".join("?" * 3) + ")", (1, 2, 3)).fetchall()': [],
            'rows = conn.execute("SELECT * FROM s WHERE owner = " + str(session["user_id"])).fetchall()': ["SQL-3"],
        }
        for query, expected in cases.items():
            with self.subTest(query):
                self.assertEqual(rules(flask_app(base.format(query=query), DB), "sql_injection"), expected)


class OsCommandTest(unittest.TestCase):
    def test_filtered_value_through_the_shell_is_cmd2(self):
        code = flask_app('''
            @app.route("/backup")
            def backup():
                date = re.sub("[|;&:><`\\\\\\\\!]", "", request.args.get("date", ""))
                subprocess.run("backup.bat " + date, shell=True)
                return "ok"
        ''', "import re\nimport subprocess\n")
        self.assertEqual(lines(code, "os_command_injection"), [("CMD-2", 12)])

    def test_every_command_function_is_a_sink(self):
        for call in (
            'os.system("ping " + host)', 'os.popen("ping " + host)', 'subprocess.call("ping " + host, shell=True)',
            'subprocess.check_output(["ping", host])', 'subprocess.Popen(["ping", host])',
            'subprocess.getoutput("ping " + host)',
        ):
            with self.subTest(call):
                code = flask_app(f'''
                    @app.route("/ping")
                    def ping():
                        host = request.args.get("host", "")
                        return str({call})
                ''', "import os\nimport subprocess\n")
                self.assertEqual(rules(code, "os_command_injection"), ["CMD-1"])

    def test_fixed_commands_are_safe(self):
        code = flask_app('''
            @app.route("/uptime")
            def uptime():
                subprocess.run(["uptime"])
                return str(os.system("date"))
        ''', "import os\nimport subprocess\n")
        self.assertEqual(risky(code), {})


class PathAndUploadTest(unittest.TestCase):
    def path(self, statement, imports=""):
        return flask_app(f'''
            @app.route("/files/<name>")
            def download(name):
                {statement}
        ''', "import os\nfrom flask import send_file, send_from_directory\n"
             "from werkzeug.utils import secure_filename\n" + imports)

    def test_sanitisers(self):
        cases = {
            'return send_file(os.path.join("files", name))': ["PATH-1"],
            'return open("files/" + name).read()': ["PATH-1"],
            'return send_file(os.path.join("files", os.path.basename(name)))': ["PATH-1"],  # basename은 인정하지 않는다
            'return send_file(os.path.join("files", name.replace("..", "")))': ["PATH-1"],
            'return send_file(os.path.join("files", secure_filename(name)))': [],
            'return send_from_directory("files", name)': [],
            'return send_file(os.path.join("files", name.replace(".", "").replace("/", "").replace("\\\\", "")))': [],
            'return send_file(os.path.join("files", "notice.txt"))': [],
        }
        for statement, expected in cases.items():
            with self.subTest(statement):
                self.assertEqual(rules(self.path(statement), "path_traversal"), expected)

    def test_uploaded_filename_is_external_input(self):
        code = flask_app('''
            ALLOWED_EXTENSIONS = {"png", "jpg"}
            ALLOWED_TYPES = {"image/png", "image/jpeg"}


            def allowed_file(filename):
                return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


            @app.route("/upload", methods=["POST"])
            def upload():
                file = request.files["file"]
                if not allowed_file(file.filename) or file.mimetype not in ALLOWED_TYPES:
                    abort(400)
                file.save(os.path.join("uploads", file.filename))
                return "ok"
        ''', "import os\n")
        self.assertEqual(risky(code), {"path_traversal": ["PATH-1"]})  # 확장자·형식은 확인했지만 이름을 그대로 쓴다

    def test_checks_the_team_decided_not_to_accept(self):
        for label, check in {
            "이름에 글자가 들어 있는지": 'if "jpg" not in file.filename:',
            "형식이 image/로 시작하는지": 'if not file.mimetype.startswith("image/"):',
        }.items():
            with self.subTest(label):
                code = flask_app(f'''
                    @app.route("/upload", methods=["POST"])
                    def upload():
                        file = request.files["file"]
                        {check}
                            abort(400)
                        file.save("uploads/fixed.bin")
                        return "ok"
                ''')
                self.assertEqual(rules(code, "file_upload"), ["UP-1", "UP-2"])

    def test_every_file_in_a_loop_needs_its_own_checks(self):
        code = flask_app('''
            ALLOWED = {".png"}


            @app.route("/upload", methods=["POST"])
            def upload():
                for file in request.files.getlist("files"):
                    if os.path.splitext(file.filename)[1] not in ALLOWED:
                        continue
                    if file.content_type != "image/png":
                        continue
                    file.save("uploads/" + secure_filename(file.filename))
                return "ok"
        ''', "import os\nfrom werkzeug.utils import secure_filename\n")
        self.assertEqual(risky(code), {})


class SsrfTest(unittest.TestCase):
    def fetch(self, expression, before=""):
        return flask_app(f'''
            SOURCES = {{"weather": "https://api.example.com/weather", "news": "https://api.example.com/news"}}


            @app.route("/fetch")
            def fetch():
                value = request.args.get("value", "")
                {before}
                return requests.get({expression}, timeout=5).text
        ''', "import requests\n")

    def test_who_decides_the_server(self):
        cases = {
            ("value", ""): ["SSRF-1"],
            ('"https://" + value + "/status"', ""): ["SSRF-1"],
            ('f"{value}/status"', ""): ["SSRF-1"],
            ('"https://api.example.com/items/" + value', ""): [],  # 요청이 가는 서버는 코드에 적혀 있다
            ('"https://api.example.com/search?q=" + value', ""): [],
            ("SOURCES[value]", "if value not in SOURCES:\n                    abort(400)"): [],
            ('SOURCES.get(value, SOURCES["news"])', ""): [],
            ("value", 'if not value.startswith("https://api.example.com/"):\n                    abort(400)'): ["SSRF-1"],
            ("value", 'if "example.com" not in value:\n                    abort(400)'): ["SSRF-1"],
        }
        for (expression, before), expected in cases.items():
            with self.subTest(expression=expression, before=before):
                self.assertEqual(rules(self.fetch(expression, before), "ssrf"), expected)

    def test_client_objects_and_urllib(self):
        for call in ("requests.Session().get(url)", "urllib.request.urlopen(url)", 'requests.request("GET", url)',
                     "httpx.get(url)"):
            with self.subTest(call):
                code = flask_app(f'''
                    @app.route("/fetch")
                    def fetch():
                        url = request.args["url"]
                        return str({call})
                ''', "import httpx\nimport requests\nimport urllib.request\n")
                self.assertEqual(rules(code, "ssrf"), ["SSRF-1"])


class DebugAndErrorTest(unittest.TestCase):
    def test_debug_values(self):
        cases = {
            "app.run(debug=True)": ["DBG-1"],
            'app.run("0.0.0.0", 5000, True)': ["DBG-1"],
            "app.config['DEBUG'] = True": ["DBG-1"],
            "app.config.update(DEBUG=True)": ["DBG-1"],
            "DEBUG = True\napp.run(debug=DEBUG)": ["DBG-1"],
            'app.run(debug=os.environ.get("FLASK_DEBUG") == "1")': ["DBG-2"],
            "app.run(debug=False)": [],
            "app.run()": [],
            "DEBUG = False\napp.debug = DEBUG": [],
        }
        for statement, expected in cases.items():
            with self.subTest(statement):
                code = "import os\nfrom flask import Flask\n\napp = Flask(__name__)\n" + statement + "\n"
                self.assertEqual(rules(code, "debug_error_exposure"), expected)

    def test_other_run_calls_are_not_the_app(self):
        code = "import subprocess\nfrom flask import Flask\n\napp = Flask(__name__)\nsubprocess.run(['ls'], check=True)\n"
        self.assertEqual(rules(code, "debug_error_exposure"), [])

    def handler(self, statement):
        return flask_app(f'''
            @app.route("/divide")
            def divide():
                try:
                    return str(int(request.args["a"]) / int(request.args["b"]))
                except Exception as e:
                    {statement}
        ''', "import traceback\n")

    def test_error_text_in_the_response(self):
        cases = {
            "return str(e), 400": ["ERR-1"],
            'return f"오류: {e}", 400': ["ERR-1"],
            "return jsonify(error=repr(e)), 400": ["ERR-1"],
            'return render_template("error.html", detail=e.args[0])': ["ERR-1"],
            "return traceback.format_exc(), 500": ["ERR-1"],
            "print(traceback.format_exc())\n                    return '오류', 500": ["ERR-2"],
            "app.logger.error(e)\n                    return '계산할 수 없어요', 400": [],
            "return '계산할 수 없어요', 400": [],
        }
        for statement, expected in cases.items():
            with self.subTest(statement):
                self.assertEqual(rules(self.handler(statement), "debug_error_exposure"), expected)

    def test_http_error_pages_may_show_the_fixed_description(self):
        """실제 학생 코드의 오탐: HTTP 오류에 미리 정해진 code·name·description은 내부 정보가 아니다."""
        safe = flask_app('''
            @app.errorhandler(404)
            @app.errorhandler(403)
            def client_error(e):
                return render_template("error.html", code=e.code, msg=e.description), e.code
        ''')
        leaking = flask_app('''
            @app.errorhandler(500)
            def server_error(e):
                return render_template("error.html", msg=str(e)), 500
        ''')
        self.assertEqual(rules(safe, "debug_error_exposure"), [])
        self.assertEqual(rules(leaking, "debug_error_exposure"), ["ERR-1"])


class HardcodedSecretTest(unittest.TestCase):
    def secret(self, statement):
        return "import os\nfrom flask import Flask\n\napp = Flask(__name__)\n" + statement + "\n"

    def test_what_counts_as_a_written_secret(self):
        cases = {
            'app.secret_key = "dev"': ["KEY-1"],
            'app.config["SECRET_KEY"] = "dev"': ["KEY-1"],
            'app.config.update(SECRET_KEY="dev")': ["KEY-1"],
            'app.secret_key = os.environ["SECRET_KEY"]': [],
            'app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")': ["KEY-3"],
            'TOKEN = os.environ.get("API_TOKEN", "")': [],  # 빈 기본값은 비밀 값이 아니다
            'DB_PASSWORD = "1234"': ["KEY-2"],
            'pw = "1234"': ["KEY-2"],
            'db = connect(passwd="1234")': ["KEY-2"],
            'ENCRYPTION_KEY = b"0123456789abcdef"': ["KEY-2"],
            'password = ""': [],
            'PW_MIN, PW_MAX = 4, 72': [],  # 숫자는 비밀 값이 아니다
            'sort_key = "created_at"': [],  # 수식어 없는 key는 비밀 이름이 아니다
            'cache_key = "posts"': [],
            'PASSWORD_FIELD = None': [],
        }
        for statement, expected in cases.items():
            with self.subTest(statement):
                self.assertEqual(rules(self.secret(statement), "hardcoded_secret"), expected)

    def test_password_compared_with_a_literal(self):
        code = flask_app('''
            @app.route("/admin", methods=["POST"])
            def admin():
                if request.form.get("password") == "admin1234":
                    return "관리자"
                if request.form["password"] == "":
                    return "비밀번호를 입력해 주세요"
                return "아니에요"
        ''')
        self.assertEqual(lines(code, "hardcoded_secret"), [("KEY-2", 8)])

    def test_comments(self):
        cases = {
            "# passwd = passw0rd": ["KEY-4"],
            "# 관리자 비밀번호: admin1234": ["KEY-4"],
            '# app.config["SECRET_KEY"] = "abc"': ["KEY-4"],
            "x = 1  # api_key: sk-test-0000": ["KEY-4"],
            "# 비밀번호 = 확인용": [],  # 실제 학생 코드의 오탐: 값이 아니라 설명이다
            "# 비밀번호: 8자 이상": [],
            "# password = request.form['password']": [],  # 주석 처리한 코드
            "# password == stored 인지 확인": [],
            "# token: required": [],
            "# 비밀번호를 해시로 바꾼다": [],
        }
        for comment, expected in cases.items():
            with self.subTest(comment):
                self.assertEqual(rules(self.secret(comment), "hardcoded_secret"), expected)


class PasswordStorageTest(unittest.TestCase):
    def signup(self, statements, imports=""):
        return flask_app(f'''
            SALT = "school-salt"


            @app.route("/signup", methods=["POST"])
            def signup():
                username = request.form["username"]
                password = request.form["password"]
                conn = sqlite3.connect("app.db")
{statements}
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, stored))
                return "가입했어요"
        ''', DB + "import hashlib\nimport os\nimport random\nimport secrets\nimport bcrypt\n"
                  "from werkzeug.security import generate_password_hash\n" + imports)

    def test_what_happens_to_the_password_before_it_is_stored(self):
        cases = {
            "stored = password": ["PW-1"],
            "stored = password.strip()": ["PW-1"],
            "stored = hashlib.md5(password.encode()).hexdigest()": ["PW-2"],
            "stored = hashlib.sha1((os.urandom(16).hex() + password).encode()).hexdigest()": ["PW-2"],
            "stored = hashlib.sha256(password.encode()).hexdigest()": ["PW-3"],
            "stored = hashlib.sha256((SALT + password).encode()).hexdigest()": ["PW-4"],
            "stored = hashlib.sha256((str(random.random()) + password).encode()).hexdigest()": ["PW-4"],
            "stored = hashlib.blake2b(password.encode()).hexdigest()": ["PW-5"],
            "stored = some_library_hash(password)": ["PW-5"],
            "stored = generate_password_hash(password)": [],
            "stored = bcrypt.hashpw(password.encode(), bcrypt.gensalt())": [],
            "stored = hashlib.sha256((secrets.token_hex(16) + password).encode()).hexdigest()": [],
            "stored = hashlib.pbkdf2_hmac('sha256', password.encode(), os.urandom(16), 600000).hex()": [],
            "stored = hashlib.pbkdf2_hmac('sha256', password.encode(), b'fixed', 600000).hex()": ["PW-4"],
        }
        for statement, expected in cases.items():
            with self.subTest(statement):
                code = self.signup("                " + statement, "from somewhere import some_library_hash\n")
                self.assertEqual(rules(code, "password_storage"), expected)

    def test_other_values_from_the_same_dict_are_not_the_password(self):
        """실제 학생 코드의 오탐: 검증 함수가 돌려준 dict에서 제목·작성자를 꺼내 저장하는 것은 비밀번호 저장이 아니다."""
        code = flask_app('''
            def execute(sql, params=()):
                conn = sqlite3.connect("board.db")
                with conn:
                    conn.execute(sql, params)


            def validate(form):
                title = form.get("title", "").strip()
                password = form.get("password", "")
                errors = [] if title else ["제목을 입력해 주세요"]
                return dict(title=title, password=password), errors


            @app.route("/new", methods=["POST"])
            def new():
                data, errors = validate(request.form)
                if errors:
                    abort(400)
                execute(
                    "INSERT INTO posts (title, password_hash) VALUES (?, ?)",
                    (data["title"], generate_password_hash(data["password"])),
                )
                return "ok"


            @app.route("/edit/<int:post_id>", methods=["POST"])
            def edit(post_id):
                data, errors = validate(request.form)
                execute("UPDATE posts SET title = ? WHERE id = ?", (data["title"], post_id))
                return "ok"
        ''', DB + "from werkzeug.security import generate_password_hash\n")
        self.assertEqual(rules(code, "password_storage"), [])
        plain = code.replace('generate_password_hash(data["password"])', 'data["password"]')
        self.assertEqual(lines(plain, "password_storage"), [("PW-1", 27)])  # 값을 묶어 넘긴 라우트의 줄

    def test_other_places_a_password_can_be_stored(self):
        code = flask_app('''
            users = {}


            class User:
                def __init__(self, name, password):
                    self.name = name
                    self.password = password


            @app.route("/signup", methods=["POST"])
            def signup():
                password = request.form["password"]
                users[request.form["username"]] = {"password": password}
                user = User(name=request.form["username"], password=password)
                user.password = password
                return "ok"
        ''')
        self.assertEqual(lines(code, "password_storage"), [("PW-1", 18), ("PW-1", 19), ("PW-1", 20)])

    def test_reading_or_checking_a_password_is_not_storing(self):
        code = flask_app('''
            @app.route("/login", methods=["POST"])
            def login():
                password = request.form["password"]
                row = sqlite3.connect("app.db").execute(
                    "SELECT password FROM users WHERE username = ? AND password = ?",
                    (request.form["username"], password),
                ).fetchone()
                return "ok" if row else "no"
        ''', DB)
        self.assertEqual(rules(code, "password_storage"), [])


class IdorTest(unittest.TestCase):
    def note(self, check, query='"SELECT body FROM notes WHERE id = ?", (note_id,)'):
        return flask_app(f'''
            def get_db():
                return sqlite3.connect("app.db")


            def login_required(view):
                @wraps(view)
                def wrapped(*args, **kwargs):
                    if "user_id" not in session:
                        return redirect(url_for("login"))
                    return view(*args, **kwargs)
                return wrapped


            def fetch_note(note_id):
                return get_db().execute({query}).fetchone()


            @app.route("/notes/<int:note_id>", methods=["GET", "POST"])
            {check}
        ''', DB + "from functools import wraps\nfrom flask import redirect, url_for\n"
                  "from werkzeug.security import check_password_hash\n")

    BODY = "def show(note_id):\n                note = fetch_note(note_id)\n"

    def test_what_was_checked_before_the_lookup(self):
        end = "                return jsonify(note)"
        cases = {
            self.BODY + end: ["IDOR-1"],
            "@login_required\n            " + self.BODY + end: ["IDOR-2"],
            self.BODY + '                if "user_id" not in session:\n                    abort(401)\n' + end: ["IDOR-2"],
            self.BODY + '                if note["user_id"] != request.args.get("user_id"):\n'
                        "                    abort(403)\n" + end: ["IDOR-3"],
            self.BODY + '                if session.get("role") != "member":\n                    abort(403)\n' + end: ["IDOR-4"],
            self.BODY + '                if note["user_id"] != session["user_id"]:\n                    abort(403)\n' + end: [],
            self.BODY + '                if session.get("role") != "admin":\n                    abort(403)\n' + end: [],
            self.BODY + '                if not session.get("is_admin"):\n                    abort(403)\n' + end: [],
            # 글에 걸린 비밀번호를 대조한 뒤에만 진행한다 (글마다 비밀번호를 두는 게시판)
            self.BODY + '                if not check_password_hash(note["password_hash"], request.form["password"]):\n'
                        "                    abort(403)\n" + end: [],
        }
        for check, expected in cases.items():
            with self.subTest(check=check):
                self.assertEqual(rules(self.note(check), "idor"), expected)

    def test_lookup_scoped_to_the_session_user_is_safe(self):
        query = '"SELECT body FROM notes WHERE id = ? AND user_id = ?", (note_id, session["user_id"])'
        code = self.note(self.BODY + "                return jsonify(note)", query)
        self.assertEqual(rules(code, "idor"), [])

    def test_lookups_that_are_not_candidates(self):
        code = flask_app('''
            @app.route("/search")
            def search():
                rows = sqlite3.connect("app.db").execute(
                    "SELECT title FROM posts WHERE title LIKE ?", (request.args.get("q", ""),)
                ).fetchall()
                return jsonify(rows)


            @app.route("/posts")
            def posts():
                page = request.args.get("page_no", 1, type=int)
                rows = sqlite3.connect("app.db").execute("SELECT title FROM posts LIMIT 10 OFFSET ?", (page,)).fetchall()
                return jsonify(rows)


            @app.route("/signup", methods=["POST"])
            def signup():
                sqlite3.connect("app.db").execute(
                    "INSERT INTO users (user_id, password) VALUES (?, ?)",
                    (request.form["user_id"], generate_password_hash(request.form["password"])),
                )
                return "ok"
        ''', DB + "from werkzeug.security import generate_password_hash\n")
        self.assertEqual(risky(code, None), {})  # 질문도 하지 않는다


class LoginAttemptTest(unittest.TestCase):
    def login(self, body, decorator="", extra=""):
        return flask_app(f'''
            MAX_FAILS = 5
            fail_counts = {{}}
            last_failed = {{}}
            {extra}


            def stored_hash(username):
                row = sqlite3.connect("app.db").execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
                return row[0] if row else ""


            @app.route("/login", methods=["POST"])
            {decorator}
            def login():
                username = request.form["username"]
                password = request.form["password"]
{body}
                return "로그인 실패", 401
        ''', DB + "import time\nfrom flask_limiter import Limiter\n"
                  "from werkzeug.security import check_password_hash\nlimiter = Limiter(key_func=lambda: 'x')\n")

    CHECK = ('                if check_password_hash(stored_hash(username), password):\n'
             '                    session["user"] = username\n'
             '                    return "로그인 성공"\n')
    LOCK = ('                if fail_counts.get(username, 0) >= MAX_FAILS:\n'
            '                    return "잠겼어요", 403\n')
    COUNT = '                fail_counts[username] = fail_counts.get(username, 0) + 1\n'

    def test_rules(self):
        cases = {
            "제한 없음": (self.CHECK, "", ["LOGIN-1"]),
            "잠금 확인 뒤 비밀번호 확인": (self.LOCK + self.CHECK + self.COUNT, "", []),
            "비밀번호를 먼저 확인": (self.CHECK + self.LOCK + self.COUNT, "", ["LOGIN-4"]),
            "20번까지 허용": (self.LOCK.replace("MAX_FAILS", "20") + self.CHECK + self.COUNT, "", ["LOGIN-2"]),
            "5번을 넘겨야 잠김": (self.LOCK.replace(">=", ">") + self.CHECK + self.COUNT, "", ["LOGIN-2"]),
            "세션에 횟수 저장": (
                '                if session.get("fails", 0) >= MAX_FAILS:\n                    return "잠겼어요", 403\n'
                + self.CHECK + '                session["fails"] = session.get("fails", 0) + 1\n', "", ["LOGIN-3"]),
            "요청 제한 모듈": (self.CHECK, '@limiter.limit("5 per minute")', []),
            "요청 제한이 너무 느슨함": (self.CHECK, '@limiter.limit("100 per minute")', ["LOGIN-2"]),
            "초 단위 제한": (self.CHECK, '@limiter.limit("5 per second")', ["LOGIN-2"]),
        }
        for label, (body, decorator, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(rules(self.login(body, decorator), "login_attempt_limit"), expected)

    def test_elapsed_time_comparison_is_not_the_limit(self):
        """실제 학생 코드: 잠금 시간이 지났는지 보는 비교(600초)를 허용 횟수로 읽으면 안 된다."""
        body = ('                if time.time() - last_failed.get(username, 0) > LOCK_SECONDS:\n'
                '                    fail_counts.pop(username, None)\n'
                + self.LOCK + self.CHECK + self.COUNT + '                last_failed[username] = time.time()\n')
        self.assertEqual(rules(self.login(body, extra="LOCK_SECONDS = 600"), "login_attempt_limit"), [])

    def test_a_password_on_each_post_is_also_an_authentication_attempt(self):
        code = flask_app('''
            def password_ok(post, password):
                return bool(password) and check_password_hash(post["password_hash"], password)


            @app.route("/post/<int:post_id>/delete", methods=["POST"])
            def delete(post_id):
                db = sqlite3.connect("board.db")
                post = db.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
                if not password_ok(post, request.form.get("password", "")):
                    abort(403)
                db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
                return "ok"
        ''', DB + "from werkzeug.security import check_password_hash\n")
        self.assertEqual(lines(code, "login_attempt_limit"), [("LOGIN-1", 14)])
        self.assertEqual(rules(code, "idor"), [])  # 글의 비밀번호를 대조한 뒤에만 지운다

    def test_routes_that_do_not_check_a_password_are_ignored(self):
        code = flask_app('''
            @app.route("/signup", methods=["POST"])
            def signup():
                if request.form["password"] != request.form["confirm"]:
                    return "비밀번호가 서로 달라요", 400
                return "ok"
        ''')
        self.assertEqual(rules(code, "login_attempt_limit"), [])


class ReportLineTest(unittest.TestCase):
    """스펙 3.4: 값을 마지막으로 만든 함수가 도착점까지 넘긴 줄을 보고한다."""

    def test_query_built_in_the_route_and_run_by_a_helper(self):
        code = flask_app('''
            def run(sql, params=()):
                return sqlite3.connect("app.db").execute(sql, params).fetchall()


            @app.route("/search")
            def search():
                name = request.args.get("name", "")
                sql = "SELECT * FROM t WHERE name = '" + name + "'"
                return jsonify(run(sql))
        ''', DB)
        self.assertEqual(lines(code, "sql_injection"), [("SQL-1", 16)])  # 도우미를 부른 줄

    def test_query_built_inside_the_helper(self):
        code = flask_app('''
            def find(name):
                return sqlite3.connect("app.db").execute("SELECT * FROM t WHERE name = '" + name + "'").fetchall()


            @app.route("/search")
            def search():
                return jsonify(find(request.args.get("name", "")))
        ''', DB)
        self.assertEqual(lines(code, "sql_injection"), [("SQL-1", 9)])  # 문장을 이어 붙인 도우미 안의 줄

    def test_same_helper_reached_from_two_routes(self):
        code = flask_app('''
            def run(sql):
                return sqlite3.connect("app.db").execute(sql).fetchall()


            @app.route("/a")
            def a():
                return jsonify(run("SELECT 1 WHERE x = '" + request.args["x"] + "'"))


            @app.route("/b")
            def b():
                return jsonify(run("SELECT 1 WHERE y = '" + request.args["y"] + "'"))
        ''', DB)
        self.assertEqual(lines(code, "sql_injection"), [("SQL-1", 14), ("SQL-1", 19)])


class WholeFileTest(unittest.TestCase):
    """기능이 많은 안전한 파일 하나에서 아무것도 걸리지 않는지."""

    SAFE_BOARD = '''import os
import sqlite3
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg"}
ALLOWED_TYPES = {"image/png", "image/jpeg"}
MAX_FAILS = 5
fail_counts = {}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(os.getenv("DB_PATH", "board.db"))
    return g.db


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    if fail_counts.get(username, 0) >= MAX_FAILS:
        return "잠겼어요", 403
    row = get_db().execute("SELECT id, password FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not check_password_hash(row[1], request.form["password"]):
        fail_counts[username] = fail_counts.get(username, 0) + 1
        return "아이디 또는 비밀번호가 올바르지 않아요", 401
    fail_counts.pop(username, None)
    session.clear()
    session["user_id"] = row[0]
    return redirect(url_for("index"))


@app.route("/signup", methods=["POST"])
def signup():
    get_db().execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (request.form["username"], generate_password_hash(request.form["password"])),
    )
    return redirect(url_for("login"))


@app.route("/")
def index():
    keyword = request.args.get("q", "")
    where, args = "", []
    if keyword:
        where = "WHERE title LIKE ?"
        args = [f"%{keyword}%"]
    posts = get_db().execute(f"SELECT id, title FROM posts {where} ORDER BY id DESC", args).fetchall()
    return render_template("index.html", posts=posts)


@app.route("/edit/<int:post_id>", methods=["POST"])
@login_required
def edit(post_id):
    post = get_db().execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if post is None:
        abort(404)
    if post["user_id"] != session["user_id"]:
        abort(403)
    get_db().execute("UPDATE posts SET title = ? WHERE id = ? AND user_id = ?",
                     (request.form["title"], post_id, session["user_id"]))
    file = request.files.get("image")
    if file:
        extension = file.filename.rsplit(".", 1)[-1].lower()
        if extension not in ALLOWED_EXTENSIONS or file.mimetype not in ALLOWED_TYPES:
            abort(400)
        file.save(os.path.join("uploads", secure_filename(file.filename)))
    flash("고쳤어요")
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", message=e.description), 404


@app.errorhandler(Exception)
def server_error(e):
    app.logger.exception("서버 오류")
    return render_template("error.html", message="서버 오류가 발생했어요"), 500


if __name__ == "__main__":
    app.run(debug=False)
'''

    def test_nothing_is_flagged_and_nothing_is_asked(self):
        self.assertEqual(risky(self.SAFE_BOARD, None), {})
        self.assertEqual(risky(self.SAFE_BOARD, ALL_PRIVATE), {})


if __name__ == "__main__":
    unittest.main()
