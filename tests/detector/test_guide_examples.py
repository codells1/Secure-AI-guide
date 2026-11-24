"""Python 시큐어코딩 가이드(2023년 개정본)의 예제로 판정 기준을 확인한다 (detection_spec 4장).

가이드의 예제는 대부분 Django로 적혀 있어서, 같은 흐름을 Flask로 옮겼다
(`request.POST.get` → `request.form.get`, `render` → `render_template`).
"안전하지 않은 코드 예시"는 그 규칙에 걸리고, "안전한 코드 예시"는 그 취약점이 안전이어야 한다.

실행: python -m unittest discover -s tests -t .
"""
import unittest

from tests.detector.helpers import flask_app, rules

DB = "import sqlite3\n"


class SqlInjectionGuideTest(unittest.TestCase):
    """입력데이터 검증 및 표현 1. SQL 삽입 (p.8~13)."""

    def test_string_concatenation_is_unsafe(self):  # p.10
        code = flask_app('''
            @app.route("/board", methods=["POST"])
            def update_board():
                dbconn = sqlite3.connect("board.db")
                curs = dbconn.cursor()
                name = request.form.get("name", "")
                content_id = request.form.get("content_id", "")
                sql_query = "update board set name='" + name + "' where content_id='" + content_id + "'"
                curs.execute(sql_query)
                dbconn.commit()
                return render_template("success.html")
        ''', DB)
        self.assertEqual(rules(code, "sql_injection"), ["SQL-1"])

    def test_bound_parameters_are_safe(self):  # p.11
        code = flask_app('''
            @app.route("/board", methods=["POST"])
            def update_board():
                dbconn = sqlite3.connect("board.db")
                curs = dbconn.cursor()
                name = request.form.get("name", "")
                content_id = request.form.get("content_id", "")
                sql_query = "update board set name=%s where content_id=%s"
                curs.execute(sql_query, (name, content_id))
                dbconn.commit()
                return render_template("success.html")
        ''', DB)
        self.assertEqual(rules(code, "sql_injection"), [])

    def test_raw_query_built_from_input_is_unsafe_and_bound_is_safe(self):  # p.12
        unsafe = flask_app('''
            @app.route("/members", methods=["POST"])
            def member_search():
                name = request.form.get("name", "")
                query = "select * from member where name='" + name + "'"
                data = Member.objects.raw(query)
                return render_template("member_list.html", member_list=data)
        ''', "from models import Member\n")
        safe = unsafe.replace('"select * from member where name=\'" + name + "\'"',
                              '"select * from member where name=%s"').replace("raw(query)", "raw(query, [name])")
        self.assertEqual(rules(unsafe, "sql_injection"), ["SQL-1"])
        self.assertEqual(rules(safe, "sql_injection"), [])


class OsCommandGuideTest(unittest.TestCase):
    """입력데이터 검증 및 표현 5. 운영체제 명령어 삽입 (p.29~32)."""

    def test_os_system_with_input_is_unsafe(self):  # p.30
        code = flask_app('''
            @app.route("/run", methods=["POST"])
            def execute_command():
                app_name_string = request.form.get("app_name", "")
                os.system(app_name_string)
                return render_template("success.html")
        ''', "import os\n")
        self.assertEqual(rules(code, "os_command_injection"), ["CMD-1"])

    def test_allow_list_makes_os_system_safe(self):  # p.30
        code = flask_app('''
            ALLOW_PROGRAM = ["notepad", "calc"]


            @app.route("/run", methods=["POST"])
            def execute_command():
                app_name_string = request.form.get("app_name", "")
                if app_name_string not in ALLOW_PROGRAM:
                    return render_template("error.html", error="허용되지 않은 프로그램입니다.")
                os.system(app_name_string)
                return render_template("success.html")
        ''', "import os\n")
        self.assertEqual(rules(code, "os_command_injection"), [])

    def test_subprocess_shell_with_input_is_unsafe(self):  # p.31
        code = flask_app('''
            @app.route("/backup", methods=["POST"])
            def execute_command():
                date = request.form.get("date", "")
                cmd_str = "cmd /c backuplog.bat " + date
                subprocess.run(cmd_str, shell=True)
                return render_template("success.html")
        ''', "import subprocess\n")
        self.assertEqual(rules(code, "os_command_injection"), ["CMD-1"])

    def test_filtered_list_arguments_without_shell_are_safe(self):  # p.32
        code = flask_app('''
            @app.route("/backup", methods=["POST"])
            def execute_command():
                date = request.form.get("date", "")
                for word in ["|", ";", "&", ":", ">", "<", "`", "\\\\", "!"]:
                    date = date.replace(word, "")
                subprocess.run(["cmd", "/c", "backuplog.bat", date])
                return render_template("success.html")
        ''', "import subprocess\n")
        self.assertEqual(rules(code, "os_command_injection"), [])

    def test_re_sub_filter_from_the_guide_comment_is_safe(self):  # p.32의 주석: re.sub로 지우는 방법
        code = flask_app('''
            @app.route("/backup", methods=["POST"])
            def execute_command():
                date = re.sub("[|;&:><`\\\\\\\\!]", "", request.form.get("date", ""))
                subprocess.run(["cmd", "/c", "backuplog.bat", date])
                return render_template("success.html")
        ''', "import re\nimport subprocess\n")
        self.assertEqual(rules(code, "os_command_injection"), [])


class FileUploadGuideTest(unittest.TestCase):
    """입력데이터 검증 및 표현 6. 위험한 형식 파일 업로드 (p.33~35)."""

    def test_saving_without_checks_is_unsafe(self):  # p.34
        code = flask_app('''
            @app.route("/upload", methods=["POST"])
            def file_upload():
                upload_file = request.files["upload_file"]
                upload_file.save(os.path.join("media/screenshot", secure_filename(upload_file.filename)))
                return render_template("success.html")
        ''', "import os\nfrom werkzeug.utils import secure_filename\n")
        self.assertEqual(rules(code, "file_upload"), ["UP-1", "UP-2"])

    def test_type_and_extension_checks_are_safe(self):  # p.34~35
        code = flask_app('''
            FILE_COUNT_LIMIT = 5
            FILE_SIZE_LIMIT = 5242880
            WHITE_LIST_EXT = [".jpg", ".jpeg"]


            @app.route("/upload", methods=["POST"])
            def file_upload():
                if len(request.files) == 0 or len(request.files) > FILE_COUNT_LIMIT:
                    return render_template("error.html", error="파일 개수 초과")
                for upload_file in request.files.values():
                    if upload_file.content_type != "image/jpeg":
                        return render_template("error.html", error="파일 타입 오류")
                    if upload_file.content_length > FILE_SIZE_LIMIT:
                        return render_template("error.html", error="파일사이즈 오류")
                    file_name, file_ext = os.path.splitext(upload_file.filename)
                    if file_ext.lower() not in WHITE_LIST_EXT:
                        return render_template("error.html", error="파일 타입 오류")
                    upload_file.save(os.path.join("media/screenshot", secure_filename(upload_file.filename)))
                return render_template("success.html")
        ''', "import os\nfrom werkzeug.utils import secure_filename\n")
        self.assertEqual(rules(code, "file_upload"), [])


class PathTraversalGuideTest(unittest.TestCase):
    """입력데이터 검증 및 표현 3. 경로 조작 및 자원 삽입 (p.18~21)."""

    UNSAFE = '''
        @app.route("/info", methods=["POST"])
        def get_info():
            request_file = request.form.get("request_file")
            (filename, file_ext) = os.path.splitext(request_file)
            file_ext = file_ext.lower()
            if file_ext not in [".txt", ".csv"]:
                return render_template("error.html", error="파일을 열 수 없습니다.")
            with open(request_file) as f:
                data = f.read()
            return render_template("success.html", data=data)
    '''

    def test_extension_check_alone_is_unsafe(self):  # p.19
        self.assertEqual(rules(flask_app(self.UNSAFE, "import os\n"), "path_traversal"), ["PATH-1"])

    def test_removing_path_characters_is_safe(self):  # p.19~20
        code = flask_app('''
            @app.route("/info", methods=["POST"])
            def get_info():
                request_file = request.form.get("request_file")
                (filename, file_ext) = os.path.splitext(request_file)
                file_ext = file_ext.lower()
                if file_ext not in [".txt", ".csv"]:
                    return render_template("error.html", error="파일을 열 수 없습니다.")
                filename = filename.replace(".", "")
                filename = filename.replace("/", "")
                filename = filename.replace("\\\\", "")
                try:
                    with open(filename + file_ext) as f:
                        data = f.read()
                except OSError:
                    return render_template("error.html", error="파일이 존재하지 않거나 열 수 없는 파일입니다.")
                return render_template("success.html", data=data)
        ''', "import os\n")
        self.assertEqual(rules(code, "path_traversal"), [])


class SsrfGuideTest(unittest.TestCase):
    """입력데이터 검증 및 표현 12. 서버사이드 요청 위조 (p.55~57)."""

    def test_request_to_an_input_address_is_unsafe(self):  # p.56
        code = flask_app('''
            @app.route("/call", methods=["POST"])
            def call_third_party_api():
                addr = request.form.get("address", "")
                result = requests.get(addr).text
                return render_template("result.html", result=result)
        ''', "import requests\n")
        self.assertEqual(rules(code, "ssrf"), ["SSRF-1"])

    def test_allow_listed_address_is_safe(self):  # p.57
        code = flask_app('''
            ALLOW_SERVER_LIST = [
                "https://127.0.0.1/latest/",
                "https://192.168.0.1/user_data",
                "https://192.168.0.100/v1/public",
            ]


            @app.route("/call", methods=["POST"])
            def call_third_party_api():
                addr = request.form.get("address", "")
                if addr not in ALLOW_SERVER_LIST:
                    return render_template("error.html", error="허용되지 않은 서버입니다.")
                result = requests.get(addr).text
                return render_template("result.html", result=result)
        ''', "import requests\n")
        self.assertEqual(rules(code, "ssrf"), [])


class AuthorizationGuideTest(unittest.TestCase):
    """보안기능 2. 부적절한 인가 (p.72~74)."""

    UNSAFE = '''
        @app.route("/content/delete", methods=["POST"])
        def delete_content():
            action = request.form.get("action", "")
            content_id = request.form.get("content_id", "")
            if action is not None and action == "delete":
                sqlite3.connect("app.db").execute("DELETE FROM content WHERE id = ?", (content_id,))
                return render_template("success.html")
            else:
                return render_template("error.html", error="접근 권한이 없습니다.")
    '''

    def test_delete_without_a_permission_check_is_unsafe(self):  # p.73
        self.assertEqual(rules(flask_app(self.UNSAFE, DB), "idor"), ["IDOR-1"])

    def test_login_and_permission_check_is_safe(self):  # p.73: login_required + permission_required
        code = flask_app(self.UNSAFE.replace(
            '    action = request.form.get("action", "")',
            '    if "user_id" not in session:\n'
            '                abort(401)\n'
            '            if session.get("role") != "admin":\n'
            '                abort(403)\n'
            '            action = request.form.get("action", "")',
        ), DB)
        self.assertEqual(rules(code, "idor"), [])


class DebugAndErrorGuideTest(unittest.TestCase):
    """캡슐화 2. 제거되지 않고 남은 디버그 코드 (p.146~149), 에러처리 1. 오류 메시지 정보노출 (p.125~128)."""

    def test_flask_debug_true_is_unsafe(self):  # p.148
        code = (
            "from flask import Flask\n\napp = Flask(__name__)\napp.debug = True\n\n\n"
            "@app.route('/')\ndef hello_world():\n    return 'Hello World!'\n\n\n"
            "if __name__ == '__main__':\n    app.run()\n    app.run(debug=True)\n"
        )
        self.assertEqual(rules(code, "debug_error_exposure"), ["DBG-1"])
        self.assertEqual(rules(code.replace("True", "False"), "debug_error_exposure"), [])

    def test_printing_the_traceback_is_unsafe_and_logging_is_safe(self):  # p.127~128
        unsafe = flask_app('''
            def fetch_url(url, useragent):
                try:
                    response = requests.get(url, stream=True, timeout=5, headers={"User-Agent": useragent})
                    return response
                except IOError:
                    traceback.print_exc()
        ''', "import logging\nimport traceback\nimport requests\n")
        safe = unsafe.replace("traceback.print_exc()", "logging.error('ERROR-01: 통신에러')")
        self.assertEqual(rules(unsafe, "debug_error_exposure"), ["ERR-2"])
        self.assertEqual(rules(safe, "debug_error_exposure"), [])


class HardcodedSecretGuideTest(unittest.TestCase):
    """보안기능 6. 하드코드된 중요정보 (p.85~87), 13. 주석문 안에 포함된 시스템 주요정보 (p.109~110)."""

    def test_password_in_connect_is_unsafe(self):  # p.86
        code = flask_app('''
            def query_execute(query):
                dbconn = pymysql.connect(
                    host="127.0.0.1",
                    port="1234",
                    user="root",
                    passwd="1234",
                    db="mydb",
                    charset="utf8",
                )
                curs = dbconn.cursor()
                curs.execute(query)
                dbconn.commit()
                dbconn.close()
        ''', "import pymysql\n")
        self.assertEqual(rules(code, "hardcoded_secret"), ["KEY-2"])

    def test_values_read_from_a_config_file_are_safe(self):  # p.87
        code = flask_app('''
            def query_execute(query, config_path):
                with open(config_path, "r") as config:
                    dbconf = json.load(fp=config)
                    block_key = get_decrypt_key(dbconf["blockKey"])
                    db_user = decrypt(block_key, dbconf["user"])
                    db_passwd = decrypt(block_key, dbconf["passwd"])
                dbconn = pymysql.connect(
                    host=dbconf["host"], port=dbconf["port"], user=db_user, passwd=db_passwd,
                    db=dbconf["db_name"], charset="utf8",
                )
                curs = dbconn.cursor()
                curs.execute(query)
                dbconn.commit()
                dbconn.close()
        ''', "import json\nimport pymysql\nfrom crypto_util import decrypt, get_decrypt_key\n")
        self.assertEqual(rules(code, "hardcoded_secret"), [])

    def test_credentials_in_a_comment_are_unsafe(self):  # p.109~110
        unsafe = flask_app('''
            def user_login(id, passwd):
                # 주석문에 포함된 중요 시스템의 인증 정보
                # id = admin
                # passwd = passw0rd
                result = login(id, passwd)
                return result
        ''', "from auth import login\n")
        safe = unsafe.replace("    # id = admin\n", "").replace("    # passwd = passw0rd\n", "")
        self.assertEqual(rules(unsafe, "hardcoded_secret"), ["KEY-4"])
        self.assertEqual(rules(safe, "hardcoded_secret"), [])


class PasswordStorageGuideTest(unittest.TestCase):
    """보안기능 5. 암호화되지 않은 중요정보 (p.81~82), 4. 취약한 암호화 알고리즘 (p.80), 14. 솔트 (p.111~112)."""

    def test_storing_the_password_as_is_is_unsafe(self):  # p.82
        code = flask_app('''
            def update_pass(dbconn, password, user_id):
                curs = dbconn.cursor()
                curs.execute("UPDATE USERS SET PASSWORD= %s WHERE USER_ID= %s", (password, user_id))
                dbconn.commit()
        ''')
        self.assertEqual(rules(code, "password_storage"), ["PW-1"])

    def test_salted_sha256_from_the_guide_is_safe(self):  # p.82
        code = flask_app('''
            def update_pass(dbconn, password, user_id, salt):
                hash_obj = SHA256.new()
                hash_obj.update(bytes(password + salt, "utf-8"))
                hash_pwd = hash_obj.hexdigest()
                curs = dbconn.cursor()
                curs.execute("UPDATE USERS SET PASSWORD= %s WHERE USER_ID= %s", (hash_pwd, user_id))
                dbconn.commit()
        ''', "from Crypto.Hash import SHA256\n")
        self.assertEqual(rules(code, "password_storage"), [])

    STORE = '''
        def save_password(dbconn, user_id, pw):
            hashed = get_hash_from_pwd(pw)
            dbconn.execute("UPDATE USERS SET PASSWORD = ? WHERE USER_ID = ?", (hashed, user_id))
    '''

    def test_md5_is_unsafe(self):  # p.80
        code = flask_app('''
            def get_hash_from_pwd(pw):
                return hashlib.md5(pw.encode("utf-8")).hexdigest()
        ''', "import hashlib\n", self.STORE)
        self.assertEqual(rules(code, "password_storage"), ["PW-2"])

    def test_hash_without_salt_is_unsafe(self):  # p.111
        code = flask_app('''
            def get_hash_from_pwd(pw):
                h = hashlib.sha256(pw.encode())
                return h.digest()
        ''', "import hashlib\n", self.STORE)
        self.assertEqual(rules(code, "password_storage"), ["PW-3"])

    def test_hash_with_a_random_salt_is_safe(self):  # p.112
        code = flask_app('''
            def get_hash_from_pwd(pw):
                salt = secrets.token_hex(32)
                h = hashlib.sha256(salt.encode() + pw.encode())
                return h.digest(), salt


            def save_password(dbconn, user_id, pw):
                hashed, salt = get_hash_from_pwd(pw)
                dbconn.execute("UPDATE USERS SET PASSWORD = ?, SALT = ? WHERE USER_ID = ?", (hashed, salt, user_id))
        ''', "import hashlib\nimport secrets\n")
        self.assertEqual(rules(code, "password_storage"), [])


class LoginAttemptGuideTest(unittest.TestCase):
    """보안기능 16. 반복된 인증시도 제한 기능 부재 (p.116~118)."""

    HELPERS = '''
        def db():
            return sqlite3.connect("app.db")


        def get_user_pw(user_id):
            row = db().execute("SELECT password FROM users WHERE user_id = ?", (user_id,)).fetchone()
            return row[0] if row else None
    '''

    def test_login_without_a_limit_is_unsafe(self):  # p.117
        code = flask_app(self.HELPERS, "import hashlib\nimport sqlite3\n", '''
            @app.route("/login", methods=["POST"])
            def login():
                user_id = request.form.get("user_id", "")
                user_pw = request.form.get("user_pw", "")
                sha = hashlib.sha256()
                sha.update(user_pw.encode("utf-8"))
                hashed_passwd = get_user_pw(user_id)
                if sha.hexdigest() == hashed_passwd:
                    return render_template("index.html", state="login_success")
                else:
                    return render_template("login.html", state="login_failed")
        ''')
        self.assertEqual(rules(code, "login_attempt_limit"), ["LOGIN-1"])

    LIMITED = '''
        LOGIN_TRY_LIMIT = 5


        def fail_count(user_id):
            row = db().execute("SELECT count FROM login_fail WHERE user_id = ?", (user_id,)).fetchone()
            return row[0] if row else 0


        @app.route("/login", methods=["POST"])
        def login():
            user_id = request.form.get("user_id", "")
            user_pw = request.form.get("user_pw", "")
            sha = hashlib.sha256()
            sha.update(user_pw.encode("utf-8"))
            hashed_passwd = get_user_pw(user_id)
            {body}
    '''

    def test_counting_failures_with_a_limit_of_five_is_accepted(self):  # p.117~118의 횟수 제한
        """잠금 확인을 먼저 하도록 순서만 바꾼 것. 횟수를 DB에 적고 5회로 제한하면 안전이다."""
        body = '''count = fail_count(user_id)
            if count >= LOGIN_TRY_LIMIT:
                return render_template("account_lock.html", state="account_lock")
            if sha.hexdigest() == hashed_passwd:
                db().execute("DELETE FROM login_fail WHERE user_id = ?", (user_id,))
                return render_template("index.html", state="login_success")
            db().execute("REPLACE INTO login_fail (user_id, count) VALUES (?, ?)", (user_id, count + 1))
            return render_template("login.html", state="login_failed")'''
        code = flask_app(self.HELPERS + self.LIMITED.format(body=body), "import hashlib\nimport sqlite3\n")
        self.assertEqual(rules(code, "login_attempt_limit"), [])

    def test_the_guide_example_checks_the_password_before_the_lock(self):  # p.117~118 그대로
        """가이드의 안전한 예제는 비밀번호가 맞으면 잠긴 계정도 통과시킨다.

        가이드 본문(p.116)은 횟수를 넘으면 계정을 잠그라고 하므로 LOGIN-4로 본다 (detection_spec 4.10).
        횟수 제한 자체는 있으므로 LOGIN-1·2·3은 나오지 않는다.
        """
        body = '''if sha.hexdigest() == hashed_passwd:
                db().execute("DELETE FROM login_fail WHERE user_id = ?", (user_id,))
                return render_template("index.html", state="login_success")
            count = fail_count(user_id)
            if count >= LOGIN_TRY_LIMIT:
                return render_template("account_lock.html", state="account_lock")
            db().execute("REPLACE INTO login_fail (user_id, count) VALUES (?, ?)", (user_id, count + 1))
            return render_template("login.html", state="login_failed")'''
        code = flask_app(self.HELPERS + self.LIMITED.format(body=body), "import hashlib\nimport sqlite3\n")
        self.assertEqual(rules(code, "login_attempt_limit"), ["LOGIN-4"])


if __name__ == "__main__":
    unittest.main()
