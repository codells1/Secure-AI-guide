"""3단계: 수정 규칙 카드 (fix_spec 5장, 3부 해결법 표).

실행: python -m unittest discover -s tests -t .
"""
import ast
import json
import unittest

from detector import analyze
from detector.result import MESSAGES, SAFE
from detector.rules import RULES
from fixer.cards import RULES_DIR, CardError, card_files, card_problems, load_card, rule_ids_of

# IDOR은 학생이 답해야 판정한다. 후보 라우트를 모두 "본인만 봐야 한다"고 답한 상태로 검사한다.
USER_INPUT = {"idor": {"public_functions": []}}

# 3부 해결법 표 (fix_methods v1.1). 강조 표시(**)만 빼고 그대로 옮긴 것.
# (규칙들, 이렇게 고친다, 이렇게 고치면 안 된다, 근거, 쪽)
TABLE = [
    (("SQL-1", "SQL-3"),
     "SQL 문장은 고정하고, 값은 `?`(PyMySQL은 `%s`) 자리로 `execute()`의 두 번째 인자에 넘긴다",
     "따옴표 제거·필터 후 이어 붙이기", "KISA 「SQL 삽입」", "9~11"),
    (("SQL-2",),
     "`ORDER BY` 값은 ① 상수 dict에서 꺼내거나 ② 상수 목록에 없으면 중단하거나 ③ `\"ASC\" if … else \"DESC\"`",
     "입력값을 그대로 이어 붙이기", "OWASP SQL Injection Prevention Cheat Sheet", ""),
    (("CMD-1",),
     "입력값이 상수 허용 목록에 없으면 중단하거나, 특수문자를 모두 지운 뒤 `shell=True` 없이 명령과 인자를 리스트로 넘긴다",
     "입력값을 그대로 명령어에 이어 붙이기, 특수문자 일부만 지우기", "KISA 「운영체제 명령어 삽입」", "29~32"),
    (("CMD-2",),
     "`shell=True`를 지우고 명령과 인자를 리스트로 넘긴다, 또는 입력값이 상수 허용 목록에 없으면 중단한다",
     "특수문자만 지우고 `shell=True`는 그대로 두기", "KISA 「운영체제 명령어 삽입」", "29~32"),
    (("UP-1", "UP-2"),
     "`save()` 전에 ① 확장자 허용 목록과 ② Content-Type 허용 목록을 둘 다 확인하고, 실패하면 중단",
     "`\"jpg\" in filename`, 확장자만 검사(Flask 공식 예시), `mimetype.startswith(\"image/\")`",
     "KISA 「위험한 형식 파일 업로드」", "33"),
    (("PATH-1",),
     "`secure_filename()`을 거치거나, `send_from_directory(고정 폴더, 이름)`을 쓰거나, `.`, `/`, `\\` 세 문자를 모두 제거",
     "`basename()`, `realpath`+`commonpath`, 직접 만든 필터",
     "KISA 「경로 조작 및 자원 삽입」, Flask 공식 문서", ""),
    (("IDOR-1", "IDOR-2", "IDOR-3", "IDOR-4"),
     "세션 사용자와 글의 소유자 필드를 비교해 다르면 `abort(403)`, 또는 `WHERE … AND user_id = 세션값`, 또는 세션 기반 관리자 확인",
     "`@login_required`나 세션에 로그인 값이 있는지만 확인하기, 쿠키·요청값과 비교, UUID로 숨기기",
     "OWASP Insecure Direct Object Reference Prevention Cheat Sheet, KISA 「부적절한 인가」", ""),
    (("SSRF-1",),
     "상수 URL 허용 목록과 정확히 비교하고 없으면 중단, 또는 입력은 키로만 쓰고 URL은 상수 dict에서 꺼냄",
     "도메인 비교, `startswith`, 블랙리스트", "KISA 「서버사이드 요청 위조」", ""),
    (("DBG-1", "DBG-2"),
     "`debug` 인자를 지우거나 `debug=False`로 고정",
     "환경변수로 켜고 끄기", "Flask 공식 문서, KISA 「제거되지 않고 남은 디버그 코드」", ""),
    (("ERR-1", "ERR-2"),
     "오류가 나면 정해 둔 안내 문구만 돌려주고, traceback 출력은 지움",
     "`return str(e)`", "KISA 「오류 메시지 정보노출」", ""),
    (("KEY-1", "KEY-2", "KEY-3"),
     "`os.environ[\"X\"]` 또는 기본값 없는 `os.getenv(\"X\")`",
     "`os.getenv(\"X\", \"비밀값\")`", "KISA 「하드코드된 중요정보」", ""),
    (("KEY-4",),
     "주석 속 비밀번호·키를 지움", "", "KISA 「주석문 안에 포함된 시스템 주요정보」", ""),
    (("PW-1", "PW-2", "PW-3", "PW-4", "PW-5"),
     "`generate_password_hash(pw)` (Flask에 포함된 Werkzeug, 가장 간단), 또는 bcrypt·argon2 기본값, "
     "또는 SHA-256·PBKDF2 + 함수 안에서 `os.urandom`·`secrets`로 만든 솔트",
     "MD5·SHA-1, 솔트 없는 해시, 고정 솔트, `random` 솔트, 목록에 없는 해시 방식(`blake2b`, passlib 등)",
     "KISA 「솔트 없이 일방향 해시 함수 사용」「취약한 암호화 알고리즘 사용」「적절하지 않은 난수 값 사용」, "
     "OWASP Password Storage Cheat Sheet", ""),
    (("LOGIN-1", "LOGIN-2", "LOGIN-3", "LOGIN-4"),
     "① 실패 횟수를 DB나 전역 dict에 저장하고, 5회 이하로 제한하고, 비밀번호 확인보다 먼저 잠금 확인, "
     "또는 ② `@limiter.limit(\"5 per minute\")`",
     "세션·쿠키에 횟수 저장, 비밀번호를 먼저 확인(KISA 예시 구조), 6회 이상 허용, 초 단위 제한(`5 per second`)",
     "KISA 「반복된 인증시도 제한 기능 부재」, 개인정보의 안전성 확보조치 기준 제5조⑥", ""),
]


def raw_rules():
    """(vuln_id, rule_id, 카드 원본)을 파일에 적힌 순서대로."""
    for vuln_id in card_files():
        data = json.loads((RULES_DIR / f"{vuln_id}.json").read_text(encoding="utf-8"))
        for rule_id, rule in data["rules"].items():
            yield vuln_id, rule_id, rule


def risky(code):
    """위험이거나 아직 판정하지 못한 항목: vuln_id → rule_id들."""
    result = analyze(code, USER_INPUT)
    assert result["ok"], "예시 코드에 문법 오류가 있다"
    return {
        item["vuln_id"]: {finding["rule_id"] for finding in item["findings"]}
        for item in result["results"]
        if item["verdict"] != SAFE
    }


class CardFilesTest(unittest.TestCase):
    def test_every_detector_rule_has_a_card(self):
        self.assertEqual(sorted(rule_id for _, rule_id, _ in raw_rules()), sorted(MESSAGES))
        self.assertEqual(len(MESSAGES), 30)

    def test_file_names_are_the_detector_vuln_ids(self):
        self.assertEqual(card_files(), sorted(rule.VULN_ID for rule in RULES))

    def test_format(self):
        for vuln_id in card_files():
            data = json.loads((RULES_DIR / f"{vuln_id}.json").read_text(encoding="utf-8"))
            self.assertEqual(card_problems(data, vuln_id), [], vuln_id)
        for _, rule_id, rule in raw_rules():
            with self.subTest(rule_id):
                self.assertIs(rule["_review"], True)  # 초안: 팀 검토 필요

    def test_references_show_what_the_source_says(self):
        """근거 자료: 쪽수만이 아니라 근거 문서의 실제 문장과 쉬운 풀이가 있다."""
        for _, rule_id, rule in raw_rules():
            reference = rule["reference"]
            with self.subTest(rule_id):
                self.assertGreater(len(reference["excerpt"]), 20)
                where = reference["excerpt_source"]
                # 화면에 보여 주는 문장과 출처는 우리말이다 (영어 문장이 그대로 나가지 않는다)
                self.assertTrue(reference["excerpt"].endswith("다."), reference["excerpt"])
                self.assertNotRegex(where + " " + reference["excerpt"], r"[A-Za-z]+(?: [A-Za-z]+){3}")
                if where.startswith("KISA"):
                    self.assertRegex(where, r"^KISA Python 시큐어코딩 가이드\(2023년 개정본\) 「.+」 \d+쪽$")
                    self.assertNotIn("excerpt_original", reference)  # 원문 그대로다
                else:
                    # 영어 문서: 우리말로 옮긴 문장을 보여 주고, 영어 원문과 그 위치를 카드에 남긴다
                    self.assertRegex(where, r"^OWASP 「.+ 방지 안내서」의 '.+' 부분$")
                    self.assertRegex(reference["excerpt_original_source"], r"^OWASP .+ Cheat Sheet, '.+'$")
                    self.assertTrue(reference["excerpt_original"].isascii() and reference["excerpt_original"].endswith("."))
                # 쉬운 풀이는 설명 작성 규칙과 같다: 1~2문장 해요체, 괄호 풀이 없음
                easy = reference["easy"]
                self.assertTrue(easy.endswith("요."), easy)
                self.assertIn(easy.count("요."), (1, 2), easy)
                self.assertNotRegex(easy, r"\([^)]*[가-힣][^)]*\)")

    def test_fixes_and_references_match_the_methods_table(self):
        expected = {}
        for rule_ids, allowed, forbidden, source, pages in TABLE:
            for rule_id in rule_ids:
                expected[rule_id] = ([allowed], [forbidden] if forbidden else [], source, pages)
        self.assertEqual(sorted(expected), sorted(MESSAGES))
        for _, rule_id, rule in raw_rules():
            with self.subTest(rule_id):
                reference = rule["reference"]
                actual = (rule["allowed_fixes"], rule["forbidden_fixes"], reference["source"], reference["pages"])
                self.assertEqual(actual, expected[rule_id])


class FallbackExampleTest(unittest.TestCase):
    """작업 지시 4.3: before는 그 rule_id가 나오고, after는 10종 모두 안전, 40줄 이내."""

    def test_before_raises_the_rule_and_after_is_safe(self):
        for vuln_id, rule_id, rule in raw_rules():
            with self.subTest(rule_id):
                example = rule["fallback_example"]
                self.assertIn(rule_id, risky(example["before"]).get(vuln_id, set()))
                self.assertEqual(risky(example["after"]), {})

    def test_examples_are_short_flask_snippets(self):
        for _, rule_id, rule in raw_rules():
            for label, code in rule["fallback_example"].items():
                with self.subTest(f"{rule_id} {label}"):
                    ast.parse(code)
                    self.assertLessEqual(len(code.splitlines()), 40)
                    self.assertIn("Flask(__name__)", code)
                    self.assertNotEqual(rule["fallback_example"]["before"], rule["fallback_example"]["after"])


class FallbackExplanationTest(unittest.TestCase):
    """설명 작성 규칙 (feedback_ui_task 4장): 1~2문장 해요체, 괄호 풀이 없음."""

    def test_one_or_two_plain_sentences(self):
        for _, rule_id, rule in raw_rules():
            for key, text in rule["fallback_explanation"].items():
                with self.subTest(f"{rule_id} {key}"):
                    self.assertTrue(text.endswith("요."), text)
                    self.assertIn(text.count("요."), (1, 2), text)  # 1~2문장
                    self.assertNotRegex(text, r"\([^)]*[가-힣][^)]*\)", text)  # 괄호로 용어를 풀이하지 않는다
                    self.assertNotIn("\n", text)
                    self.assertNotIn("`", text)  # 화면에 글자 그대로 넣는다


class ConceptTest(unittest.TestCase):
    """용어 풀이 (feedback_ui_task 3장): 취약점마다 1~2개, 팀이 쓴 고정 문장."""

    def test_every_vulnerability_has_reviewable_concepts(self):
        for vuln_id in card_files():
            data = json.loads((RULES_DIR / f"{vuln_id}.json").read_text(encoding="utf-8"))
            with self.subTest(vuln_id):
                self.assertIn(len(data["concept"]), (1, 2))
                covered = set()
                for item in data["concept"]:
                    self.assertTrue(item["question"].endswith("요?"), item["question"])
                    self.assertTrue(item["answer"].endswith("요."), item["answer"])
                    self.assertNotRegex(item["answer"], r"\([^)]*[가-힣][^)]*\)")
                    self.assertIs(item["_review"], True)
                    covered.update(item["rule_ids"])
                self.assertEqual(covered, set(data["rules"]))  # 어느 규칙에서도 풀이가 하나는 나온다

    def test_only_concepts_for_the_group_rules_are_loaded(self):
        questions = lambda rule_ids: [item["question"] for item in  # noqa: E731
                                      load_card("debug_error_exposure", rule_ids).concepts]
        self.assertEqual(questions(["DBG-1"]), ["디버그 모드가 뭐예요?"])
        self.assertEqual(questions(["ERR-1"]), ["오류 내용을 왜 보여 주면 안 돼요?"])
        self.assertEqual(len(questions(["DBG-2", "ERR-2"])), 2)
        self.assertEqual(sorted(load_card("sql_injection", ["SQL-1"]).concepts[0]), ["answer", "question"])

    def test_bad_concept_format_is_reported(self):
        data = json.loads((RULES_DIR / "ssrf.json").read_text(encoding="utf-8"))
        self.assertEqual(card_problems(data, "ssrf"), [])
        data["concept"][0]["rule_ids"] = ["SQL-1"]  # 이 취약점에 없는 규칙
        self.assertEqual(card_problems(data, "ssrf"), ["concept(question, answer, rule_ids)이 맞지 않다"])


class LoadCardTest(unittest.TestCase):
    def test_single_rule(self):
        card = load_card("sql_injection", ["SQL-1"])
        self.assertEqual((card.vuln_id, card.name, card.rule_ids), ("sql_injection", "SQL 삽입", ("SQL-1",)))
        self.assertEqual(len(card.allowed_fixes), 1)
        self.assertEqual(len(card.examples), 1)
        (reference,) = card.references
        self.assertEqual((reference["rule_id"], reference["source"], reference["pages"]), ("SQL-1", "KISA 「SQL 삽입」", "9~11"))
        self.assertEqual(reference["excerpt_source"], "KISA Python 시큐어코딩 가이드(2023년 개정본) 「SQL 삽입」 9쪽")
        self.assertTrue(reference["excerpt"].startswith("DB API 사용 시 인자화된 쿼리를 통해"))
        self.assertIs(reference["translated"], False)  # KISA 문장은 원문 그대로
        self.assertTrue(reference["easy"].startswith("SQL 문장에는 값이 들어갈 빈칸만"))
        self.assertEqual(sorted(card.fallback_explanations[0]), ["how_to_fix", "impact", "problem", "rule_id"])

    def test_english_sources_are_shown_in_korean(self):
        """영어 문서(OWASP)가 근거인 규칙은 우리말로 옮긴 문장을 보여 주고, 옮긴 글임을 표시한다."""
        for vuln_id, rule_id in (("sql_injection", "SQL-2"),):
            with self.subTest(rule_id):
                (reference,) = load_card(vuln_id, [rule_id]).references
                self.assertIs(reference["translated"], True)
                self.assertRegex(reference["excerpt"], r"[가-힣]")
                self.assertNotIn("excerpt_original", reference)  # 영어 원문은 화면으로 보내지 않는다

    def test_group_with_two_rules_keeps_both_without_repeating(self):
        card = load_card("file_upload", ["UP-1", "UP-2"])
        self.assertEqual(card.rule_ids, ("UP-1", "UP-2"))
        self.assertEqual(len(card.allowed_fixes), 1)  # 같은 행의 규칙은 내용이 같다
        self.assertEqual(len(card.key_sentences), 2)
        self.assertEqual(len(card.examples), 2)
        self.assertEqual([item["rule_id"] for item in card.references], ["UP-1", "UP-2"])
        self.assertEqual([item["rule_id"] for item in card.fallback_explanations], ["UP-1", "UP-2"])

    def test_rules_from_different_rows_keep_both_fixes(self):
        card = load_card("sql_injection", ["SQL-1", "SQL-2"])
        self.assertEqual(len(card.allowed_fixes), 2)
        self.assertEqual(len(card.forbidden_fixes), 2)

    def test_every_rule_loads(self):
        for vuln_id in card_files():
            self.assertEqual(load_card(vuln_id, rule_ids_of(vuln_id)).rule_ids, rule_ids_of(vuln_id))

    def test_missing_or_bad_ids_raise_card_error(self):
        for vuln_id, rule_ids in (
            ("no_such_vuln", ["SQL-1"]),
            ("../cards", ["SQL-1"]),
            ("sql_injection", ["UP-1"]),
            ("sql_injection", []),
            (None, ["SQL-1"]),
        ):
            with self.subTest(vuln_id=vuln_id, rule_ids=rule_ids):
                with self.assertRaises(CardError):
                    load_card(vuln_id, rule_ids)


if __name__ == "__main__":
    unittest.main()
