"""첫 화면(소개 페이지): 문구 규칙, 점검 항목 이름, 예시 파일. 실제 API는 호출하지 않는다."""

import re
import unittest
from pathlib import Path

from app import app
from detector import analyze
from detector.result import SAFE
from fixer.cards import load_card, rule_ids_of

ROOT = Path(__file__).resolve().parent.parent
# 체크리스트 순서 (탐지 모듈의 결과 순서)
VULN_IDS = [result["vuln_id"] for result in analyze("x = 1\n")["results"]]


def page():
    response = app.test_client().get("/")
    return response.status_code, response.get_data(as_text=True)


def landing(html):
    """첫 화면 부분만 (작업 화면 앞까지)."""
    start, end = html.index('<div id="landing"'), html.index('<div id="workspace"')
    return html[start:end]


def text_of(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


class LandingPageTest(unittest.TestCase):
    def setUp(self):
        self.status, self.html = page()
        self.landing = landing(self.html)

    def test_the_first_screen_is_the_landing_page(self):
        self.assertEqual(self.status, 200)
        self.assertIn("<title>내 코드 보안 점검</title>", self.html)
        self.assertNotIn(" hidden", self.landing.split(">", 1)[0])  # 첫 화면은 처음부터 보인다
        self.assertRegex(self.html, r'<div id="workspace" class="workspace" hidden>')  # 작업 화면은 숨겨 둔다
        self.assertEqual(len(re.findall(r"<h1[ >]", self.html)), 1)

    def test_forbidden_words_are_nowhere_on_the_page(self):
        for word in ("백신", "중·고등학생", "중고등학생", "중학생", "고등학생", "10분이면", "관련 법"):
            with self.subTest(word):
                self.assertNotIn(word, self.html)

    def test_sections_come_in_order_and_the_menu_points_at_them(self):
        order = [self.landing.index(marker) for marker in (
            'class="lp-header"', "정말 안전할까요?", 'id="upload"', "45<span>%</span>",
            'id="how"', 'id="items"', 'id="privacy"', "공개하기 전에, 내 코드부터 점검해 볼까요?", "제주대학교 SW융합캡스톤디자인")]
        self.assertEqual(order, sorted(order))
        for target in ("#how", "#items", "#privacy", "#upload"):
            with self.subTest(target):
                self.assertIn(f'href="{target}"', self.landing)
                self.assertIn(f'id="{target[1:]}"', self.landing)

    def test_item_names_are_the_checklist_names(self):
        names = re.findall(r'<div class="lp-item"><span class="lp-item-num">(\d\d)</span><h3>([^<]+)</h3>', self.landing)
        self.assertEqual([number for number, _ in names], [f"{index:02d}" for index in range(1, 11)])
        expected = [load_card(vuln_id, rule_ids_of(vuln_id)[:1]).name for vuln_id in VULN_IDS]
        self.assertEqual([name for _, name in names], expected)
        script = (ROOT / "static" / "main.js").read_text(encoding="utf-8")
        for name in expected:  # 체크리스트(main.js의 VULN_TITLES)와도 같다
            self.assertIn(f"'{name}'", script)

    def test_privacy_text_matches_what_the_program_does(self):
        text = text_of(self.landing)
        # 수정 피드백은 비밀 값과 주석을 가린 파일 전체를 보낸다 ("위험한 부분만"이 아니다)
        self.assertIn("설명을 만들기 위해 코드를 외부 AI로 보내요. 프로그램이 찾은 비밀 값과 주석은 가려서 보내고, AI 회사는 보통 30일 이내에 지워요.", text)
        self.assertNotIn("위험한 부분만", text)

    def test_the_preview_is_a_picture_not_controls(self):
        start = self.landing.index('<div class="preview"')
        preview = self.landing[start:self.landing.index("</section>", start)]
        self.assertIn('role="img" aria-label="점검 화면 미리보기: 위험한 줄이 빨갛게 표시되고 예/아니오 질문이 나온다"', preview)
        self.assertNotRegex(preview, r"<(button|a|input)[ >]")

    def test_upload_uses_a_label_and_a_python_file_input(self):
        self.assertRegex(self.landing, r'<label id="upload" class="dropzone" for="file-input">')
        self.assertRegex(self.landing, r'<input type="file" id="file-input"[^>]* accept="\.py">')
        self.assertNotRegex(self.landing, r'<input type="file"[^>]* multiple')
        self.assertRegex(self.landing, r'<p id="landing-error"[^>]* role="alert" hidden>')

    def test_upload_limit_in_the_script_is_the_server_limit(self):
        script = (ROOT / "static" / "main.js").read_text(encoding="utf-8")
        self.assertIn("const MAX_FILE_BYTES = 1024 * 1024;", script)
        self.assertEqual(app.config["MAX_CONTENT_LENGTH"], 1024 * 1024)


class ExampleFileTest(unittest.TestCase):
    """[예시 코드로 해 보기]의 파일: 짧고, 질문 없이 끝까지 볼 수 있다."""

    def setUp(self):
        _, html = page()
        self.url = re.search(r'id="example-btn"[^>]* data-src="([^"]+)"', html).group(1)
        self.code = (ROOT / "static" / "example_app.py").read_text(encoding="utf-8")

    def test_it_is_served_as_it_is(self):
        response = app.test_client().get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True).replace("\r\n", "\n"), self.code)
        response.close()

    def test_it_has_three_risky_items_and_asks_nothing(self):
        result = analyze(self.code)
        self.assertTrue(result["ok"])
        self.assertLess(self.code.count("\n"), 30)
        risky = {item["vuln_id"]: [finding["rule_id"] for finding in item["findings"]]
                 for item in result["results"] if item["verdict"] != SAFE}
        self.assertEqual(risky, {"sql_injection": ["SQL-1"], "debug_error_exposure": ["DBG-1"], "hardcoded_secret": ["KEY-1"]})
        self.assertTrue(all(item["needs_user_input"] is None for item in result["results"]))


if __name__ == "__main__":
    unittest.main()
