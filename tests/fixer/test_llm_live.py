"""9단계: 실제 API 테스트. RUN_LLM_TESTS=1일 때만 돈다 (비용이 든다).

팀이 만든 테스트 파일만 쓴다 (학생 코드는 쓰지 않는다). 파일은 탐지 스펙 7장의 위험 테스트 파일을
tests/fixtures/risky/ 에 넣거나, LLM_TEST_DIR로 폴더를 알려 준다.

    PowerShell:  $env:RUN_LLM_TESTS = '1'; python -m unittest tests.fixer.test_llm_live -v

rule_id별로 첫 시도 통과 / 재시도 후 통과 / 대체 예시 횟수와 사용량 합계를 표로 출력한다.
"""
import os
import unittest
from collections import Counter, defaultdict
from pathlib import Path

from detector import analyze
from fixer import service
from fixer.grouping import make_groups
from fixer.llm_client import USAGE_KEYS

LIVE = os.getenv("RUN_LLM_TESTS") == "1"
TEST_DIR = Path(os.getenv("LLM_TEST_DIR") or Path(__file__).parent.parent / "fixtures" / "risky")
# IDOR은 학생이 답해야 판정한다. 후보 라우트를 모두 "본인만 봐야 한다"고 답한 상태로 돌린다.
USER_INPUT = {"idor": {"public_functions": []}}
OUTCOMES = ("first", "retry", "fallback")


@unittest.skipUnless(LIVE, "RUN_LLM_TESTS=1일 때만 실제 API를 호출한다")
class LiveFixTest(unittest.TestCase):
    def test_pass_rates_per_rule(self):
        files = sorted(TEST_DIR.glob("*.py"))
        if not files:
            self.skipTest(f"테스트 파일이 없다: {TEST_DIR}")
        from dotenv import load_dotenv

        load_dotenv()  # .env의 ANTHROPIC_API_KEY, FIX_MODEL
        outcomes, usage = defaultdict(Counter), Counter()
        for path in files:
            code = path.read_text(encoding="utf-8")
            for group in make_groups(analyze(code, USER_INPUT), code):
                result, attempts = service.run_group(code, path.name, group, USER_INPUT)
                outcome = "fallback" if result["status"] == "fallback" else ("first" if len(attempts) == 1 else "retry")
                for rule_id in group.rule_ids:
                    outcomes[rule_id][outcome] += 1
                usage.update({key: result["usage"][key] for key in (*USAGE_KEYS, "calls")})
                # ②와 ③은 어떤 경우에도 함께 있다
                self.assertTrue(result["diff"]["before"].strip(), f"{path.name} {group.group_id}")
                self.assertIn("다음 조건대로 고쳐줘.", result["prompt"])

        print("\n| rule_id | 첫 시도 | 재시도 후 | 대체 예시 |\n|---|---|---|---|")
        for rule_id in sorted(outcomes):
            print(f"| {rule_id} | " + " | ".join(str(outcomes[rule_id][name]) for name in OUTCOMES) + " |")
        print("사용량 합계:", dict(usage))
        self.assertTrue(outcomes, "위험 묶음이 하나도 없다")


if __name__ == "__main__":
    unittest.main()
