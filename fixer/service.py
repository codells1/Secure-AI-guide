"""①② 생성 흐름: API 호출 → 검증 → 1회 재시도 → 대체 예시."""
import json
import logging
import os
import re
from pathlib import Path

import anthropic

from .code_utils import apply_fix, extract_range, find_target_range
from .prompts import RESPONSE_SCHEMA, SYSTEM_PROMPT, build_user_message

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent / "fix_rules"
DEFAULT_MODEL = "claude-opus-5-5"
MAX_TOKENS = 8000
MAX_ATTEMPTS = 2
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# 안전 분류기가 거절하면 API가 같은 요청을 이 모델로 다시 실행한다.
# Sonnet 5.5는 대체 모델로 claude-sonnet-5만 지정할 수 있다.
FALLBACK_MODELS = {
    "claude-opus-5-5": "claude-opus-4-8",
    "claude-sonnet-5-5": "claude-sonnet-5",
}


class RuleNotReady(Exception):
    """이 finding에 쓸 수정 규칙 카드가 아직 없다."""


def load_rule(vuln_id, rule_id):
    # vuln_id가 파일 경로에 들어가므로 형식을 제한한다
    if not re.fullmatch(r"[a-z0-9_]+", vuln_id):
        raise RuleNotReady(vuln_id)
    path = RULES_DIR / f"{vuln_id}.json"
    if not path.is_file():
        raise RuleNotReady(vuln_id)
    card = json.loads(path.read_text(encoding="utf-8"))
    rule = card.get("rules", {}).get(rule_id)
    if rule is None:
        raise RuleNotReady(rule_id)
    return card, rule


def _call_model(client, user_message):
    """형식에 맞는 응답이면 dict, 잘렸거나 거절되었으면 None."""
    model = os.getenv("FIX_MODEL", DEFAULT_MODEL)
    fallback = FALLBACK_MODELS.get(model)
    response = client.beta.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
        output_config={"format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}},
        betas=[FALLBACK_BETA],
        **({"fallbacks": [{"model": fallback}]} if fallback else {}),
    )
    # 비용 실측용 기록. 학생 코드는 로그에 남기지 않는다
    logger.info("fix usage model=%s input=%s output=%s stop=%s", response.model,
                response.usage.input_tokens, response.usage.output_tokens, response.stop_reason)
    if response.stop_reason != "end_turn":
        return None
    text = next((b.text for b in response.content if b.type == "text"), None)
    return json.loads(text) if text else None


def _fallback(rule, reason):
    logger.warning("fix fallback: %s", reason)
    return {
        "status": "fallback",
        "explanation": rule["fallback_explanation"],
        "before": rule["fallback_example"]["before"],
        "after": rule["fallback_example"]["after"],
        "added_top_level": [],
    }


def generate_fix(client, verifier, code, finding, user_input=None):
    """verifier(원본, 고친 코드, finding, 새 시작, 새 끝, user_input) -> (통과 여부, 실패 사유)"""
    card, rule = load_rule(finding["vuln_id"], finding["rule_id"])
    start, end, _ = find_target_range(code, finding["line"])

    retry = None
    for _attempt in range(MAX_ATTEMPTS):
        message = build_user_message(code, finding, start, end, card, rule, retry)
        try:
            data = _call_model(client, message)
        except anthropic.APIError as exc:
            return _fallback(rule, type(exc).__name__)
        except json.JSONDecodeError:
            data = None

        if data is None:
            retry = "이전 응답이 형식에 맞지 않거나 잘렸다. 더 짧게 다시 작성한다."
            continue

        try:
            patched, new_start, new_end = apply_fix(
                code, start, end, data["fixed_code"], data["added_top_level"])
            passed, reason = verifier(code, patched, finding, new_start, new_end, user_input)
        except ValueError:
            passed, reason = False, "V1: 코드를 해석할 수 없다."

        if passed:
            return {
                "status": "verified",
                "explanation": {k: data[k] for k in ("problem", "impact", "how_to_fix")},
                "before": extract_range(code, start, end),
                "after": data["fixed_code"].strip("\n"),
                "added_top_level": data["added_top_level"],
            }
        retry = reason

    return _fallback(rule, "verification failed")
