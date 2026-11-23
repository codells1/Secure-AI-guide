"""수정 묶음 하나의 피드백 만들기 (fix_spec 2장, 7장).

가리기 → API 1회 → 탐지 모듈로 검증 → (실패 시 재시도 1회) → (또 실패 시 대체 예시).
어느 경우든 ② 수정 전후 비교와 ③ 프롬프트를 함께 돌려준다.
서버는 상태를 갖지 않고, 학생 코드와 결과를 저장하지 않는다.
"""
import logging

from detector import analyze
from detector.result import MESSAGES

from . import llm_client
from .apply_check import V1, V2, V3, apply, check, leftover_findings, missing_top_level
from .cards import EXPLANATION_KEYS, load_card
from .grouping import make_groups, range_text
from .llm_client import USAGE_KEYS, LLMFailure
from .masking import MaskingError, mask
from .prompt_template import build_prompt

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 2  # 첫 시도 + 재시도 1회
STATUS_OK, STATUS_FALLBACK = "ok", "fallback"
# 가리지 못한 코드는 ③ 프롬프트에도 넣지 않는다 (학생이 다른 AI 서비스에 붙여넣기 때문).
CODE_NOT_SHOWN = "# (코드를 가리지 못해 넣지 않았어요. 고칠 부분의 코드를 여기에 직접 붙여 넣어 주세요.)"

CHECK_NOTES = {
    V1: "고친 코드를 끼워 넣으면 문법 오류가 난다.",
    V2: "고친 범위 안에 같은 취약점이 남아 있다.",
    V3: "고치기 전에는 없던 다른 취약점이 생겼다.",
}
FAILURE_NOTES = {
    "max_tokens": "앞선 응답이 너무 길어서 중간에 잘렸다. fixed_code에는 <target_range>의 코드만 쓰고 설명은 한 문장씩 짧게 쓴다.",
    "refusal": "앞선 요청에는 응답이 만들어지지 않았다. 학생이 자기 코드의 보안 결점을 스스로 고치도록 돕는 수정 예시와 설명만 만든다.",
    "bad_json": "앞선 응답이 정해진 형식과 달랐다. 모든 항목을 채워서 다시 쓴다.",
}


def describe_groups(code, analyze_result):
    """분석 응답에 붙일 수정 묶음 목록 (작업 지시 5장). API는 부르지 않는다.

    target_code는 가린 코드의 범위 원문이다. 가리지 못했으면 코드를 넣지 않는다.
    """
    groups = make_groups(analyze_result, code)
    if not groups:
        return []
    try:
        masked = mask(code, analyze_result)
    except MaskingError:
        masked = None
    return [
        {**group.to_dict(), "target_code": range_text(masked, group.target_range) if masked is not None else ""}
        for group in groups
    ]


def find_group(code, user_input, group_id):
    """브라우저가 보낸 group_id에 해당하는 묶음을 탐지 결과에서 다시 만든다. 없으면 None.

    브라우저가 보낸 묶음 내용은 믿지 않고, 같은 코드를 다시 analyze()해서 얻은 묶음만 쓴다.
    """
    result = analyze(code, user_input)
    if not result.get("ok"):
        raise ValueError("코드를 해석할 수 없습니다.")
    return next((group for group in make_groups(result, code) if group.group_id == group_id), None)


def fix_group(code, filename, group, user_input=None, client=None):
    """수정 묶음 하나의 FixResult(프론트엔드로 가는 dict)를 돌려준다.

    group은 같은 code와 user_input으로 만든 묶음이어야 한다 (grouping.make_groups).
    client를 주지 않으면 실제 API 클라이언트를 쓴다.
    """
    return run_group(code, filename, group, user_input, client)[0]


def run_group(code, filename, group, user_input=None, client=None):
    """(FixResult, 시도 기록)을 돌려준다.

    시도 기록(통과 여부, 실패한 조건, 사용량)은 서버 안에서만 쓴다. 검증 내용은 학생에게 보이지 않는다.
    """
    result = analyze(code, user_input)
    if not result.get("ok"):
        raise ValueError("코드를 해석할 수 없습니다.")
    card = load_card(group.vuln_id, group.rule_ids)
    attempts = []
    try:
        masked = mask(code, result)
    except MaskingError:
        # 가리지 못한 코드는 외부로 보내지 않는다.
        logger.warning("fix fallback: masking failed")
        return _fallback(filename, group, card, None, attempts), attempts

    base = analyze(masked, user_input)
    target_code = range_text(masked, group.target_range)
    client = client or llm_client.default_client()
    retry_note = None
    for _ in range(MAX_ATTEMPTS):
        try:
            data, usage = llm_client.request_fix(client, masked, group, card, retry_note)
        except LLMFailure as failure:
            attempts.append({"passed": False, "failed": [failure.reason], "usage": failure.usage})
            retry_note = FAILURE_NOTES.get(failure.reason, retry_note)
            continue
        new_code, new_range = apply(masked, group, data["fixed_code"], data["added_top_level"])
        after = analyze(new_code, user_input)
        failed = check(base, after, group, new_range)
        attempts.append({"passed": not failed, "failed": failed, "usage": usage})
        if not failed:
            diff = {
                "before": target_code,
                "after": range_text(new_code, new_range),  # 검증한 그대로를 보여 준다
                "added_top_level": missing_top_level(masked, data["added_top_level"]),
                "is_general_example": False,
            }
            explanations = [{key: data[key].strip() for key in EXPLANATION_KEYS}]
            fix_result = _result(filename, group, card, STATUS_OK, explanations, diff, target_code,
                                 data["fix_instruction"], attempts)
            return fix_result, attempts
        retry_note = _check_note(failed, base, after, group, new_range)
    return _fallback(filename, group, card, target_code, attempts), attempts


def _fallback(filename, group, card, target_code, attempts):
    """대체 예시: 카드의 일반 예시와 설명, fix_instruction 없는 프롬프트."""
    example = card.examples[0]
    diff = {
        "before": example["before"],
        "after": example["after"],
        "added_top_level": [],
        "is_general_example": True,
    }
    explanations = [dict(explanation) for explanation in card.fallback_explanations]  # 규칙마다 하나
    return _result(filename, group, card, STATUS_FALLBACK, explanations, diff, target_code, None, attempts)


def _result(filename, group, card, status, explanations, diff, target_code, fix_instruction, attempts):
    shown_code = target_code if target_code is not None else CODE_NOT_SHOWN
    usage = {key: sum(attempt["usage"][key] for attempt in attempts) for key in USAGE_KEYS}
    usage["calls"] = len(attempts)
    logger.info("fix result status=%s usage=%s", status, usage)
    return {
        "group_id": group.group_id,
        "status": status,
        "rule_ids": list(group.rule_ids),
        "messages": [MESSAGES[rule_id] for rule_id in group.rule_ids],
        "explanation": {key: explanations[0][key] for key in EXPLANATION_KEYS},
        "explanations": explanations,
        "diff": diff,
        "prompt": build_prompt(filename, group, card, shown_code, fix_instruction),
        "references": [dict(reference) for reference in card.references],
        "concepts": [dict(concept) for concept in card.concepts],
        "target_code": target_code or "",
        "usage": usage,
    }


def _check_note(failed, base, after, group, new_range):
    """재시도 때 모델에 알려 줄 내용: 실패한 조건과 남은 finding 메시지 (fix_spec 7.2)."""
    lines = ["앞선 수정은 다음 검증을 통과하지 못했다."]
    for condition in failed:
        note = CHECK_NOTES[condition]
        if condition == V1:
            line = (after.get("error") or {}).get("line")
            if isinstance(line, int) and new_range[0] <= line <= new_range[1]:
                note += f" (fixed_code의 {line - new_range[0] + 1}번째 줄 근처)"
        lines.append(f"- {condition}: {note}")
    leftover = list(dict.fromkeys(
        f"{finding['rule_id']}: {finding['message']}" for finding in leftover_findings(base, after, group, new_range)
    ))
    if leftover:
        lines.append("남아 있는 문제:")
        lines.extend(f"- {item}" for item in leftover)
    lines.append("<allowed_fixes>의 방식만 써서 다시 고친다.")
    return "\n".join(lines)
