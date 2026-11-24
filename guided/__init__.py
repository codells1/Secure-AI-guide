"""체크리스트 유도질문: 위험 항목마다 질문 5개와 채점 결과를 만든다 (유도질문 v5).

탐지 모듈의 analyze() 결과만 읽고 LLM을 쓰지 않는다. 같은 코드에는 항상 같은 질문과 채점이 나온다.
질문·힌트·정답 문구는 questions.json, 채점표는 answer_keys.json에 있다. 두 파일 모두 팀 검토 전 초안이다.
"""
import ast
import json
from functools import lru_cache
from pathlib import Path

from detector.result import VULNERABLE

DATA_DIR = Path(__file__).parent
QUESTION_COUNT = 5  # ①기능 ②노출 ③위험한 방식 ④방어 ⑤개인정보
YES, NO = "예", "아니오"
_ANSWERS = {YES: True, NO: False, None: None}


class GuidedError(Exception):
    """질문 파일이나 채점표의 형식이 맞지 않는다."""


def describe(code, analyze_result):
    """위험 항목의 유도질문: {vuln_id: [{"question", "answer", "hint", "reveal"} × 5]}.

    answer는 True(예) / False(아니오) / None(채점하지 않음)이다.
    hint는 1번째 오답, reveal은 2번째 오답에 보여 줄 문장이고, 채점하지 않는 질문에서는 비어 있다.
    """
    questions = _questions()
    described = {}
    for result in analyze_result.get("results", []):
        items = questions["items"].get(result["vuln_id"])
        if result["verdict"] != VULNERABLE or not items:
            continue
        findings = result["findings"]
        values = {
            "{lines}": format_lines(detected_lines(findings)),
            "{func}": ", ".join(_function_names(code, [finding["line"] for finding in findings])),
        }
        answers = expected_answers(finding["rule_id"] for finding in findings)
        described[result["vuln_id"]] = [
            _question(item, answer, questions["fallback"], values) for item, answer in zip(items, answers)
        ]
    return described


def expected_answers(rule_ids):
    """질문 ①~⑤의 정답 (True / False / None).

    항목에서 걸린 모든 규칙의 정답이 같은 질문만 채점한다.
    하나라도 채점하지 않는 규칙이거나 정답이 다르면 None이다. 채점표에 없는 규칙도 채점하지 않는다.
    """
    keys = _answer_keys()
    rows = [keys.get(rule_id) for rule_id in dict.fromkeys(rule_ids)]
    if not rows or any(row is None for row in rows):
        return [None] * QUESTION_COUNT
    return [column[0] if len(set(column)) == 1 else None for column in zip(*rows)]


def detected_lines(findings):
    """항목의 탐지 줄: 모든 finding의 path에 있는 줄 (입력을 받은 줄부터 문제가 생기는 줄까지)."""
    return sorted({line for finding in findings for line in finding["path"]})


def format_lines(lines):
    """줄 번호를 "19–21, 25"처럼 적는다. 이어지는 줄은 범위로 묶는다."""
    parts, start, previous = [], None, None
    for line in [*sorted(set(lines)), None]:
        if previous is not None and line == previous + 1:
            previous = line
            continue
        if previous is not None:
            parts.append(str(start) if start == previous else f"{start}–{previous}")
        start = previous = line
    return ", ".join(parts)


def _question(item, answer, fallback, values):
    if answer is None:
        return {"question": item["question"], "answer": None, "hint": "", "reveal": ""}
    word = YES if answer else NO
    filled = {**values, "{answer}": word}
    return {
        "question": item["question"],
        "answer": answer,
        "hint": _fill(item.get("hint", {}).get(word) or fallback["hint"], filled),
        "reveal": _fill(item.get("reveal", {}).get(word) or fallback["reveal"], filled),
    }


def _fill(text, values):
    for placeholder, value in values.items():
        text = text.replace(placeholder, value)
    return text


def _function_names(code, lines):
    """그 줄들이 들어 있는 함수의 이름 (줄 순서대로 한 번씩). 함수 밖의 줄은 뺀다."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return []
    spans = [
        (node.lineno, node.end_lineno, node.name)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    names = []
    for line in lines:
        inside = [span for span in spans if span[0] <= line <= span[1]]
        if inside and max(inside)[2] not in names:  # 가장 안쪽 함수: 시작 줄이 가장 늦다
            names.append(max(inside)[2])
    return names


@lru_cache(maxsize=None)
def _answer_keys():
    """채점표: {rule_id: (True / False / None) × 5}."""
    rules = _read("answer_keys.json").get("rules")
    if not isinstance(rules, dict):
        raise GuidedError("answer_keys.json: rules가 없다")
    keys = {}
    for rule_id, row in rules.items():
        if not isinstance(row, list) or len(row) != QUESTION_COUNT or any(
            not isinstance(cell, (str, type(None))) or cell not in _ANSWERS for cell in row
        ):
            raise GuidedError(f"answer_keys.json: {rule_id}의 정답은 예 / 아니오 / null {QUESTION_COUNT}개여야 한다")
        keys[rule_id] = tuple(_ANSWERS[cell] for cell in row)
    return keys


@lru_cache(maxsize=None)
def _questions():
    """질문 파일: {"fallback": {"hint", "reveal"}, "items": {vuln_id: [질문 × 5]}}."""
    data = _read("questions.json")
    fallback, items = data.get("fallback"), data.get("items")
    if not isinstance(fallback, dict) or not all(_text(fallback.get(key)) for key in ("hint", "reveal")):
        raise GuidedError("questions.json: fallback(hint, reveal)이 없다")
    if not isinstance(items, dict):
        raise GuidedError("questions.json: items가 없다")
    for vuln_id, questions in items.items():
        if not isinstance(questions, list) or len(questions) != QUESTION_COUNT or not all(
            isinstance(item, dict) and _text(item.get("question")) and _texts_by_answer(item.get("hint", {}))
            and _texts_by_answer(item.get("reveal", {}))
            for item in questions
        ):
            raise GuidedError(f"questions.json: {vuln_id}의 질문은 question이 있는 {QUESTION_COUNT}개여야 한다")
    return {"fallback": fallback, "items": items}


def _read(name):
    try:
        data = json.loads((DATA_DIR / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise GuidedError(f"{name}: 읽을 수 없다") from None
    if not isinstance(data, dict):
        raise GuidedError(f"{name}: 객체가 아니다")
    return data


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _texts_by_answer(value):
    """정답별 문구: {"예": "...", "아니오": "..."} 가운데 있는 것만."""
    return isinstance(value, dict) and all(key in (YES, NO) and _text(text) for key, text in value.items())
