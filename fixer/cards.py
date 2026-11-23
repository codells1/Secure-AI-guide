"""수정 규칙 카드 읽기·검사 (fix_spec 5장). 카드는 fixer/fix_rules/<vuln_id>.json에 있다."""
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

RULES_DIR = Path(__file__).parent / "fix_rules"
EXPLANATION_KEYS = ("problem", "impact", "how_to_fix")
_VULN_ID = re.compile(r"[a-z0-9_]+")


class CardError(Exception):
    """카드가 없거나 형식이 맞지 않는다."""


@dataclass(frozen=True)
class Card:
    """수정 묶음 하나에 쓰는 카드. 묶음에 규칙이 여러 개면 각 규칙의 내용을 모두 담는다."""

    vuln_id: str
    name: str  # 화면과 ③ 프롬프트에 쓰는 취약점 이름
    rule_ids: tuple
    key_sentences: tuple  # 모델에 넣는다
    allowed_fixes: tuple  # 모델과 ③ 프롬프트에 넣는다
    forbidden_fixes: tuple  # 모델에 넣는다
    examples: tuple  # ({"before", "after"}, ...) 모델에 넣고, 검증 실패 시 첫 번째를 ②에 보여 준다
    references: tuple  # ({"rule_id", "source", "pages"}, ...) 화면의 "근거" 표시용
    fallback_explanations: tuple  # ({"rule_id", "problem", "impact", "how_to_fix"}, ...) 검증 실패 시 ①
    concepts: tuple  # ({"question", "answer"}, ...) 묶음의 규칙에 해당하는 용어 풀이. 모델에는 넣지 않고 화면에 접어서 보여 준다


def load_card(vuln_id, rule_ids):
    """묶음의 규칙 카드를 모두 합쳐 돌려준다. 같은 내용은 한 번만 담고 규칙 순서를 지킨다."""
    data = _read(vuln_id)
    if not rule_ids:
        raise CardError("규칙이 없는 묶음입니다.")
    rules = []
    for rule_id in rule_ids:
        if not isinstance(rule_id, str) or rule_id not in data["rules"]:
            raise CardError("이 규칙의 카드가 없습니다.")
        rules.append((rule_id, data["rules"][rule_id]))
    return Card(
        vuln_id=data["vuln_id"],
        name=data["name"],
        rule_ids=tuple(rule_id for rule_id, _ in rules),
        key_sentences=_unique(rule["key_sentence"] for _, rule in rules),
        allowed_fixes=_unique(fix for _, rule in rules for fix in rule["allowed_fixes"]),
        forbidden_fixes=_unique(fix for _, rule in rules for fix in rule["forbidden_fixes"]),
        examples=_unique_examples(rule["fallback_example"] for _, rule in rules),
        references=tuple(
            {
                "rule_id": rule_id,
                "source": rule["reference"]["source"],
                "pages": rule["reference"]["pages"],
                # 근거 문서의 실제 문장, 그 문장이 있는 곳, 쉬운 풀이.
                # 화면의 "근거 자료"에 쪽수 대신 내용을 보여 준다. 모델에는 넣지 않는다.
                "excerpt": rule["reference"].get("excerpt", ""),
                "excerpt_source": rule["reference"].get("excerpt_source", ""),
                "easy": rule["reference"].get("easy", ""),
                # 영어 문서의 문장은 우리말로 옮겨서 보여 준다. 영어 원문(excerpt_original)은 카드에만 남긴다.
                "translated": bool(rule["reference"].get("excerpt_original")),
            }
            for rule_id, rule in rules
        ),
        fallback_explanations=tuple(
            {"rule_id": rule_id, **{key: rule["fallback_explanation"][key] for key in EXPLANATION_KEYS}}
            for rule_id, rule in rules
        ),
        concepts=tuple(
            {"question": item["question"], "answer": item["answer"]}
            for item in data.get("concept", [])
            if set(item["rule_ids"]) & set(rule_ids)  # 묶음의 규칙과 겹치는 풀이만
        ),
    )


def card_files():
    """카드 파일이 있는 vuln_id들."""
    return sorted(path.stem for path in RULES_DIR.glob("*.json"))


def rule_ids_of(vuln_id):
    return tuple(_read(vuln_id)["rules"])


@lru_cache(maxsize=None)
def _read(vuln_id):
    # vuln_id가 파일 경로에 들어가므로 형식을 제한한다 (브라우저가 보낸 값일 수 있다).
    if not isinstance(vuln_id, str) or not _VULN_ID.fullmatch(vuln_id):
        raise CardError("이 취약점의 카드가 없습니다.")
    path = RULES_DIR / f"{vuln_id}.json"
    if not path.is_file():
        raise CardError("이 취약점의 카드가 없습니다.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise CardError(f"{path.name}: 읽을 수 없습니다.") from None
    problems = card_problems(data, vuln_id)
    if problems:
        raise CardError(f"{path.name}: " + " / ".join(problems))
    return data


def card_problems(data, vuln_id):
    """카드 파일 내용이 fix_spec 5장 형식과 다른 점들. 비어 있으면 형식이 맞는 것이다."""
    if not isinstance(data, dict):
        return ["객체가 아니다"]
    problems = []
    if data.get("vuln_id") != vuln_id:
        problems.append("vuln_id가 파일 이름과 다르다")
    if not _text(data.get("name")):
        problems.append("name이 없다")
    rules = data.get("rules")
    if not isinstance(rules, dict) or not rules:
        return problems + ["rules가 없다"]
    for rule_id, rule in rules.items():
        problems.extend(f"{rule_id}: {problem}" for problem in _rule_problems(rule))
    # 용어 풀이(concept)는 취약점 단위로 둔다. 팀이 쓴 고정 문장이고, 어느 규칙에 보여 줄지 적는다.
    concept = data.get("concept", [])
    if not isinstance(concept, list) or not all(
        isinstance(item, dict)
        and _text(item.get("question"))
        and _text(item.get("answer"))
        and _texts(item.get("rule_ids"))
        and item["rule_ids"]
        and set(item["rule_ids"]) <= set(rules)
        for item in concept
    ):
        problems.append("concept(question, answer, rule_ids)이 맞지 않다")
    return problems


def _rule_problems(rule):
    if not isinstance(rule, dict):
        return ["객체가 아니다"]
    problems = []
    if not _text(rule.get("key_sentence")):
        problems.append("key_sentence가 없다")
    reference = rule.get("reference")
    if not isinstance(reference, dict) or not _text(reference.get("source")) or not all(
        isinstance(reference.get(key), str) for key in ("pages", "excerpt")
    ) or not all(
        isinstance(reference.get(key, ""), str)
        for key in ("excerpt_source", "easy", "excerpt_original", "excerpt_original_source")
    ):
        problems.append("reference(source, pages, excerpt)가 맞지 않다")
    if not _texts(rule.get("allowed_fixes")) or not rule["allowed_fixes"]:
        problems.append("allowed_fixes가 없다")
    if not _texts(rule.get("forbidden_fixes")):
        problems.append("forbidden_fixes가 목록이 아니다")
    example = rule.get("fallback_example")
    if not isinstance(example, dict) or not all(_text(example.get(key)) for key in ("before", "after")):
        problems.append("fallback_example(before, after)이 없다")
    explanation = rule.get("fallback_explanation")
    if not isinstance(explanation, dict) or not all(_text(explanation.get(key)) for key in EXPLANATION_KEYS):
        problems.append("fallback_explanation(problem, impact, how_to_fix)이 없다")
    return problems


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _texts(value):
    return isinstance(value, list) and all(_text(item) for item in value)


def _unique(items):
    return tuple(dict.fromkeys(items))


def _unique_examples(examples):
    seen = {}
    for example in examples:
        seen.setdefault((example["before"], example["after"]), example)
    return tuple({"before": before, "after": after} for before, after in seen)
