"""재점검: 수정 전후 탐지 결과 비교 (fix_spec 9장).

API를 부르지 않는다. 학생이 고친 코드는 탐지 모듈만 판정하고, 여기서는 이전 결과와 견주기만 한다.
이전 결과는 서버에 저장하지 않고, 브라우저가 요청에 함께 보낸 것을 쓴다.
"""
from detector.result import MESSAGES

from .grouping import _function_name, parse

RESOLVED, STILL, NEW = "해결됨", "아직 위험", "새로 생김"


def compare(prev_results, now_results, prev_code, now_code):
    """이전 결과와 지금 결과를 비교한 항목 목록을 돌려준다.

    학생이 코드를 고치면 줄 번호가 바뀌므로 줄 번호로 비교하지 않는다.
    비교 키는 vuln_id + rule_id + 함수 이름(함수 밖이면 "<module>")이고, 같은 키가 여러 개면 개수로 비교한다.
    각 항목: vuln_id, rule_id, function_name, status("해결됨" | "아직 위험" | "새로 생김"),
    line(지금 코드의 줄 번호. 해결됐으면 None), message.
    """
    before = _by_key(prev_results, prev_code)
    after = _by_key(now_results, now_code)
    # 탐지 모듈이 준 취약점 순서 그대로 (지금은 안전해진 취약점도 그 자리에 둔다)
    vuln_ids = list(dict.fromkeys([result["vuln_id"] for result in now_results]
                                  + [result["vuln_id"] for result in prev_results]))
    items = []
    for vuln_id in vuln_ids:
        active, resolved = [], []
        for key in dict.fromkeys([k for k in after if k[0] == vuln_id] + [k for k in before if k[0] == vuln_id]):
            old, new = before.get(key, []), after.get(key, [])
            kept = min(len(old), len(new))
            for index, finding in enumerate(new):
                active.append(_item(key, STILL if index < kept else NEW, finding["line"]))
            resolved.extend(_item(key, RESOLVED, None) for _ in old[kept:])
        items.extend(sorted(active, key=lambda item: item["line"]))
        items.extend(resolved)
    return items


def valid_results(value):
    """브라우저가 보낸 이전 결과가 analyze()의 results와 같은 모양인지."""
    return isinstance(value, list) and all(
        isinstance(result, dict)
        and isinstance(result.get("vuln_id"), str)
        and isinstance(result.get("findings"), list)
        and all(
            isinstance(finding, dict) and isinstance(finding.get("rule_id"), str) and type(finding.get("line")) is int
            for finding in result["findings"]
        )
        for result in value
    )


def _by_key(results, code):
    """(vuln_id, rule_id, 함수 이름) → 그 키의 finding들 (줄 순서)."""
    tree = parse(code)
    keyed = {}
    for result in results:
        for finding in sorted(result["findings"], key=lambda item: item["line"]):
            key = (result["vuln_id"], finding["rule_id"], _function_name(tree, finding["line"]))
            keyed.setdefault(key, []).append(finding)
    return keyed


def _item(key, status, line):
    vuln_id, rule_id, function_name = key
    return {
        "vuln_id": vuln_id,
        "rule_id": rule_id,
        "function_name": function_name,
        "status": status,
        "line": line,
        "message": MESSAGES.get(rule_id, ""),
    }
