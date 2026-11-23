"""고친 코드 끼워 넣기와 V1~V3 검증 (fix_spec 7장).

검증용 사본만 만든다. 학생 코드에는 적용하지 않고, 코드를 실행하지도 않는다.
판정은 탐지 모듈의 analyze() 결과로만 한다.
"""
import ast

from detector.result import SAFE, VULNERABLE

from .grouping import parse, split_lines

V1, V2, V3 = "V1", "V2", "V3"


def apply(masked_code, group, fixed_code, added_top_level):
    """가린 코드에 수정안을 끼워 넣은 (새 코드, 고친 범위)를 돌려준다.

    1. group.target_range를 fixed_code로 바꾼다. fixed_code가 비어 있으면 그 범위를 지운다.
    2. added_top_level을 마지막 최상위 import 아래에 넣는다 (import가 없으면 맨 위).
       이미 같은 줄이 있으면 넣지 않는다.
    3. 늘거나 줄어든 줄 수만큼 고친 범위를 보정한다.

    고친 범위는 (시작 줄, 끝 줄)이고, 범위를 지웠으면 끝 줄이 시작 줄보다 1 작다 (빈 범위).
    """
    lines = split_lines(masked_code)
    start, end = group.target_range
    if not 1 <= start <= end <= len(lines):
        raise ValueError("target_range가 코드 범위를 벗어났습니다.")
    fixed = _trim(split_lines(fixed_code))
    import_end = _last_top_level_import(parse(masked_code))

    lines[start - 1:end] = fixed
    if import_end > end:  # import가 고친 범위보다 아래에 있다: 줄 수가 달라진 만큼 옮긴다
        insert_at = import_end + len(fixed) - (end - start + 1)
    elif import_end >= start:  # 고친 범위가 마지막 import 문 자체다
        insert_at = start - 1 + len(fixed)
    else:
        insert_at = import_end

    added = [line for block in missing_top_level("\n".join(lines), added_top_level) for line in block.split("\n")]
    lines[insert_at:insert_at] = added

    new_start = start + len(added) if insert_at < start else start
    return "\n".join(lines), (new_start, new_start + len(fixed) - 1)


def missing_top_level(code, added_top_level):
    """added_top_level 가운데 코드에 아직 없는 것들. 앞뒤 빈 줄은 빼고, 같은 것은 한 번만 담는다.

    여러 줄짜리 항목(dict 상수 등)은 통째로 비교한다. 줄 단위로 보면 `}` 같은 줄이 빠진다.
    """
    lines = split_lines(code)
    kept, kept_lines = [], []
    for item in added_top_level:
        block = _trim(split_lines(item))
        if block and not _contains(lines, block) and not _contains(kept_lines, block):
            kept.append("\n".join(block))
            kept_lines.extend(block)
    return kept


def check(base, after, group, new_range):
    """통과하지 못한 조건의 ID 목록을 돌려준다. 비어 있으면 통과다.

    base는 analyze(가린 코드, user_input), after는 analyze(끼워 넣은 코드, user_input)이다.
    - V1: after가 ok다 (문법 오류 없음)
    - V2: 고친 범위 안에 묶음의 vuln_id finding이 없다
    - V3: base에서 "안전"이던 vuln_id가 after에서 "위험"이 아니다
    """
    if not after.get("ok"):
        return [V1]
    failed = []
    if _findings_in_range(after, group.vuln_id, new_range):
        failed.append(V2)
    if _newly_risky(base, after):
        failed.append(V3)
    return failed


def leftover_findings(base, after, group, new_range):
    """검증에 걸린 finding들 (재시도 때 모델에 알려 줄 것): 고친 범위에 남은 것과 새로 생긴 위험."""
    if not after.get("ok"):
        return []
    found = list(_findings_in_range(after, group.vuln_id, new_range))
    for result in _newly_risky(base, after):
        found.extend(result["findings"])
    return found


def _findings_in_range(after, vuln_id, new_range):
    start, end = new_range
    return [
        finding
        for result in after["results"]
        if result["vuln_id"] == vuln_id
        for finding in result["findings"]
        if start <= finding["line"] <= end
    ]


def _newly_risky(base, after):
    """base에서 안전이었는데 after에서 위험이 된 결과 항목들."""
    if not base.get("ok"):
        raise ValueError("기준 결과(base)가 없습니다.")
    was_safe = {result["vuln_id"] for result in base["results"] if result["verdict"] == SAFE}
    return [
        result
        for result in after["results"]
        if result["vuln_id"] in was_safe and result["verdict"] == VULNERABLE
    ]


def _last_top_level_import(tree):
    """마지막 최상위 import 문이 끝나는 줄. 없으면 0."""
    ends = [node.end_lineno for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    return max(ends, default=0)


def _trim(lines):
    """앞뒤의 빈 줄을 뺀다. 가운데 빈 줄은 그대로 둔다."""
    first, last = 0, len(lines)
    while first < last and not lines[first].strip():
        first += 1
    while last > first and not lines[last - 1].strip():
        last -= 1
    return lines[first:last]


def _contains(lines, block):
    """lines 안에 block이 연달아 들어 있는지. 줄 끝 공백만 무시한다."""
    block = [line.rstrip() for line in block]
    lines = [line.rstrip() for line in lines]
    return any(lines[index:index + len(block)] == block for index in range(len(lines) - len(block) + 1))
