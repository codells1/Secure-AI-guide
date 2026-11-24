"""민감정보 가리기 (fix_spec 4장). 외부로 보내거나 화면에 보여 줄 사본을 만든다.

새 탐지 규칙을 만들지 않는다. 탐지 모듈의 하드코딩 규칙(KEY-1~4)이 찾은 값만 가린다.
finding에는 줄 번호만 있고 값의 위치는 없으므로, 탐지 모듈의 같은 규칙으로 값을 다시 찾는다
(detector.rules.hardcoded_secret의 secret_values, literal_nodes).
"""
from detector.rules import hardcoded_secret as _rule
from detector.source import SourceSyntaxError, parse_source

from .grouping import normalize

MASK_VALUE = "***"
MASK_LITERAL = '"***"'
MASK_COMMENT = "# (가린 주석)"
COMMENT_RULE = _rule.COMMENT_RULE


class MaskingError(Exception):
    """가리지 못했다. 이 코드는 외부로 보내지 않고 대체 예시로 처리한다."""


def mask(code, analyze_result):
    """탐지된 비밀값을 가린 코드를 돌려준다. 줄 수와 줄 번호는 그대로다.

    값만 가리고 키 이름은 남긴다. 가린 뒤에도 KEY-1~3은 같은 줄에서 탐지되고 KEY-4는 사라진다.
    하나라도 가리지 못하면 MaskingError를 낸다 (덜 가린 코드를 돌려주지 않는다).
    analyze_result는 같은 code를 analyze()한 결과여야 한다.
    """
    text = normalize(code)
    wanted = _secret_findings(analyze_result)
    if not wanted:
        return text
    try:
        masked = _mask(text, wanted)
        _verify(text, masked, wanted)
    except SourceSyntaxError:
        raise MaskingError("코드를 해석할 수 없어 가리지 못했습니다.") from None
    except AttributeError:
        raise MaskingError("탐지 모듈의 구조가 달라져 비밀값의 위치를 찾지 못했습니다.") from None
    return masked


def _secret_findings(analyze_result):
    """하드코딩 규칙의 finding을 {(rule_id, 줄)}로 돌려준다."""
    if not analyze_result.get("ok"):
        raise MaskingError("탐지 결과가 없어 가리지 못했습니다.")
    return {
        (finding["rule_id"], finding["line"])
        for result in analyze_result["results"]
        if result["vuln_id"] == _rule.VULN_ID
        for finding in result["findings"]
    }


def _mask(text, wanted):
    source = parse_source(text)
    flagged = [item for item in _flagged_values(source) if (item[0], item[1].lineno) in wanted]
    located = {(rule_id, node.lineno) for rule_id, node, _ in flagged}
    if located != {item for item in wanted if item[0] != COMMENT_RULE}:
        raise MaskingError("탐지된 비밀값의 위치를 찾지 못했습니다.")

    spans = set()
    for _, node, scope in flagged:
        for literal in _literal_nodes(source, node, scope):
            spans.add((literal.lineno, literal.col_offset, literal.end_lineno, literal.end_col_offset))
    lines = text.split("\n")
    # 뒤쪽부터 바꿔야 앞쪽 위치가 밀리지 않는다.
    for span in sorted(_outermost(spans), reverse=True):
        _replace(lines, span)

    comments = {comment.line: comment.text for comment in source.comments}
    for rule_id, line in wanted:
        if rule_id != COMMENT_RULE:
            continue
        if line not in comments:
            raise MaskingError("탐지된 주석의 위치를 찾지 못했습니다.")
        current = lines[line - 1]
        # 주석은 '#'부터 줄 끝까지다. 값과 함께 이미 지워졌으면 그대로 둔다.
        if current.endswith(comments[line]):
            lines[line - 1] = current[: len(current) - len(comments[line])] + MASK_COMMENT
    return "\n".join(lines)


def _flagged_values(source):
    """탐지 모듈이 KEY-1~3으로 보고하는 값 노드를 (rule_id, 값 노드, 스코프)로 돌려준다. 판단은 탐지 모듈이 한다."""
    return [(secret.rule_id, secret.node, secret.scope) for secret in _rule.secret_values(source)]


def _literal_nodes(source, root, scope):
    """정적 문자열 root를 이루는 리터럴 노드들. 이름은 대입된 곳까지 따라간다."""
    return _rule.literal_nodes(source, root, scope)


def _outermost(spans):
    """다른 범위 안에 들어 있는 범위는 뺀다 (f-string 안의 조각 등)."""
    return [
        span for span in spans
        if not any(other != span and other[:2] <= span[:2] and span[2:] <= other[2:] for other in spans)
    ]


def _replace(lines, span):
    """범위를 "***"로 바꾼다. col_offset은 UTF-8 바이트 기준이라 바이트로 자른다 (탐지 스펙 3.5)."""
    start_line, start_col, end_line, end_col = span
    before = lines[start_line - 1].encode("utf-8")[:start_col].decode("utf-8")
    after = lines[end_line - 1].encode("utf-8")[end_col:].decode("utf-8")
    replacement = MASK_LITERAL
    if end_line > start_line:
        # 여러 줄에 걸친 값은 괄호 안에 줄바꿈을 남겨 줄 수를 그대로 둔다.
        replacement = "(" + MASK_LITERAL + "\n" * (end_line - start_line) + ")"
    lines[start_line - 1:end_line] = (before + replacement + after).split("\n")


def _verify(text, masked, wanted):
    """덜 가려졌거나 탐지 결과가 달라졌으면 MaskingError를 낸다."""
    if masked.count("\n") != text.count("\n"):
        raise MaskingError("가린 뒤 줄 수가 달라졌습니다.")
    source = parse_source(masked)
    remaining = {(finding.rule_id, finding.line) for finding in _rule.check(source)}
    if remaining != {item for item in wanted if item[0] != COMMENT_RULE}:
        raise MaskingError("가린 뒤 탐지 결과가 달라졌습니다.")
    for _, node, scope in _flagged_values(source):
        parts = [part for part in source.static.parts(node, scope) or [] if isinstance(part, (str, bytes))]
        if any(part and part not in (MASK_VALUE, MASK_VALUE.encode()) for part in parts):
            raise MaskingError("가려지지 않은 값이 남아 있습니다.")
