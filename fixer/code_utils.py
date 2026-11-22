"""학생 코드의 줄 범위 계산과 검증용 적용. 코드를 실행하지 않는다."""
import ast


def split_lines(code):
    return code.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def number_lines(code):
    return "\n".join(f"{i}: {line}" for i, line in enumerate(split_lines(code), 1))


def _parse(code):
    try:
        return ast.parse(code.replace("\r\n", "\n").replace("\r", "\n"))
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise ValueError("코드를 해석할 수 없습니다.") from exc


def find_target_range(code, line):
    """finding 줄을 포함하는 가장 안쪽 함수(데코레이터 포함). 함수 밖이면 그 줄 하나."""
    if not 1 <= line <= len(split_lines(code)):
        raise ValueError("finding 줄 번호가 코드 범위를 벗어났습니다.")

    best = None
    for node in ast.walk(_parse(code)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = min([node.lineno] + [d.lineno for d in node.decorator_list])
        if start <= line <= node.end_lineno:
            if best is None or node.end_lineno - start < best[1] - best[0]:
                best = (start, node.end_lineno, node.name)
    return best if best else (line, line, None)


def extract_range(code, start, end):
    return "\n".join(split_lines(code)[start - 1:end])


def apply_fix(code, start, end, fixed_code, added_top_level):
    """target_range를 교체하고 import를 넣는다. 반환: (고친 코드, 고친 범위의 새 시작, 끝)"""
    lines = split_lines(code)
    fixed = split_lines(fixed_code.strip("\n"))
    added = [l for item in added_top_level for l in split_lines(item.strip("\n"))]

    imports = [n for n in _parse(code).body if isinstance(n, (ast.Import, ast.ImportFrom))]
    insert_at = imports[-1].end_lineno if imports else 0

    # 교체로 줄 수가 달라진 만큼 삽입 위치를 보정한다
    delta = len(fixed) - (end - start + 1)
    if insert_at > end:
        insert_at += delta
    elif insert_at >= start:  # 함수 밖 finding이 import 줄 자체인 경우
        insert_at = start - 1 + len(fixed)

    patched = lines[:start - 1] + fixed + lines[end:]
    patched[insert_at:insert_at] = added

    new_start = start + len(added) if insert_at < start else start
    return "\n".join(patched), new_start, new_start + len(fixed) - 1
