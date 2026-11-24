"""4.1 SQL 삽입 (sql_injection): SQL-1, SQL-2, SQL-3."""
import re

from ..result import Finding
from ..values import EXTERNAL, S, T, U
from .common import covered, flow_finding

VULN_ID = "sql_injection"

EXECUTE_METHODS = frozenset({"execute", "executemany", "executescript", "raw"})
TEXT_FUNCTIONS = frozenset({"sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text"})
QUERY_KEYWORDS = ("sql", "query", "operation", "statement", "raw_query", "text")

_ORDER_BY = re.compile(r"\border\s+by\s+(?:[\w.`\"]+\s*(?:asc|desc)?\s*,\s*)*$", re.IGNORECASE)


def _query(event):
    """이 호출이 SQL 문장을 실행하는 자리면 그 문장의 값."""
    if event.method in EXECUTE_METHODS or event.name in TEXT_FUNCTIONS:
        for keyword in QUERY_KEYWORDS:
            if keyword in event.kwargs:
                return event.kwargs[keyword]
        return event.args[0] if event.args else None
    return None


def check(source):
    program = source.flow
    findings = []
    for event in program.calls:
        query = _query(event)
        if query is None:
            continue
        for alt in query.alts:
            external = False
            for atom in alt:
                if isinstance(atom, T) and atom.taint.has(EXTERNAL) and not covered(atom.taint, event.facts):
                    external = True
                    rule_id = "SQL-2" if _ORDER_BY.search(atom.taint.before or "") else "SQL-1"
                    findings.append(flow_finding(program, event, atom.taint, rule_id))
            if external:
                continue
            # 사용자 입력이 아니어도, 고정 문장에 고정이 아닌 값을 이어 붙였으면 SQL-3
            has_text = any(isinstance(atom, S) and atom.text.strip() for atom in alt)
            dynamic = [atom for atom in alt if isinstance(atom, U)]
            if has_text and dynamic:
                findings.append(Finding(_built_line(event, dynamic), "SQL-3"))
    return findings


def _built_line(event, atoms):
    """이어 붙인 함수가 도착점까지 값을 넘긴 줄 (스펙 3.4)."""
    here = id(event.function) if event.function is not None else 0
    owners = {int(mark[6:]) for atom in atoms for mark in atom.marks if mark.startswith("owner:")}
    if not event.stack or here in owners or not owners:
        return event.line
    for function_id, call_line in event.stack:
        if function_id in owners:
            return call_line
    return event.stack[0][1]
