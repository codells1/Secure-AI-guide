"""취약점 규칙 10종. 스펙 4장 순서대로 둔다.

규칙 모듈은 `VULN_ID`와 `check(source)`를 가진다.
- 학생 응답을 받아야 판정할 수 있는 규칙은 `check` 대신 `evaluate(source, user_input)`를 가진다.
  (findings, needs_user_input)을 돌려준다.
- 학생 응답으로 확인 표시만 하는 규칙은 `is_acknowledged(user_input)`도 가진다.
"""
from . import (
    debug_error_exposure,
    file_upload,
    hardcoded_secret,
    idor,
    login_attempt_limit,
    password_storage,
    path_traversal,
    sql_injection,
    ssrf,
    ssti,
)

RULES = (
    sql_injection,
    ssti,
    file_upload,
    path_traversal,
    idor,
    ssrf,
    debug_error_exposure,
    hardcoded_secret,
    password_storage,
    login_attempt_limit,
)
