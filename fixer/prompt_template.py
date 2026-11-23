"""③ 원래 쓰던 LLM에 붙여넣을 프롬프트 (fix_spec 8장).

API를 쓰지 않고 템플릿으로 만든다. 조건 목록은 고정이고, "내 코드에 맞춘 고치는 방법" 한 줄만
API 응답(fix_instruction)에서 온다. 검증을 통과하지 못했으면 그 줄을 빼고 만든다.
"""
import re

from detector.result import MESSAGES

from .grouping import MODULE

# fix_spec 8장의 템플릿 그대로다.
TEMPLATE = """내 Flask 프로젝트의 {file} 파일 {location}에 "{vuln_name}" 보안 취약점이 있어.
문제: {message}

[지금 코드]
{fence}python
{target_code}
{fence}

다음 조건대로 고쳐줘.
1. 다음 방식으로 고칠 것: {allowed_fixes}
   {fix_instruction}
2. 이 취약점과 관련 없는 기능은 바꾸지 말 것
3. 고친 코드 전체와 새로 필요한 import를 보여줄 것
4. 무엇을 바꿨는지, 기존 기능이 그대로 동작하는지 확인하는 방법을 설명할 것
5. 고친 뒤, 고친 코드에 같은 취약점이 남아 있는지 스스로 다시 검토하고, 남아 있으면 한 번 더 고칠 것
6. 프로젝트의 다른 파일도 볼 수 있다면, 같은 문제가 있는 곳을 함께 알려줄 것"""
INSTRUCTION_LINE = "   {fix_instruction}\n"
MIN_FENCE = 3
DEFAULT_FILE = "app.py"
MAX_FILE_NAME = 100


def build_prompt(filename, group, card, target_code, fix_instruction=None):
    """묶음 하나의 ③ 프롬프트를 만든다.

    target_code는 가린 코드의 target_range 원문이다 (학생이 다른 AI 서비스에 붙여넣기 때문).
    fix_instruction은 V1~V3를 통과한 응답의 것만 넘긴다. 없으면 그 줄을 통째로 뺀다.
    """
    values = {
        "file": _file_name(filename),
        "location": _location(group),
        "vuln_name": card.name,
        "message": "\n".join(MESSAGES[rule_id] for rule_id in group.rule_ids),
        "fence": "`" * max(MIN_FENCE, _longest_backtick_run(target_code) + 1),
        "target_code": target_code.rstrip("\n"),
        "allowed_fixes": " / ".join(card.allowed_fixes),
    }
    template = TEMPLATE
    instruction = " ".join(fix_instruction.split()) if isinstance(fix_instruction, str) else ""
    if instruction:
        values["fix_instruction"] = instruction
    else:
        template = template.replace(INSTRUCTION_LINE, "")
    # format은 템플릿의 자리만 채운다. 값 안의 중괄호(학생 코드의 dict, f-string)는 건드리지 않는다.
    return template.format(**values)


def _location(group):
    """함수 안이면 "{함수 이름} 함수", 함수 밖이면 "{line}번째 줄"."""
    if group.function_name != MODULE:
        return f"{group.function_name} 함수"
    return f"{group.findings[0]['line']}번째 줄"


def _file_name(filename):
    """경로와 제어 문자를 뺀 파일 이름. 비어 있으면 app.py."""
    name = re.split(r"[\\/]", filename if isinstance(filename, str) else "")[-1]
    name = "".join(character for character in name if character.isprintable()).strip()
    return name[:MAX_FILE_NAME] or DEFAULT_FILE


def _longest_backtick_run(text):
    return max((len(run) for run in re.findall(r"`+", text)), default=0)
