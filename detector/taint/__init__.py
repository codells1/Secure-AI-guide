"""오염 분석 (스펙 3.1~3.3): 사용자 입력이 위험 함수의 위험한 인자 자리까지 가는지 추적한다."""
from .engine import SinkHit, find_sink_hits
from .spec import CLEAN, CallInfo, Marked, Same, Sink, TaggedCall, TaintSpec, Update, register
from .values import SANITIZED, Kind, Part

__all__ = [
    "CLEAN",
    "SANITIZED",
    "CallInfo",
    "Kind",
    "Marked",
    "Part",
    "Same",
    "Sink",
    "SinkHit",
    "TaggedCall",
    "TaintSpec",
    "Update",
    "find_sink_hits",
    "register",
]
