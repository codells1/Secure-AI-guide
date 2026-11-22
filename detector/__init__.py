"""취약점 탐지(판정) 모듈. 판정 기준은 docs/detection_spec.md 하나뿐이다."""
from .analyzer import analyze

__all__ = ["analyze"]
