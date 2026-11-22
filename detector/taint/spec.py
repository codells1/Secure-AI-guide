"""취약점별 도착점·정화 규칙 등록 (스펙 3.3).

취약점 모듈이 TaintSpec을 만들어 register()로 등록하면, 엔진은 그 명세만 보고 움직인다.
"""
import ast
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Sink:
    """도착점: 어떤 호출의 몇 번째 인자가 위험한지."""

    function: str | None = None  # 별칭을 푼 전체 이름으로 찾는다: "flask.render_template_string"
    method: str | None = None  # 메서드 이름으로 찾는다: 아무 객체의 `.execute(...)`
    arg: int = 0  # 위험한 인자 자리
    keywords: tuple[str, ...] = ()  # 그 인자를 키워드로 줄 때의 이름들
    role: str = ""  # 한 취약점 안에서 도착점 종류를 나눌 때 쓴다
    # method 도착점을 이 호출로 만든 객체의 메서드로 한정한다: ("requests.Session", "httpx.Client")
    objects: tuple[str, ...] = ()


@dataclass(frozen=True)
class TaggedCall:
    """표시(tag)를 붙일지 물어볼 때 취약점 모듈에 넘기는 호출 정보."""

    name: str | None  # 별칭을 푼 함수 이름: "re.sub"
    method: str | None  # 오염된 값의 메서드를 부른 경우 그 이름: "replace"
    texts: tuple  # 위치 인자가 문자열 리터럴이면 그 글자, 아니면 None
    keywords: tuple = ()  # 키워드 인자 이름들 (`count=1` 같은 인자가 있는지 볼 때 쓴다)


@dataclass(frozen=True)
class CallInfo:
    """on_call 훅에 넘기는 호출 정보. 인자의 값들은 엔진이 계산한 것이다."""

    node: ast.Call
    name: str | None  # 별칭을 푼 함수 이름
    method: str | None  # 메서드 호출이면 메서드 이름
    receiver: tuple | None  # 메서드를 부르는 대상의 값들
    arguments: tuple  # 위치 인자의 값들
    keywords: dict  # 키워드 인자 이름 → 값들
    scope: ast.AST | None  # 호출이 있는 함수 (모듈 최상위면 None)
    source: object  # 분석 중인 소스 (이름을 풀 때 쓴다)

    def argument(self, index, name):
        """index번째 위치 인자 또는 name 키워드 인자의 값들. 없으면 None."""
        if len(self.arguments) > index and not any(
            isinstance(argument, ast.Starred) for argument in self.node.args[: index + 1]
        ):
            return self.arguments[index]
        return self.keywords.get(name)


# on_call 훅이 돌려줄 수 있는 결과. None을 돌려주면 엔진의 기본 처리로 넘어간다.
CLEAN = "clean"  # 결과는 정화된 값이다


@dataclass(frozen=True)
class Marked:
    """결과에 표시를 붙인다. 오염된 값을 받았으면 오염, 아니면 모르는 값이 된다."""

    tags: frozenset


@dataclass(frozen=True)
class Same:
    """주어진 값들을 그대로 결과로 쓴다 (`.encode()`처럼 내용을 바꾸지 않는 호출)."""

    group: tuple


@dataclass(frozen=True)
class Update:
    """호출 대상 변수의 값을 group으로 바꾼다 (`h.update(pw)`처럼 객체 안에 값을 넣는 호출)."""

    group: tuple


@dataclass(frozen=True)
class TaintSpec:
    vuln_id: str
    sinks: tuple[Sink, ...]
    # 결과를 오염되지 않은 값으로 보는 함수 (별칭을 푼 이름)
    sanitizers: frozenset[str] = frozenset()
    # 인자들을 조각 그대로 이어 붙인 결과를 내는 함수 (`os.path.join` 등)
    propagators: frozenset[str] = frozenset()
    # 오염된 값을 다루는 호출을 보고, 결과에 붙일 표시들을 돌려주는 함수.
    # 표시가 없는 호출을 거치면 그동안 붙은 표시는 사라진다 (오염은 남는다).
    tagger: Callable[[TaggedCall], frozenset] | None = None
    # 출발점. None이면 스펙 3.1의 요청 값 전체를 쓴다.
    source_attributes: frozenset[str] | None = None
    source_calls: frozenset[str] | None = None
    url_variables: bool = True  # 라우트 URL 변수를 출발점으로 볼지
    # 호출 인자가 아닌 자리의 값을 볼 때 쓴다: 분석할 소스를 받아 (식 노드, 역할)들을 돌려주는 함수.
    # 그 식에 올 수 있는 값들이 도착점과 같은 방식으로 기록된다.
    probes: Callable | None = None
    # 첨자·호출 식이 출발점인지 정하는 함수: (식 노드, 그 식이 있는 함수, 소스) → bool
    extra_source: Callable | None = None
    # 이 이름의 변수에 대입되는 값을 출발점으로 볼지 정하는 함수: (변수 이름) → bool.
    # 이미 오염됐거나 표시가 붙은 값(정화된 값, 난수 등)은 그대로 둔다.
    source_names: Callable | None = None
    # 호출 결과를 명세가 정하는 함수: (CallInfo) → CLEAN | Marked | Same | Update | None
    on_call: Callable | None = None
    # 오염된 값의 이 메서드를 거쳐도 그동안 붙은 표시를 유지한다
    tag_keeping_methods: frozenset[str] = frozenset()
    # 오염되지 않은 값에서 첨자·속성으로 꺼내도 유지할 표시
    sticky_tags: frozenset[str] = frozenset()
    # `Path("d") / name`처럼 나누기 연산을 경로 이어 붙이기로 볼지
    division_joins: bool = False


_registry = {}


def register(spec):
    """명세를 등록하고 그대로 돌려준다. 등록된 도착점의 결과로는 어떤 분석에서도 오염을 전파하지 않는다."""
    _registry[spec.vuln_id] = spec
    return spec


def registered_specs():
    return tuple(_registry.values())
