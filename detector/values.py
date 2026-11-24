"""값 모델: 코드의 식 하나가 가질 수 있는 값을 조각(atom)의 나열로 나타낸다.

- S: 코드에 적힌 고정 글자
- T: 추적하는 값 (외부 입력값, 비밀번호, 올린 파일)
- U: 그 밖의 알 수 없는 값. 어디서 왔는지 표시(marks)만 가진다

문자열을 이어 붙이면 조각이 순서대로 이어지고, 분기가 합쳐지면 갈래(alts)가 늘어난다.
"""
from dataclasses import dataclass, replace
from itertools import product

NOCONST = object()  # 상수 값을 모른다는 표시
MAX_ALTS = 12

EXTERNAL = "external"  # 요청에서 온 값, URL 변수
PASSWORD = "password"  # 비밀번호 값
UPLOAD = "upload"  # request.files에서 꺼낸 파일 객체


@dataclass(frozen=True)
class Taint:
    labels: frozenset
    origin: int  # 출발점마다 다른 번호. 같은 값에서 갈라진 조각은 번호가 같다
    line: int
    trail: tuple = ()  # 거쳐 온 줄
    part: str = ""  # "", "filename", "ext", "stem", "ctype"
    key: str = ""  # 요청에서 꺼낸 키 또는 매개변수 이름
    via: str = ""  # 요청의 어느 곳에서 왔는지: "args", "form", "cookies", "json" …
    urlvar: bool = False
    checks: frozenset = frozenset()  # 값 자체에 한 처리: "num", "quote", "secure_name", "safe_join"
    removed: frozenset = frozenset()  # replace·re.sub로 지운 문자
    before: str | None = None  # 처음 이어 붙을 때 바로 앞에 있던 고정 글자
    owner: int = 0  # 마지막으로 이어 붙이거나 묶은 함수 (0은 모듈 최상위)
    state: str = ""  # 비밀번호가 거친 처리: ""(그대로), "PW-2" ~ "PW-5"

    def has(self, label):
        return label in self.labels


@dataclass(frozen=True)
class S:
    text: str


@dataclass(frozen=True)
class T:
    taint: Taint


@dataclass(frozen=True)
class U:
    marks: frozenset = frozenset()


@dataclass(frozen=True)
class Value:
    alts: tuple = ((U(),),)
    const: object = NOCONST  # 상수 하나로 확정된 값 (str, int, bool, None, tuple, frozenset, dict …)
    items: tuple | None = None  # 튜플·리스트 리터럴의 원소
    fields: tuple | None = None  # dict 리터럴의 (키, 값)
    obj: tuple | None = None  # 모델링한 객체: ("request",), ("session",), ("hash", 방식, 넣은 값) …
    wt: frozenset = frozenset()  # 이 값이 참일 때 확정되는 사실
    wf: frozenset = frozenset()  # 이 값이 거짓일 때 확정되는 사실

    # ---- 읽기 ----
    def atoms(self):
        for alt in self.alts:
            yield from alt

    def taints(self, deep=True):
        """이 값(deep이면 원소·필드까지)에 든 Taint들."""
        found = {atom.taint for atom in self.atoms() if isinstance(atom, T)}
        if deep:
            for child in self.children():
                found |= child.taints()
        return found

    def children(self):
        yield from self.items or ()
        for _, value in self.fields or ():
            yield value
        if self.obj and self.obj[0] in ("hash", "path", "uploads"):
            for part in self.obj[1:]:
                if isinstance(part, Value):
                    yield part

    def marks(self, deep=False):
        found = set()
        for atom in self.atoms():
            if isinstance(atom, U):
                found |= atom.marks
        if deep:
            for child in self.children():
                found |= child.marks(True)
        return found

    def has_mark(self, mark, deep=False):
        return mark in self.marks(deep)

    def mark_values(self, prefix):
        """`key:role` 같은 표시에서 prefix 뒤의 값들."""
        return {mark[len(prefix):] for mark in self.marks() if mark.startswith(prefix)}

    @property
    def is_static(self):
        return all(isinstance(atom, S) for atom in self.atoms())

    def texts(self):
        """갈래마다 고정 글자를 이은 문자열. 고정이 아닌 조각이 있으면 None."""
        if not self.is_static:
            return None
        return ["".join(atom.text for atom in alt) for alt in self.alts]

    @property
    def text(self):
        texts = self.texts()
        return texts[0] if texts and len(set(texts)) == 1 else None

    def static_prefix(self):
        """모든 갈래에서 첫 비고정 조각 앞까지의 고정 글자들."""
        prefixes = []
        for alt in self.alts:
            head = []
            for atom in alt:
                if not isinstance(atom, S):
                    break
                head.append(atom.text)
            prefixes.append("".join(head))
        return prefixes

    def field(self, key):
        for name, value in self.fields or ():
            if name == key:
                return value
        return None

    # ---- 바꾸기 ----
    def map_taints(self, change, deep=True):
        """모든 Taint에 change를 적용한다. change가 None을 돌려주면 그 조각은 알 수 없는 값이 된다."""
        def convert(atom):
            if not isinstance(atom, T):
                return atom
            changed = change(atom.taint)
            return U(frozenset({"cleaned"})) if changed is None else T(changed)

        alts = tuple(tuple(convert(atom) for atom in alt) for alt in self.alts)
        items = self.items
        fields = self.fields
        if deep:
            if items is not None:
                items = tuple(item.map_taints(change) for item in items)
            if fields is not None:
                fields = tuple((key, value.map_taints(change)) for key, value in fields)
        return replace(self, alts=_dedupe(alts), items=items, fields=fields, wt=frozenset(), wf=frozenset())

    def plain(self):
        """참·거짓 사실과 객체 정보를 뗀 값."""
        return replace(self, wt=frozenset(), wf=frozenset())


def static(text):
    return Value(alts=((S(str(text)),),), const=text)


def const(value):
    """코드에 적힌 상수. 문자열이 아니어도 글자로는 고정이다."""
    if isinstance(value, bytes):
        return Value(alts=((S(value.decode("utf-8", "replace")),),), const=value)
    return Value(alts=((S("" if value is None else str(value)),),), const=value)


def unknown(*marks):
    return Value(alts=((U(frozenset(marks)),),))


def tainted(taint):
    return Value(alts=((T(taint),),))


def boolean(wt=frozenset(), wf=frozenset(), marks=()):
    return Value(alts=((U(frozenset(marks)),),), wt=frozenset(wt), wf=frozenset(wf))


def of_taints(taints, *marks):
    """Taint 여러 개를 한 갈래에 담은 값 (알 수 없는 함수를 거친 결과 등)."""
    atoms = tuple(T(taint) for taint in sorted(taints, key=_taint_order))
    if marks or not atoms:
        atoms += (U(frozenset(marks)),)
    return Value(alts=(atoms,))


def _taint_order(taint):
    return (taint.origin, taint.part, taint.state, sorted(taint.labels), sorted(taint.checks), sorted(taint.removed))


def _dedupe(alts):
    return tuple(dict.fromkeys(alts))


def _collapse(alts):
    """갈래가 너무 많으면 조각을 한 갈래로 모은다 (순서와 앞 글자 정보는 버린다)."""
    atoms = []
    for alt in alts:
        for atom in alt:
            if not isinstance(atom, S) and atom not in atoms:
                atoms.append(atom)
    return (tuple(atoms) or (U(),),)


def merge(first, second):
    """두 분기에서 온 값을 합친다."""
    if first is second or first == second:
        return first
    alts = _dedupe(first.alts + second.alts)
    if len(alts) > MAX_ALTS:
        alts = _collapse(alts)
    same_const = first.const is not NOCONST and second.const is not NOCONST and _same(first.const, second.const)
    items = None
    if first.items is not None and second.items is not None and len(first.items) == len(second.items):
        items = tuple(merge(a, b) for a, b in zip(first.items, second.items))
    fields = None
    if first.fields is not None and second.fields is not None:
        keys = list(dict.fromkeys([key for key, _ in first.fields] + [key for key, _ in second.fields]))
        fields = tuple(
            (key, _merge_optional(first.field(key), second.field(key))) for key in keys
        )
    return Value(
        alts=alts,
        const=first.const if same_const else NOCONST,
        items=items,
        fields=fields,
        obj=first.obj if first.obj == second.obj else None,
    )


def _merge_optional(first, second):
    if first is None:
        return second
    if second is None:
        return first
    return merge(first, second)


def _same(a, b):
    try:
        return type(a) is type(b) and a == b
    except Exception:  # noqa: BLE001 - 비교할 수 없는 상수
        return False


def merge_all(values):
    values = list(values)
    if not values:
        return unknown()
    result = values[0]
    for value in values[1:]:
        result = merge(result, value)
    return result


def join(values, owner, line):
    """문자열 이어 붙이기. 추적하는 조각에는 바로 앞의 고정 글자와 이어 붙인 함수·줄을 적는다."""
    combos = list(product(*[value.alts for value in values])) if values else [()]
    if len(combos) > MAX_ALTS:
        flat = tuple(atom for value in values for atom in _collapse(value.alts)[0])
        combos = [(flat,)]
    alts = []
    for combo in combos:
        atoms = []
        for alt in combo:
            for atom in alt:
                if isinstance(atom, S) and atoms and isinstance(atoms[-1], S):
                    atoms[-1] = S(atoms[-1].text + atom.text)
                elif not (isinstance(atom, S) and atom.text == ""):
                    atoms.append(atom)
        marked = []
        for index, atom in enumerate(atoms):
            if isinstance(atom, T):
                taint = atom.taint
                before = taint.before
                if before is None:
                    before = atoms[index - 1].text if index and isinstance(atoms[index - 1], S) else ""
                trail = taint.trail if line in taint.trail else taint.trail + (line,)
                atom = T(replace(taint, before=before, owner=owner, trail=trail))
            elif isinstance(atom, U) and len(atoms) > 1:
                # 알 수 없는 값도 어느 함수에서 이어 붙였는지 적어 둔다 (보고할 줄을 정할 때 쓴다)
                kept = {mark for mark in atom.marks if not mark.startswith("owner:")}
                atom = U(frozenset(kept | {f"owner:{owner}"}))
            marked.append(atom)
        alts.append(tuple(marked) or (S(""),))
    alts = _dedupe(tuple(alts))
    result = Value(alts=alts)
    text = result.text
    return replace(result, const=text) if text is not None else result


def owned(value, owner, line):
    """튜플·dict로 묶을 때: 든 조각에 묶은 함수와 줄을 적는다."""
    def change(taint):
        trail = taint.trail if line in taint.trail else taint.trail + (line,)
        return replace(taint, owner=owner, trail=trail)

    return value.map_taints(change)


def collection_of(value):
    """상수 모음(list·tuple·set·dict 리터럴)이면 그 원소들의 집합, 아니면 None."""
    constant = value.const
    if isinstance(constant, (tuple, list, set, frozenset)):
        return set(constant)
    if isinstance(constant, dict):
        return set(constant)
    if value.items is not None and all(item.const is not NOCONST for item in value.items):
        return {item.const for item in value.items if _hashable(item.const)}
    if value.fields is not None:
        return {key for key, _ in value.fields}
    return None


def _hashable(item):
    try:
        hash(item)
    except TypeError:
        return False
    return True
