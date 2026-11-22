"""소스 문자열 읽기. 학생 코드는 실행하지 않고 ast와 tokenize로 읽기만 한다."""
import ast
import io
import tokenize
from dataclasses import dataclass

from .names import Names
from .static_str import StaticStrings


class SourceSyntaxError(Exception):
    """문법 오류라서 판정할 수 없다 (C5)."""

    def __init__(self, line):
        self.line = line
        self.message = f"{line}번째 줄에 문법 오류가 있어요."
        super().__init__(self.message)


@dataclass(frozen=True)
class Comment:
    line: int
    text: str  # '#'부터 줄 끝까지


@dataclass(frozen=True)
class Source:
    """규칙들이 함께 쓰는 분석 재료. 원본 코드 문자열은 들고 있지 않는다."""

    tree: ast.Module
    comments: tuple[Comment, ...]
    names: Names
    static: StaticStrings


def parse_source(code: str) -> Source:
    # ast와 tokenize의 줄 번호가 어긋나지 않게 줄바꿈을 \n 하나로 맞춘다 (줄 수는 그대로다).
    text = code.removeprefix("﻿").replace("\r\n", "\n").replace("\r", "\n")
    try:
        tree = ast.parse(text)
        comments = _read_comments(text)
    except SyntaxError as error:  # IndentationError, TabError 포함
        raise SourceSyntaxError(error.lineno or 1) from None
    except tokenize.TokenError as error:
        raise SourceSyntaxError(error.args[1][0]) from None
    except ValueError:  # 널 문자가 섞인 소스 (3.12부터는 SyntaxError로 온다)
        raise SourceSyntaxError(1) from None
    names = Names(tree)
    return Source(tree, comments, names, StaticStrings(tree, names))


def _read_comments(text):
    """주석은 AST에 없으므로 tokenize의 COMMENT 토큰으로 읽는다."""
    tokens = tokenize.generate_tokens(io.StringIO(text).readline)
    return tuple(
        Comment(token.start[0], token.string) for token in tokens if token.type == tokenize.COMMENT
    )
