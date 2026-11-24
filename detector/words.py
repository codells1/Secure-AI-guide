"""이름 사전: 이름을 단어로 나눠 사전의 낱말이 들어 있는지 본다 (스펙 4.5, 4.8, 4.9, 4.10)."""
import re

# 비밀번호 값의 이름 (4.9, 4.10)
PASSWORD_WORDS = ("password", "passwd", "pwd", "pw")
PASSWORD_KOREAN = ("비밀번호", "패스워드", "암호")

# 비밀 값의 이름 (4.8). `key`는 앞에 수식어가 붙거나 이름 전체가 `key`일 때만 해당한다.
SECRET_WORDS = (*PASSWORD_WORDS, "secret", "token", "apikey")
KEY_QUALIFIERS = frozenset(
    {"api", "secret", "private", "access", "auth", "encryption", "encrypt", "signing", "sign",
     "jwt", "aes", "hmac", "master", "session", "crypto", "cipher"}
)

# 대상을 고르는 id류 요청값의 키 (4.5)
ID_WORDS = ("id", "uid", "idx", "no", "num", "seq", "pk", "userid")
IDENTITY_WORDS = ("username", "email")
NOT_ID_WORDS = ("page",)

# 소유자 필드, 역할, 관리자 (4.5)
OWNER_WORDS = ("user", "owner", "author", "writer", "member", "uid", "userid", "username")
ROLE_WORDS = ("role", "admin", "level", "grade", "staff", "superuser", "permission")
ROLE_KOREAN = ("권한", "등급")
ADMIN_WORDS = ("admin", "administrator", "superuser", "staff")
ADMIN_VALUES = frozenset({"admin", "administrator", "관리자"})

# 인증 실패 횟수 (4.10)
COUNTER_WORDS = (
    "fail", "fails", "failed", "failure", "failures", "attempt", "attempts", "try", "tries",
    "retry", "retries", "count", "counts", "cnt", "lock", "locked", "wrong", "limit", "max",
)
COUNTER_KOREAN = ("실패", "횟수", "잠금", "시도")


def split_words(name):
    """`DB_PASSWORD`, `apiKey` → ["db", "password"], ["api", "key"]. `_`·대소문자 경계·숫자에서 나눈다."""
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [word.lower() for word in re.findall(r"[A-Za-z]+", spaced)]


def has_word(name, dictionary):
    """dictionary의 낱말이 name의 단어로 들어 있는지. monkey, keyboard, tokens는 해당하지 않는다."""
    words = split_words(name)
    return any(entry in words for entry in dictionary)


def is_password_name(name):
    return any(word in name for word in PASSWORD_KOREAN) or has_word(name, PASSWORD_WORDS)


def is_secret_name(name):
    words = split_words(name)
    if any(entry in words for entry in SECRET_WORDS):
        return True
    if words == ["key"]:
        return True
    return any(
        word == "key" and index > 0 and words[index - 1] in KEY_QUALIFIERS for index, word in enumerate(words)
    )


def is_id_key(name):
    words = split_words(name)
    if any(entry in words for entry in NOT_ID_WORDS):
        return False
    return any(entry in words for entry in ID_WORDS)


def is_identity_key(name):
    return has_word(name, IDENTITY_WORDS)


def is_owner_field(name):
    return has_word(name, OWNER_WORDS)


def is_role_key(name):
    return any(word in name for word in ROLE_KOREAN) or has_word(name, ROLE_WORDS)


def is_admin_key(name):
    return has_word(name, ADMIN_WORDS)


def is_counter_name(name):
    return any(word in name for word in COUNTER_KOREAN) or has_word(name, COUNTER_WORDS)


# 시간을 뜻하는 이름: 경과 시간을 숫자와 비교하는 것은 횟수 제한이 아니다 (4.10)
TIME_WORDS = (
    "time", "seconds", "second", "sec", "secs", "minutes", "minute", "hours", "timestamp", "now", "datetime",
    "elapsed", "since", "until", "expire", "expires", "expiry", "window", "duration", "timeout",
)


def is_time_name(name):
    return has_word(name, TIME_WORDS)
