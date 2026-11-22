"""이름 사전 맞추기: 이름을 단어로 나눠 사전의 낱말이 들어 있는지 본다."""
import re


def split_words(name):
    """`DB_PASSWORD`, `apiKey` → ["db", "password"], ["api", "key"]. `_`·대문자 경계·숫자에서 나눈다."""
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)  # apiKey → api Key
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)  # APIKey → API Key
    return [word.lower() for word in re.findall(r"[A-Za-z]+", spaced)]


def has_word(name, dictionary):
    """dictionary의 낱말이 name의 단어로 들어 있는지. 대소문자는 무시한다.

    `api_key`처럼 `_`로 이은 낱말은 연속한 두 단어와 맞춘다.
    DB_PASSWORD, SECRET_KEY, apiKey는 해당하고 monkey, keyboard, tokens는 해당하지 않는다.
    """
    words = split_words(name)
    for entry in dictionary:
        sequence = entry.split("_")
        size = len(sequence)
        if any(words[start : start + size] == sequence for start in range(len(words) - size + 1)):
            return True
    return False
