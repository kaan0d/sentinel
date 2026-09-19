"""Splits filter text into tokens. Errors are returned, never raised."""

from dataclasses import dataclass

from sentinel.filter.nodes import FilterError

MAX_TOKENS = 1000

LPAREN, RPAREN, AND, OR, NOT, WORD = "(", ")", "and", "or", "not", "word"

# Address, network and number characters: 10.0.0.0/8, 2001:db8::1, 80-90.
_WORD_PUNCTUATION = "._:/-"
_KEYWORDS = {"and": AND, "or": OR, "not": NOT}


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    text: str  # as written
    pos: int  # index into the filter text


def _is_word_char(c: str) -> bool:
    return c.isascii() and (c.isalnum() or c in _WORD_PUNCTUATION)


def tokenize(text: str) -> tuple[list[Token], FilterError | None]:
    """The tokens found before the first error (or all of them), and that error if any."""
    tokens: list[Token] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if len(tokens) >= MAX_TOKENS:
            return tokens, FilterError(f"filter has more than {MAX_TOKENS} tokens", i)
        if c in "()":
            tokens.append(Token(c, c, i))
            i += 1
        elif c == "!":
            tokens.append(Token(NOT, c, i))
            i += 1
        elif text.startswith(("&&", "||"), i):
            tokens.append(Token(AND if c == "&" else OR, text[i : i + 2], i))
            i += 2
        elif _is_word_char(c):
            j = i
            while j < len(text) and _is_word_char(text[j]):
                j += 1
            word = text[i:j]
            tokens.append(Token(_KEYWORDS.get(word.lower(), WORD), word, i))
            i = j
        elif c in "&|":
            return tokens, FilterError(f"unexpected {c!r}, did you mean {c * 2!r}?", i)
        else:
            return tokens, FilterError(f"unexpected character {c!r}", i)
    return tokens, None
