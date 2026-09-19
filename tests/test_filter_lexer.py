import random

from sentinel.filter.lexer import AND, LPAREN, MAX_TOKENS, NOT, OR, RPAREN, WORD, Token, tokenize
from sentinel.filter.nodes import FilterError


def kinds(text: str) -> list[str]:
    tokens, error = tokenize(text)
    assert error is None, error
    return [t.kind for t in tokens]


def test_words_operators_and_parentheses() -> None:
    tokens, error = tokenize("tcp and (port 80 or port 443)")
    assert error is None
    assert tokens == [
        Token(WORD, "tcp", 0),
        Token(AND, "and", 4),
        Token(LPAREN, "(", 8),
        Token(WORD, "port", 9),
        Token(WORD, "80", 14),
        Token(OR, "or", 17),
        Token(WORD, "port", 20),
        Token(WORD, "443", 25),
        Token(RPAREN, ")", 28),
    ]


def test_symbol_forms_of_the_operators() -> None:
    assert kinds("a&&b||!c") == [WORD, AND, WORD, OR, NOT, WORD]
    tokens, _ = tokenize("a&&b")
    assert [t.text for t in tokens] == ["a", "&&", "b"]


def test_keywords_are_case_insensitive_and_keep_their_spelling() -> None:
    tokens, _ = tokenize("TCP AND Not udp")
    assert [(t.kind, t.text) for t in tokens] == [
        (WORD, "TCP"),
        (AND, "AND"),
        (NOT, "Not"),
        (WORD, "udp"),
    ]


def test_addresses_networks_and_ranges_are_single_words() -> None:
    for word in ("10.0.0.1", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32", "80-90", "::1"):
        tokens, error = tokenize(word)
        assert error is None
        assert [t.text for t in tokens] == [word]


def test_any_whitespace_separates() -> None:
    assert kinds("tcp\tand\nudp\r\n  or  icmp") == [WORD, AND, WORD, OR, WORD]
    assert kinds("   ") == []
    assert kinds("") == []


def test_positions_are_indexes_into_the_text() -> None:
    text = "  tcp   and udp"
    tokens, _ = tokenize(text)
    assert [text[t.pos : t.pos + len(t.text)] for t in tokens] == ["tcp", "and", "udp"]


def test_unexpected_characters() -> None:
    cases = {
        "tcp @ udp": FilterError("unexpected character '@'", 4),
        "tcp & udp": FilterError("unexpected '&', did you mean '&&'?", 4),
        "tcp | udp": FilterError("unexpected '|', did you mean '||'?", 4),
        "port é": FilterError("unexpected character 'é'", 5),
        "a = b": FilterError("unexpected character '='", 2),
    }
    for text, expected in cases.items():
        tokens, error = tokenize(text)
        assert error == expected, text
        assert tokens  # what came before the error is still returned


def test_a_filter_with_too_many_tokens_is_an_error() -> None:
    ok, error = tokenize(" ".join(["tcp"] * MAX_TOKENS))
    assert error is None
    assert len(ok) == MAX_TOKENS
    _, error = tokenize(" ".join(["tcp"] * (MAX_TOKENS + 1)))
    assert error is not None
    assert "more than 1000 tokens" in error.message


def test_random_text_never_raises_and_positions_are_in_range() -> None:
    rng = random.Random(8)
    alphabet = "tcp and or not()!&|.:/-0123456789 \t\néλ@#"
    for _ in range(2000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        tokens, error = tokenize(text)
        for t in tokens:
            assert text[t.pos : t.pos + len(t.text)] == t.text
        if error is not None:
            assert 0 <= error.position < len(text)
