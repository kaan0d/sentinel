"""Recursive-descent parser for the filter language.

    expr      := or
    or        := and ( ("or" | "||") and )*
    and       := not ( ("and" | "&&") not )*
    not       := ("not" | "!") not | primary
    primary   := "(" expr ")" | primitive
    primitive := PROTO [ qualified ]           tcp port 80  ==  tcp and port 80
               | qualified | "vlan" [ NUMBER ]
    qualified := [ "src" | "dst" ] ( "host" ADDRESS | "net" NETWORK
                                   | "port" NUMBER | "portrange" NUMBER "-" NUMBER )
    PROTO     := ip | ip6 | arp | tcp | udp | icmp | dns | http | tls

Keywords are case-insensitive. Errors carry the position of the offending token and are
returned, never raised: a filter comes from a person, and a typo must not be a traceback."""

from ipaddress import ip_address, ip_network

from sentinel.filter.lexer import AND, LPAREN, NOT, OR, RPAREN, WORD, Token, tokenize
from sentinel.filter.nodes import (
    PROTOCOLS,
    QUALIFIERS,
    And,
    Direction,
    Expr,
    FilterError,
    Host,
    Net,
    Not,
    Or,
    Port,
    Proto,
    Vlan,
)

MAX_DEPTH = 100


class _Fail(Exception):
    """Internal: parsing stopped. Always caught inside this module."""

    def __init__(self, message: str, pos: int) -> None:
        super().__init__(message)
        self.error = FilterError(message, pos)


def _q(text: str) -> str:
    """User text for an error message, shortened so a huge token cannot flood the terminal."""
    return repr(text if len(text) <= 40 else text[:37] + "...")


def _number(token: Token, what: str, top: int) -> int:
    digits = token.text.isascii() and token.text.isdigit() and len(token.text) <= 10
    if not digits or int(token.text) > top:
        raise _Fail(f"expected {what} (0-{top}), got {_q(token.text)}", token.pos)
    return int(token.text)


class _Parser:
    def __init__(self, tokens: list[Token], end: int) -> None:
        self._tokens = tokens
        self._end = end  # position reported for "unexpected end of filter"
        self._i = 0

    def _peek(self) -> Token | None:
        return self._tokens[self._i] if self._i < len(self._tokens) else None

    def _take(self, expected: str) -> Token:
        token = self._peek()
        if token is None:
            raise _Fail(f"unexpected end of filter, expected {expected}", self._end)
        self._i += 1
        return token

    def _accept(self, kind: str) -> bool:
        token = self._peek()
        if token is not None and token.kind == kind:
            self._i += 1
            return True
        return False

    def parse(self) -> Expr:
        expr = self._or(0)
        token = self._peek()
        if token is not None:
            raise _Fail(
                f"unexpected {_q(token.text)}, expected 'and', 'or' or end of filter", token.pos
            )
        return expr

    def _or(self, depth: int) -> Expr:
        items = [self._and(depth)]
        while self._accept(OR):
            items.append(self._and(depth))
        if len(items) == 1:
            return items[0]
        return Or(
            tuple(x for item in items for x in (item.operands if isinstance(item, Or) else (item,)))
        )

    def _and(self, depth: int) -> Expr:
        items = [self._not(depth)]
        while self._accept(AND):
            items.append(self._not(depth))
        if len(items) == 1:
            return items[0]
        return And(
            tuple(
                x for item in items for x in (item.operands if isinstance(item, And) else (item,))
            )
        )

    def _not(self, depth: int) -> Expr:
        token = self._peek()
        if token is not None and token.kind == NOT:
            self._i += 1
            self._check_depth(depth, token)
            return Not(self._not(depth + 1))
        return self._primary(depth)

    @staticmethod
    def _check_depth(depth: int, token: Token) -> None:
        if depth >= MAX_DEPTH:
            raise _Fail(f"filter is nested more than {MAX_DEPTH} levels deep", token.pos)

    def _primary(self, depth: int) -> Expr:
        token = self._take("a filter primitive or '('")
        if token.kind == LPAREN:
            self._check_depth(depth, token)
            inner = self._or(depth + 1)
            if not self._accept(RPAREN):
                after = self._peek()
                raise _Fail("expected ')'", after.pos if after else self._end)
            return inner
        if token.kind != WORD:
            raise _Fail(
                f"unexpected {_q(token.text)}, expected a filter primitive or '('", token.pos
            )
        return self._word(token)

    def _word(self, token: Token) -> Expr:
        word = token.text.lower()
        if word in QUALIFIERS:
            return self._qualified(token)
        if word == "vlan":
            nxt = self._peek()
            if nxt is not None and nxt.kind == WORD and nxt.text.isdigit():
                self._i += 1
                return Vlan(_number(nxt, "a VLAN id", 4095))
            return Vlan(None)
        if word in PROTOCOLS:
            nxt = self._peek()
            if nxt is not None and nxt.kind == WORD and nxt.text.lower() in QUALIFIERS:
                return And((Proto(word), self._qualified(self._take("a qualifier"))))
            return Proto(word)
        raise _Fail(f"unknown filter word {_q(token.text)}", token.pos)

    def _qualified(self, token: Token) -> Expr:
        direction: Direction = None
        word = token.text.lower()
        if word in ("src", "dst"):
            direction = "src" if word == "src" else "dst"
            token = self._take("host, net, port or portrange")
            word = token.text.lower()
            if token.kind != WORD or word not in QUALIFIERS[2:]:
                raise _Fail(
                    f"expected host, net, port or portrange, got {_q(token.text)}", token.pos
                )
        value = self._take(
            {"host": "an IP address", "net": "a network", "port": "a port number"}.get(
                word, "a port range"
            )
        )
        if word == "host":
            try:
                return Host(direction, ip_address(value.text))
            except ValueError:
                raise _Fail(f"expected an IP address, got {_q(value.text)}", value.pos) from None
        if word == "net":
            try:
                return Net(direction, ip_network(value.text, strict=False))
            except ValueError:
                raise _Fail(
                    f"expected a network like 10.0.0.0/8, got {_q(value.text)}", value.pos
                ) from None
        if word == "port":
            port = _number(value, "a port number", 65535)
            return Port(direction, port, port)
        low, dash, high = value.text.partition("-")
        if (
            not dash
            or not (low.isdigit() and high.isdigit())
            or not (low.isascii() and high.isascii())
            or max(len(low), len(high)) > 10
        ):
            raise _Fail(f"expected a port range like 80-90, got {_q(value.text)}", value.pos)
        lo, hi = int(low), int(high)
        if lo > 65535 or hi > 65535 or lo > hi:
            raise _Fail(f"invalid port range {_q(value.text)}", value.pos)
        return Port(direction, lo, hi)


def parse(text: str) -> Expr | FilterError:
    """The syntax tree of `text`, or the first error found. Never raises."""
    tokens, error = tokenize(text)
    if error is not None:
        return error
    if not tokens:
        return FilterError("empty filter", 0)
    try:
        return _Parser(tokens, len(text)).parse()
    except _Fail as e:
        return e.error
