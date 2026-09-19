"""A BPF-like packet filter language: `tcp and (port 80 or port 443) and not src host 10.0.0.1`."""

from collections.abc import Sequence
from dataclasses import dataclass

from sentinel.filter.evaluator import matches
from sentinel.filter.nodes import Expr, FilterError, format_expr
from sentinel.filter.parser import parse
from sentinel.proto.layer import Layer


@dataclass(frozen=True, slots=True)
class Filter:
    """The result of `parse_filter`: check `error` before using it. A filter with an error
    matches nothing."""

    text: str
    expr: Expr | None = None
    error: str | None = None
    position: int = 0  # where in `text` the error is

    def matches(self, layers: Sequence[Layer]) -> bool:
        return self.expr is not None and matches(self.expr, layers)

    def describe_error(self) -> list[str]:
        """The message, the filter text and a caret under the position of the error."""
        assert self.error is not None
        return [self.error, f"  {self.text}", f"  {' ' * self.position}^"]

    def __str__(self) -> str:
        return format_expr(self.expr) if self.expr is not None else self.text


def parse_filter(text: str) -> Filter:
    """Parse filter text. Never raises: a bad filter comes back with `error` set."""
    result = parse(text)
    if isinstance(result, FilterError):
        return Filter(text, error=result.message, position=result.position)
    return Filter(text, expr=result)


__all__ = ["Filter", "parse_filter"]
