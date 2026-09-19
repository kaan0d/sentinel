"""Typed, range-checked parameters for detector rules."""

from dataclasses import dataclass

type Value = int | float | bool


@dataclass(frozen=True, slots=True)
class Param:
    name: str
    kind: type  # int, float or bool
    default: Value
    low: float = 0
    high: float = 1_000_000_000
    doc: str = ""


def check_param(param: Param, value: object) -> tuple[Value | None, str | None]:
    """The value converted to the parameter's type, or None and a message. Never raises."""
    if param.kind is bool:
        if isinstance(value, bool):
            return value, None
        return None, f"'{param.name}' must be true or false"
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None, f"'{param.name}' must be a number"
    if param.kind is int and not isinstance(value, int):
        return None, f"'{param.name}' must be a whole number"
    number: Value = float(value) if param.kind is float else value
    if not param.low <= number <= param.high:  # also false for nan
        return None, f"'{param.name}' must be between {param.low:g} and {param.high:g}"
    return number, None
