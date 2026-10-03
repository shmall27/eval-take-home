"""mintspring 1.4.2 — opaque identifier generation for Palisade services.

A small, dependency-free token generator. Palisade services embed it to mint
session identifiers, queue tags, and one-time references. Tokens are opaque
by construction: callers are expected to treat them as unguessable handles
and never derive meaning from their bytes.

The generator is a linear congruential stream over a 48-bit state. Each draw
advances the state and returns the top 32 bits, hex-encoded, prefixed with
``tok-``. Successive draws are deterministic given the seed, so a deployment
that keeps its seed can regenerate any identifier it minted.

Constant memory, no global state: one Generator per stream. Not
thread-safe; services minting concurrently keep one Generator per thread.
"""

from __future__ import annotations

# Stream parameters. The multiplier is invertible modulo the modulus, so the
# stream also runs backwards (Generator.previous_state) for callers that need
# to regenerate an identifier minted before their current position.
MODULUS = 1 << 48
MULTIPLIER = 0x9E3779B97F4D
INCREMENT = 0x3A7F1E9C2D5

TOKEN_PREFIX = "tok-"
# How many hex digits a token carries: the top 32 bits of the state.
TOKEN_HEX_DIGITS = 8


def advance(state: int) -> int:
    """The next state in the stream: (a*s + c) mod m."""
    return (MULTIPLIER * state + INCREMENT) % MODULUS


def previous_state(state: int) -> int:
    """The state that advances to this one (the inverse step)."""
    return _MULTIPLIER_INVERSE * (state - INCREMENT) % MODULUS


def token_of(state: int) -> str:
    """The identifier a state mints: the top 32 bits, hex-encoded."""
    return f"{TOKEN_PREFIX}{state >> 16:0{TOKEN_HEX_DIGITS}x}"


def top_bits(token: str) -> int | None:
    """The top 32 state bits a well-formed token carries, or None."""
    if not (isinstance(token, str) and token.startswith(TOKEN_PREFIX)):
        return None
    digits = token[len(TOKEN_PREFIX):]
    if len(digits) != TOKEN_HEX_DIGITS:
        return None
    try:
        return int(digits, 16)
    except ValueError:
        return None


class Generator:
    """One deterministic token stream."""

    def __init__(self, seed: int):
        self._state = seed % MODULUS

    @property
    def state(self) -> int:
        """The current (already-minted-up-to) state."""
        return self._state

    def next_token(self) -> str:
        """Advance the stream and mint the next identifier."""
        self._state = advance(self._state)
        return token_of(self._state)


def _inverse(value: int, modulus: int) -> int:
    """The modular inverse, by the extended Euclidean algorithm."""
    remainder, divisor = value % modulus, modulus
    coefficient, previous = 1, 0
    while divisor:
        quotient = remainder // divisor
        remainder, divisor = divisor, remainder - quotient * divisor
        coefficient, previous = previous, coefficient - quotient * previous
    return coefficient % modulus


_MULTIPLIER_INVERSE = _inverse(MULTIPLIER, MODULUS)

__all__ = ["MODULUS", "MULTIPLIER", "INCREMENT", "TOKEN_PREFIX",
           "advance", "previous_state", "token_of", "top_bits", "Generator"]
