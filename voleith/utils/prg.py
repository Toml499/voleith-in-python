"""
PRG (Pseudorandom Generator) based on shake_256.

Expands a short seed (bytes) into a sequence of field elements using
SHAKE-256, which is a variable-length XOF (Extendable Output Function).

Note on bias
------------
For a prime p that is not a power of 2, reducing a uniform random integer
mod p introduces a small statistical bias.  Here we over-sample by one byte
per element to keep the bias negligible (< 2^{-8}) for primes up to 2^{2048}.
This is acceptable for an educational implementation; a production system
would use rejection sampling.
"""

import hashlib

import numpy as np


def prg_expand(seed: bytes, n: int, field) -> object:
    """
    Expand *seed* into *n* uniformly distributed elements of *field*.

    Parameters
    ----------
    seed  : bytes — the PRG seed (should be uniformly random, >= 16 bytes)
    n     : int   — number of field elements to produce
    field : galois.GF — the field, e.g. galois.GF(7)

    Returns
    -------
    A galois FieldArray of shape (n,) with elements in field.
    """
    if n == 0:
        return field([])

    p = int(field.characteristic)
    # Over-sample by one extra byte per element to reduce mod-bias.
    byte_len = (p.bit_length() + 7) // 8 + 1

    xof = hashlib.shake_256(seed)
    raw: bytes = xof.digest(n * byte_len)

    values = [
        int.from_bytes(raw[i * byte_len : (i + 1) * byte_len], "big") % p
        for i in range(n)
    ]
    return field(values)
