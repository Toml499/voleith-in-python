"""
VOLE correlation dataclass.

A VOLE (Vector Oblivious Linear Evaluation) correlation is a tuple
(x, k, delta, m) satisfying:

    m_i = x_i * delta + k_i   for all i in {0, ..., n-1}

In a *real* two-party VOLE protocol:
  - The Sender holds (x, k) — secret to the sender
  - The Receiver holds (delta, m) — delta chosen by the receiver

In the "in the head" setting the Prover knows *all four* components
because they simulate both parties internally.  The VOLE constraint
then acts as a "MAC": m_i is an authentication tag on x_i under key delta,
with k_i as a one-time randomiser.

Why is this useful?
-------------------
Linear functions of authenticated values are themselves authenticated:
  sum_i a_i * m_i = (sum_i a_i * x_i) * delta + (sum_i a_i * k_i)
This means the verifier can check linear relations over authenticated
witnesses without learning the witness itself.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class VOLECorrelation:
    """
    A VOLE correlation (x, k, delta, m) over a finite field.

    Attributes
    ----------
    x     : FieldArray, shape (n,) — the witness / sender's input vector
    k     : FieldArray, shape (n,) — the mask / sender's key vector
    delta : FieldArray, scalar     — the receiver's global key
    m     : FieldArray, shape (n,) — the receiver's MACs:  m_i = x_i * delta + k_i
    """

    x: object      # galois FieldArray (n,)
    k: object      # galois FieldArray (n,)
    delta: object  # galois FieldArray scalar
    m: object      # galois FieldArray (n,)

    def check(self) -> bool:
        """Return True iff m == x * delta + k holds for every element."""
        expected = self.x * self.delta + self.k
        return bool(np.all(self.m == expected))

    def __len__(self) -> int:
        return len(self.x)
