"""
Linear relation: R = { (A, b, x)  |  A @ x = b  over field F }.

The prover wants to convince the verifier that they know a secret vector x
satisfying A @ x = b, without revealing x.

How the VOLE MAC check encodes this relation
--------------------------------------------
Suppose the prover holds authenticated values [x_i] = (x_i, k_i) and the
verifier holds (Δ, m_i) with  m_i = x_i * Δ + k_i.

Applying A linearly to the MAC:
  A @ m = A @ (x * Δ + k)
        = (A @ x) * Δ + (A @ k)
        = b * Δ + c        <-- this holds iff A @ x = b

where  c = A @ k  is the "correction" term the prover reveals.

The verifier checks  A @ m = b * Δ + c.
If the check passes and Δ was chosen after k was committed, then A @ x = b
with high probability (soundness error 1/|F|).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import numpy as np


@dataclass
class LinearRelation:
    """
    Public statement: 'I know x such that A @ x = b'.

    Attributes
    ----------
    A : FieldArray, shape (m_rows, n_cols) — the constraint matrix
    b : FieldArray, shape (m_rows,)        — the target vector
    """

    A: object  # galois FieldArray
    b: object  # galois FieldArray

    def check(self, x: object) -> bool:
        """Return True iff A @ x == b (used by the prover to validate the witness)."""
        return bool(np.all(self.A @ x == self.b))

    def compute_correction(self, k: object) -> object:
        """
        Compute the correction term c = A @ k.

        This is the only information about k that the prover reveals.
        The verifier uses it to run the linear VOLE check:
          A @ m = b * Δ + c
        """
        return self.A @ k

    def encode(self) -> bytes:
        """
        Deterministically encode (A, b) as bytes for Fiat-Shamir hashing.

        We convert to a plain Python list of ints so that the encoding is
        unambiguous regardless of internal numpy/galois representation.
        """
        A_list = np.array(self.A, dtype=int).tolist()
        b_list = np.array(self.b, dtype=int).tolist()
        return json.dumps({"A": A_list, "b": b_list}, separators=(",", ":")).encode()
