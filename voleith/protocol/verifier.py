"""
Verifier for the VOLE-in-the-Head linear relation proof.

Given proof (comm, Δ, m, c) and public statement (A, b), the verifier:

  1. Recomputes Δ = Hash(statement || comm)  and checks it matches proof.delta
     (This confirms the prover derived Δ honestly from their commitment.)

  2. Checks: A @ m = b * Δ + c
     (This is the linear VOLE MAC check.  It holds iff A @ x = b, given that
      m = x*Δ + k and c = A@k for the prover's committed k.)

Both checks together give the verifier confidence (up to the soundness
limitations documented in prover.py) that the prover knows a valid witness.
"""

import numpy as np

from ..relations.linear import LinearRelation
from .prover import Proof
from .transcript import derive_challenge


class Verifier:
    """Verifies VOLE-in-the-Head proofs for a fixed linear relation."""

    def __init__(self, relation: LinearRelation, field: object) -> None:
        self.relation = relation
        self.field = field

    def verify(self, proof: Proof) -> bool:
        """
        Verify a VOLE-in-the-Head proof.

        Returns True if both checks pass, False otherwise.
        Prints a diagnostic message on failure.
        """
        stmt_bytes = self.relation.encode()

        # Check 1 — Fiat-Shamir consistency
        #   The verifier independently recomputes Δ from the public transcript.
        #   If the prover tampered with Δ, this catches it.
        expected_delta = derive_challenge(stmt_bytes, proof.seed_commitment, self.field)
        if not np.all(proof.delta == expected_delta):
            print("[FAIL] Δ does not match Hash(statement || commitment).")
            return False

        # Check 2 — linear VOLE MAC check
        #   A @ m  =?=  b * Δ + c
        #
        #   Derivation (honest prover):
        #     A @ m = A @ (x*Δ + k)
        #           = (A @ x)*Δ + A@k
        #           = b*Δ + c          (since A@x = b and c = A@k)
        lhs = self.relation.A @ proof.m
        rhs = self.relation.b * proof.delta + proof.correction

        if not np.all(lhs == rhs):
            print("[FAIL] Linear VOLE check failed:  A @ m  ≠  b * Δ + c")
            return False

        return True
