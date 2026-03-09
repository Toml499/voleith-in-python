"""
Verifier for the VOLE-in-the-Head linear relation proof (GGM version).

Given proof (ggm_opening, Δ, m, correction_j) and public statement (A, b):

  1. Recompute Δ = Hash(statement || ggm_commitment)  [Fiat-Shamir]
  2. Recover N-1 leaf seeds from ggm_opening; verify against commitment.
  3. Recompute j* and check it matches opening.j_star.
  4. Compute corr^p = A @ k^p for all p ≠ j*.
  5. full_correction = Σ_{p≠j*} corr^p + correction_j.
  6. Check: A @ m = b·Δ + full_correction.
"""

import numpy as np

from ..relations.linear import LinearRelation
from ..vole.ggm import ggm_recover
from ..utils.prg import prg_expand
from .prover import Proof, _derive_j_star
from .transcript import derive_challenge


class Verifier:
    """Verifies GGM-based VOLE-in-the-Head proofs for a fixed linear relation."""

    def __init__(self, relation: LinearRelation, field: object) -> None:
        self.relation = relation
        self.field = field

    def verify(self, proof: Proof) -> bool:
        """
        Verify a GGM-based VOLE-in-the-Head proof.

        Returns True if all checks pass, False otherwise.
        """
        F          = self.field
        opening    = proof.ggm_opening
        commitment = opening.commitment
        stmt_bytes = self.relation.encode()

        # 1 — Fiat-Shamir Δ
        expected_delta = derive_challenge(stmt_bytes, commitment, F)
        if not np.all(proof.delta == expected_delta):
            print("[FAIL] Δ does not match Hash(statement || ggm_commitment).")
            return False

        # 2 — GGM recovery + commitment verification
        try:
            leaf_seeds = ggm_recover(opening)
        except ValueError as e:
            print(f"[FAIL] GGM opening invalid: {e}")
            return False

        # 3 — Fiat-Shamir j*
        n      = len(np.array(proof.m).flatten())
        j_star = _derive_j_star(stmt_bytes, commitment, proof.m, F)
        if j_star != opening.j_star:
            print(f"[FAIL] j* mismatch: expected {j_star}, opening has {opening.j_star}.")
            return False

        # 4 — Reconstruct Σ_{p≠j*} (A @ k^p)
        n_b = len(np.array(self.relation.b).flatten())
        correction_sum = F([0] * n_b)
        for p, seed_p in enumerate(leaf_seeds):
            if p == j_star:
                continue
            k_p    = prg_expand(seed_p, n, F)
            corr_p = self.relation.compute_correction(k_p)
            correction_sum = correction_sum + corr_p

        # 5 — Add revealed j*-th correction and run linear check
        full_correction = correction_sum + proof.correction_j
        lhs = self.relation.A @ proof.m
        rhs = self.relation.b * proof.delta + full_correction

        if not np.all(lhs == rhs):
            print("[FAIL] Linear VOLE check failed: A @ m ≠ b·Δ + Σ corr^p")
            return False

        return True
