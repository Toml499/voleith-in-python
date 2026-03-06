"""
Quicksilver R1CS verifier for VOLE-in-the-Head.

Given proof (comm, Δ, m, χ, T, V) and public R1CS relation, the verifier:

  1. Recomputes Δ = Hash(statement || comm) and checks it matches proof.delta
     (Fiat-Shamir: ensures Δ was derived after the prover committed to k)

  2. Recomputes χ = Hash(statement || comm || m) and checks it matches proof.chi
     (Fiat-Shamir: ensures χ was derived after m was fixed)

  3. For each constraint i, computes:
         check_i = MA_i * MB_i - MC_i * Δ
     where  MA_i = A_i · m,  MB_i = B_i · m,  MC_i = C_i · m
     (all computable by the verifier who holds m)

  4. Checks the batched Quicksilver identity:
         Σ_i χ^i * check_i  =?=  T * Δ + V

     If the witness is valid, each check_i = t_i*Δ + v_i, so the LHS equals
     (Σ χ^i * t_i)*Δ + (Σ χ^i * v_i) = T*Δ + V.

     A cheating prover who submits an incorrect witness would need the equation
     to hold despite some check_i ≠ t_i*Δ + v_i.  Since χ is random (derived
     after m is fixed), the probability of this happening is O(n / |F|).
"""

import numpy as np

from ..relations.r1cs import R1CSRelation
from .r1cs_prover import R1CSProof, _derive_chi
from .transcript import derive_challenge


class R1CSVerifier:
    """Verifies Quicksilver VOLE-in-the-Head proofs for a fixed R1CS relation."""

    def __init__(self, relation: R1CSRelation, field) -> None:
        self.relation = relation
        self.field = field

    def verify(self, proof: R1CSProof) -> bool:
        """
        Verify a Quicksilver R1CS proof.

        Returns True if all checks pass, False otherwise (with a diagnostic message).
        """
        F = self.field
        stmt_bytes = self.relation.encode()

        # Check 1 — Fiat-Shamir Δ
        expected_delta = derive_challenge(stmt_bytes, proof.seed_commitment, F)
        if not np.all(proof.delta == expected_delta):
            print("[FAIL] Δ does not match Hash(statement || commitment).")
            return False

        # Check 2 — Fiat-Shamir χ
        expected_chi = _derive_chi(stmt_bytes, proof.seed_commitment, proof.m, F)
        if not np.all(proof.chi == expected_chi):
            print("[FAIL] χ does not match Hash(statement || commitment || m).")
            return False

        # Check 3+4 — batched Quicksilver multiplication check
        #
        #   For each constraint i:
        #     check_i = MA_i * MB_i - MC_i * Δ
        #
        #   Batched LHS:  Σ χ^i * check_i
        #   Expected RHS: T * Δ + V
        checks = self.relation.compute_mult_check(proof.m, proof.delta, F)

        batched_lhs = F(0)
        chi_power   = F(1)
        for check_i in checks:
            batched_lhs = batched_lhs + chi_power * check_i
            chi_power   = chi_power * proof.chi

        rhs = proof.T * proof.delta + proof.V

        if not np.all(batched_lhs == rhs):
            print("[FAIL] Quicksilver batched multiplication check failed: Σ χ^i*check_i ≠ T*Δ + V")
            return False

        return True
