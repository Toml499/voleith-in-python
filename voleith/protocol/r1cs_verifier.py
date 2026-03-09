"""
Quicksilver R1CS verifier for VOLE-in-the-Head (GGM version).

Given proof (ggm_opening, Δ, m, χ, T_j, V) and public R1CS relation:

  1. Recompute Δ = Hash(statement || commitment)          [Fiat-Shamir check]
  2. Recover N-1 leaf seeds from ggm_opening; verify against commitment.
  3. Recompute χ = Hash(statement || commitment || m)     [Fiat-Shamir check]
  4. Recompute j* = Hash(... || χ) mod N                 [Fiat-Shamir check]
  5. Compute per-constraint check values:
       check_i = MA_i * MB_i - MC_i * Δ   (from m and relation)
  6. Compute T̂_{-j*}·Δ from the N-1 opened leaf seeds and m:
       T̂^p·Δ = Σ_i χ^i * (MA_i*(B_i·k^p) + MB_i*(A_i·k^p) - Δ*(C_i·k^p))
  7. Check batched equation:
       Σ_i χ^i * check_i  +  V  =  T̂_{-j*}·Δ  +  T_j

The check in step 7 is algebraically equivalent to the original single-party
Quicksilver identity  Σ check_i = T·Δ + V  via the identity  Σ_p T̂^p·Δ = T·Δ + 2V.
Using the T̂ formulation allows the verifier to reconstruct its share of the check
from opened k^p and m alone — no witness values are needed.
"""

import numpy as np

from ..relations.r1cs import R1CSRelation, eval_lc
from ..utils.prg import prg_expand
from ..vole.ggm import ggm_recover
from .r1cs_prover import R1CSProof, _derive_chi, _derive_j_star_r1cs
from .transcript import derive_challenge


class R1CSVerifier:
    """Verifies GGM Quicksilver VOLE-in-the-Head proofs for a fixed R1CS relation."""

    def __init__(self, relation: R1CSRelation, field) -> None:
        self.relation = relation
        self.field = field

    def verify(self, proof: R1CSProof) -> bool:
        """
        Verify a GGM Quicksilver R1CS proof.

        Returns True if all checks pass, False otherwise (with a diagnostic message).
        """
        F          = self.field
        opening    = proof.ggm_opening
        commitment = opening.commitment
        stmt_bytes = self.relation.encode()

        # 1 — Fiat-Shamir Δ
        expected_delta = derive_challenge(stmt_bytes, commitment, F)
        if not np.all(proof.delta == expected_delta):
            print("[FAIL] Δ does not match Hash(statement || commitment).")
            return False

        # 2 — GGM recovery + commitment verification
        try:
            leaf_seeds = ggm_recover(opening)
        except ValueError as e:
            print(f"[FAIL] GGM opening invalid: {e}")
            return False

        # 3 — Fiat-Shamir χ
        expected_chi = _derive_chi(stmt_bytes, commitment, proof.m, F)
        if not np.all(proof.chi == expected_chi):
            print("[FAIL] χ does not match Hash(statement || commitment || m).")
            return False

        # 4 — Fiat-Shamir j*
        j_star = _derive_j_star_r1cs(stmt_bytes, commitment, proof.m, proof.chi, F)
        if j_star != opening.j_star:
            print(f"[FAIL] j* mismatch: expected {j_star}, opening has {opening.j_star}.")
            return False

        # 5 — Batched LHS: Σ_i χ^i * check_i
        checks      = self.relation.compute_mult_check(proof.m, proof.delta, F)
        batched_lhs = F(0)
        chi_power   = F(1)
        for check_i in checks:
            batched_lhs = batched_lhs + chi_power * check_i
            chi_power   = chi_power * proof.chi

        # 6 — Reconstruct T̂_{-j*}·Δ from the N-1 opened leaf seeds
        #
        #   T̂^p·Δ = Σ_i χ^i * (MA_i*(B_i·k^p) + MB_i*(A_i·k^p) - Δ*(C_i·k^p))
        #
        # MA_i = A_i · m and MB_i = B_i · m are computable by the verifier.
        # B_i·k^p and A_i·k^p are computable from the opened seed_p.
        n_wires = len(np.array(proof.m).flatten())
        T_hat_minus_j_delta = F(0)
        for p, seed_p in enumerate(leaf_seeds):
            if p == j_star:
                continue
            k_p       = prg_expand(seed_p, n_wires, F)
            chi_power = F(1)
            for A, B, C in self.relation.constraints:
                MA  = eval_lc(A, proof.m, F)
                MB  = eval_lc(B, proof.m, F)
                ka  = eval_lc(A, k_p, F)
                kb  = eval_lc(B, k_p, F)
                kc  = eval_lc(C, k_p, F)
                T_hat_minus_j_delta = (
                    T_hat_minus_j_delta
                    + chi_power * (MA * kb + MB * ka - proof.delta * kc)
                )
                chi_power = chi_power * proof.chi

        # 7 — Check: Σ check_i + V = T̂_{-j*}·Δ + T̂_j
        lhs = batched_lhs + proof.V
        rhs = T_hat_minus_j_delta + proof.T_j

        if not np.all(lhs == rhs):
            print("[FAIL] Quicksilver GGM batched check failed: Σ check_i + V ≠ T̂_{-j*}·Δ + T̂_j")
            return False

        return True
