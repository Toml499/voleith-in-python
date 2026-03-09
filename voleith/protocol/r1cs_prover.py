"""
Quicksilver R1CS prover for VOLE-in-the-Head (GGM version).

Protocol summary
----------------
Given public R1CS relation and secret full witness w (w[0] = 1 always):

  1. Generate 16-byte root_seed; ggm_commitment = ggm_commit(root_seed)
  2. Derive Δ = Hash(statement || ggm_commitment)        [Fiat-Shamir]
  3. Per party p: k^p = prg_expand(seed_p, n_wires);  k = Σ_p k^p
  4. Compute m_j = w_j*Δ + k_j  for every wire j
  5. Derive χ = Hash(statement || ggm_commitment || m)   [Fiat-Shamir]
  6. Derive j* = Hash(statement || ggm_commitment || m || χ) mod N
  7. Compute T̂_j = T̂^{j*}·Δ  (MAC-based correction for party j*):
       T̂^p·Δ = Σ_i χ^i * (MA_i*(B_i·k^p) + MB_i*(A_i·k^p) − Δ*(C_i·k^p))
     where MA_i = A_i·m, MB_i = B_i·m  (uses m, not w — verifier can do the same)
  8. V = Σ_i χ^i * v_i  using combined k  (not per-party separable)
  9. Punctured opening: ggm_opening = ggm_puncture(root_seed, j*)
  10. Proof = (ggm_opening, Δ, m, χ, T_j, V)

Verifier check:
  Σ_i χ^i * check_i + V  =  T̂_{-j*}·Δ + T̂_j
where T̂_{-j*}·Δ = Σ_{p≠j*} T̂^p·Δ  (verifier reconstructs from opened k^p and m).
Equivalent to the original Σ check_i = T·Δ + V via: Σ_p T̂^p·Δ = T·Δ + 2V.

Soundness (1/N = 1/128)
---------
T̂^{j*}·Δ is bound by ggm_commitment (via k^{j*}) before j* is chosen.  A cheating
prover who uses a wrong m cannot forge T̂_j and V to satisfy the batched equation,
except with probability ≤ 1/N (GGM) + O(n/|F|) (Schwartz-Zippel over χ).
"""

import hashlib
import os
from dataclasses import dataclass

import numpy as np

from ..relations.r1cs import R1CSRelation
from ..vole.generator import generate_vole, generate_per_party_masks
from ..vole.ggm import ggm_commit, ggm_puncture, GGMOpening, N_PARTIES
from .transcript import derive_challenge


# ── Fiat-Shamir helpers ───────────────────────────────────────────────────────

def _derive_chi(stmt_bytes: bytes, commitment: bytes, m, field) -> object:
    """Derive batching challenge χ ∈ F after m is fixed."""
    p = int(field.characteristic)
    byte_len = (p.bit_length() + 7) // 8
    m_bytes = b"".join(int(x).to_bytes(byte_len, "big") for x in np.array(m).flatten())
    h = hashlib.sha3_256()
    h.update(b"voleith-r1cs-chi-v1:")
    h.update(stmt_bytes)
    h.update(b":")
    h.update(commitment)
    h.update(b":")
    h.update(m_bytes)
    return field(int.from_bytes(h.digest(), "big") % int(field.characteristic))


def _derive_j_star_r1cs(stmt_bytes: bytes, commitment: bytes, m, chi, field) -> int:
    """Derive punctured-party index j* after χ is fixed."""
    p = int(field.characteristic)
    byte_len = (p.bit_length() + 7) // 8
    m_bytes = b"".join(int(x).to_bytes(byte_len, "big") for x in np.array(m).flatten())
    h = hashlib.sha3_256()
    h.update(b"voleith-r1cs-jstar-v1:")
    h.update(stmt_bytes)
    h.update(b":")
    h.update(commitment)
    h.update(b":")
    h.update(m_bytes)
    h.update(b":")
    h.update(int(chi).to_bytes(byte_len, "big"))
    return int.from_bytes(h.digest(), "big") % N_PARTIES


# ── proof dataclass ───────────────────────────────────────────────────────────

@dataclass
class R1CSProof:
    """
    A GGM Quicksilver VOLE-in-the-Head proof for an R1CS relation.

    Fields
    ------
    ggm_opening : GGMOpening — punctured opening (carries commitment + j_star)
    delta       : field elem — VOLE key (Fiat-Shamir)
    m           : FieldArray — authenticated wire values: m_j = w_j*Δ + k_j
    chi         : field elem — batching challenge (Fiat-Shamir)
    T_j         : field elem — T̂^{j*}·Δ = Σ_i χ^i (MA_i·kb^{j*} + MB_i·ka^{j*} − Δ·kc^{j*})
    V           : field elem — Σ_i χ^i v_i  (quadratic term, from combined k)
    """
    ggm_opening: GGMOpening
    delta:       object
    m:           object
    chi:         object
    T_j:         object
    V:           object


# ── prover ────────────────────────────────────────────────────────────────────

class R1CSProver:
    """Generates GGM Quicksilver VOLE-in-the-Head proofs for a fixed R1CS relation."""

    def __init__(self, relation: R1CSRelation, field) -> None:
        self.relation = relation
        self.field = field

    def prove(self, witness: list[int]) -> R1CSProof:
        """
        Generate a non-interactive ZK proof that 'I know w satisfying the R1CS'.

        Parameters
        ----------
        witness : list[int]
            Full witness vector (witness[0] must be 1).
        """
        F = self.field
        w = F(witness)

        if not self.relation.check(w, F):
            raise ValueError("Witness does not satisfy the R1CS relation")

        # 1–2: GGM commitment + Δ
        root_seed      = os.urandom(16)
        ggm_commitment = ggm_commit(root_seed)
        stmt_bytes     = self.relation.encode()
        delta          = derive_challenge(stmt_bytes, ggm_commitment, F)

        # 3–4: N-party VOLE → combined m
        vole = generate_vole(witness, root_seed, delta, F)
        k, m = vole.k, vole.m

        # 5: χ via Fiat-Shamir (after m is fixed)
        chi = _derive_chi(stmt_bytes, ggm_commitment, m, F)

        # 6: j* via Fiat-Shamir (after χ is fixed)
        j_star = _derive_j_star_r1cs(stmt_bytes, ggm_commitment, m, chi, F)

        # 7: T̂^{j*}·Δ — MAC-based correction for party j* (verifier-reconstructible formula)
        #
        #   T̂^p·Δ = Σᵢ χⁱ (MA_i·(B_i·k^p) + MB_i·(A_i·k^p) − Δ·(C_i·k^p))
        #
        # This is algebraically equivalent to the original Σ check_i = T·Δ + V check
        # via the identity: Σ check_i + V = Σ_p T̂^p·Δ.
        # Using MAC values (m) instead of witness values (w) allows the verifier to
        # reconstruct T̂_{−j*}·Δ from the opened k^p without knowing the witness.
        from ..relations.r1cs import eval_lc
        per_party = generate_per_party_masks(root_seed, len(witness), F)
        k_j = per_party[j_star]

        T_j     = F(0)
        cp      = F(1)
        for A, B, C in self.relation.constraints:
            MA   = eval_lc(A, m, F)       # A_i · m
            MB   = eval_lc(B, m, F)       # B_i · m
            ka_j = eval_lc(A, k_j, F)    # A_i · k^{j*}
            kb_j = eval_lc(B, k_j, F)    # B_i · k^{j*}
            kc_j = eval_lc(C, k_j, F)    # C_i · k^{j*}
            T_j  = T_j + cp * (MA * kb_j + MB * ka_j - delta * kc_j)
            cp   = cp * chi

        # 8: V from combined k (not per-party separable)
        _, vs = self.relation.compute_mult_proof(vole.x, k, F)
        V = F(0)
        chi_power = F(1)
        for v_i in vs:
            V = V + chi_power * v_i
            chi_power = chi_power * chi

        # 9: punctured opening
        ggm_opening = ggm_puncture(root_seed, j_star)

        return R1CSProof(
            ggm_opening=ggm_opening,
            delta=delta,
            m=m,
            chi=chi,
            T_j=T_j,
            V=V,
        )
