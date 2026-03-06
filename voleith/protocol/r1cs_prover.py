"""
Quicksilver R1CS prover for VOLE-in-the-Head.

Protocol summary
----------------
Given public R1CS relation and secret full witness w (w[0] = 1 always):

  1. Sample seed; derive k = PRG(seed, n_wires) — one mask per wire
  2. Commit: comm = Hash(seed || rand)              — hides seed before Δ
  3. Derive Δ = Hash(statement || comm)             — Fiat-Shamir, VOLE key
  4. Compute m_j = w_j * Δ + k_j  for every wire j — authenticated witness
  5. Derive χ = Hash(statement || comm || m)        — Fiat-Shamir, batching key
     (χ is derived AFTER m is fixed so the prover cannot tailor t_i/v_i to χ)
  6. For each R1CS constraint i, compute Quicksilver terms:
         t_i = a_i*kb_i + b_i*ka_i - kc_i
         v_i = ka_i * kb_i
     where  a_i = A_i·w,  ka_i = A_i·k,  etc.
  7. Batch:  T = Σ_i χ^i * t_i ,  V = Σ_i χ^i * v_i
  8. Proof = (comm, Δ, m, χ, T, V)

Why is (T, V) enough?
---------------------
The verifier holds m and can compute  check_i = MA_i*MB_i - MC_i*Δ  for each i.
If the witness is valid, check_i = t_i*Δ + v_i.
The batched equation  Σ χ^i * check_i = T*Δ + V  is a polynomial identity in χ
of degree n_constraints.  A cheating prover who satisfies it for a random χ
(chosen after committing to m) would need to find a polynomial root, giving a
soundness error of O(n_constraints / |F|) — negligible for large fields.

Zero-knowledge
--------------
  m_j = w_j*Δ + k_j  with uniform k_j  →  m_j is uniformly random, hides w_j.
  t_i = a_i*kb_i + b_i*ka_i - kc_i    →  uniform (linear in uniform ka_i).
  v_i = ka_i * kb_i                    →  uniform (product of two independent uniforms).
Neither T nor V leaks any information about the witness.
"""

import hashlib
import os
from dataclasses import dataclass

import numpy as np

from ..relations.r1cs import R1CSRelation
from ..vole.generator import generate_vole
from .commit import commit
from .transcript import derive_challenge


# ── Fiat-Shamir for χ ─────────────────────────────────────────────────────────

def _derive_chi(
    stmt_bytes: bytes,
    seed_commitment: bytes,
    m,          # galois FieldArray (n_wires,)
    field,      # galois.GF(p)
) -> object:
    """
    Derive the batching challenge χ ∈ F via Fiat-Shamir.

    χ is derived AFTER m is committed to (m itself is included in the transcript),
    so the prover cannot choose t_i / v_i to depend on χ.
    """
    p = int(field.characteristic)
    byte_len = (p.bit_length() + 7) // 8

    m_bytes = b"".join(
        int(x).to_bytes(byte_len, "big") for x in np.array(m).flatten()
    )

    h = hashlib.sha3_256()
    h.update(b"voleith-r1cs-chi-v1:")
    h.update(stmt_bytes)
    h.update(b":")
    h.update(seed_commitment)
    h.update(b":")
    h.update(m_bytes)
    digest = h.digest()

    val = int.from_bytes(digest, "big") % p
    return field(val)


# ── proof dataclass ───────────────────────────────────────────────────────────

@dataclass
class R1CSProof:
    """
    A Quicksilver VOLE-in-the-Head proof for an R1CS relation.

    Fields
    ------
    seed_commitment : bytes      — commitment to the PRG seed
    delta           : field elem — VOLE key (Fiat-Shamir)
    m               : FieldArray — authenticated wire values: m_j = w_j*Δ + k_j
    chi             : field elem — batching challenge (Fiat-Shamir)
    T               : field elem — Σ χ^i * t_i  (cross term)
    V               : field elem — Σ χ^i * v_i  (quadratic term)
    """

    seed_commitment: bytes
    delta: object
    m:     object
    chi:   object
    T:     object
    V:     object


# ── prover ────────────────────────────────────────────────────────────────────

class R1CSProver:
    """Generates Quicksilver VOLE-in-the-Head proofs for a fixed R1CS relation."""

    def __init__(self, relation: R1CSRelation, field) -> None:
        self.relation = relation
        self.field = field

    def prove(self, witness: list[int]) -> R1CSProof:
        """
        Generate a non-interactive ZK proof that 'I know w satisfying the R1CS'.

        Parameters
        ----------
        witness : list[int]
            Full witness vector including the constant wire (witness[0] must be 1)
            and all intermediate / private wires.

        Returns
        -------
        R1CSProof — contains no information about the witness beyond what is public.
        """
        F = self.field
        w = F(witness)

        if not self.relation.check(w, F):
            raise ValueError("Witness does not satisfy the R1CS relation")

        # Steps 1–2: sample seed, derive mask k, commit
        seed      = os.urandom(32)
        seed_rand = os.urandom(32)
        seed_commitment = commit(seed, seed_rand)

        # Step 3: Δ via Fiat-Shamir
        stmt_bytes = self.relation.encode()
        delta = derive_challenge(stmt_bytes, seed_commitment, F)

        # Step 4: generate VOLE — m_j = w_j * Δ + k_j
        vole = generate_vole(witness, seed, delta, F)
        k = vole.k
        m = vole.m

        # Step 5: χ via Fiat-Shamir (bound to m)
        chi = _derive_chi(stmt_bytes, seed_commitment, m, F)

        # Step 6: per-constraint Quicksilver terms
        ts, vs = self.relation.compute_mult_proof(vole.x, k, F)

        # Step 7: batch with χ
        T         = F(0)
        V         = F(0)
        chi_power = F(1)
        for t_i, v_i in zip(ts, vs):
            T = T + chi_power * t_i
            V = V + chi_power * v_i
            chi_power = chi_power * chi

        return R1CSProof(
            seed_commitment=seed_commitment,
            delta=delta,
            m=m,
            chi=chi,
            T=T,
            V=V,
        )
