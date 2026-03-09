"""
Prover for the VOLE-in-the-Head linear relation proof (GGM version).

Protocol summary
----------------
Given public statement (A, b) and secret witness x with A @ x = b:

  1. Generate 16-byte root_seed uniformly at random.
  2. Commit: ggm_commitment = ggm_commit(root_seed)
         (Merkle root over N=128 per-party leaf-seed commitments)
  3. Derive Δ = Hash(statement || ggm_commitment)   [Fiat-Shamir]
  4. Per party p: k^p = prg_expand(leaf_seeds[p], n);  k = Σ_p k^p
  5. Compute authenticated witness: m = x·Δ + k
  6. Derive j* = Hash(statement || ggm_commitment || m) mod N  [Fiat-Shamir]
  7. Punctured opening: ggm_opening = ggm_puncture(root_seed, j*)
  8. Reveal: correction_j = A @ k^{j*}
  9. Proof = (ggm_opening, delta, m, correction_j)

Soundness (1/N = 1/128)
---------
A cheating prover must commit to all N per-party corrections via
ggm_commitment before seeing j*.  After j* is revealed, correction_{j*}
is constrained by the committed seed.  A cheating prover who uses a wrong
witness can pass only if their forged correction_{j*} exactly compensates
the error — probability ≤ 1/N.
"""

import hashlib
import os
from dataclasses import dataclass

import numpy as np

from ..relations.linear import LinearRelation
from ..vole.generator import generate_vole, generate_per_party_masks
from ..vole.ggm import ggm_commit, ggm_puncture, GGMOpening, N_PARTIES
from .transcript import derive_challenge


def _derive_j_star(stmt_bytes: bytes, commitment: bytes, m, field) -> int:
    """Derive punctured-party index j* ∈ [0, N) via Fiat-Shamir."""
    p = int(field.characteristic)
    byte_len = (p.bit_length() + 7) // 8
    m_bytes = b"".join(int(x).to_bytes(byte_len, "big") for x in np.array(m).flatten())
    h = hashlib.sha3_256()
    h.update(b"voleith-linear-jstar-v1:")
    h.update(stmt_bytes)
    h.update(b":")
    h.update(commitment)
    h.update(b":")
    h.update(m_bytes)
    return int.from_bytes(h.digest(), "big") % N_PARTIES


@dataclass
class Proof:
    """
    A GGM-based VOLE-in-the-Head proof for a linear relation.

    Fields
    ------
    ggm_opening  : GGMOpening — punctured opening (carries commitment + j_star)
    delta        : FieldArray scalar — VOLE key (Fiat-Shamir)
    m            : FieldArray (n,) — combined authenticated witness  m = x·Δ + Σk^p
    correction_j : FieldArray — A @ k^{j*}  (j*-th party's correction)
    """
    ggm_opening:  GGMOpening
    delta:        object
    m:            object
    correction_j: object


class Prover:
    """Generates GGM-based VOLE-in-the-Head proofs for a fixed linear relation."""

    def __init__(self, relation: LinearRelation, field: object) -> None:
        self.relation = relation
        self.field = field

    def prove(self, witness: list[int]) -> Proof:
        """
        Generate a non-interactive ZK proof that 'I know x with A @ x = b'.

        Parameters
        ----------
        witness : list[int] — the secret values (must satisfy A @ x = b)
        """
        F = self.field
        x = F(witness)
        if not self.relation.check(x):
            raise ValueError("Witness does not satisfy the relation A @ x = b")

        root_seed      = os.urandom(16)
        ggm_commitment = ggm_commit(root_seed)

        stmt_bytes = self.relation.encode()
        delta = derive_challenge(stmt_bytes, ggm_commitment, F)

        vole   = generate_vole(witness, root_seed, delta, F)
        m      = vole.m
        j_star = _derive_j_star(stmt_bytes, ggm_commitment, m, F)

        ggm_opening  = ggm_puncture(root_seed, j_star)
        per_party    = generate_per_party_masks(root_seed, len(witness), F)
        correction_j = self.relation.compute_correction(per_party[j_star])

        return Proof(
            ggm_opening=ggm_opening,
            delta=delta,
            m=m,
            correction_j=correction_j,
        )
