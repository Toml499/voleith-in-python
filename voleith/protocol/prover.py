"""
Prover for the VOLE-in-the-Head linear relation proof.

Protocol summary
----------------
Given public statement (A, b) and secret witness x with A @ x = b:

  1. Sample random seed s  (32 bytes, uniform)
  2. Derive k = PRG(s)     (the mask — will stay hidden)
  3. Commit: comm = Hash("..." || r || s)   [hides s, binds k before Δ is known]
  4. Challenge: Δ = Hash("..." || encode(A,b) || comm)   [Fiat-Shamir]
  5. Compute VOLE: m_i = x_i * Δ + k_i
  6. Compute correction: c = A @ k
  7. Proof = (comm, Δ, m, c)

EDUCATIONAL NOTE — Soundness limitation
----------------------------------------
In this simplified single-instance version, the linear check

    A @ m = b * Δ + c

is *completeness-correct* (it holds for an honest prover) and the proof
is *zero-knowledge* (m = x*Δ + k hides x since k is uniformly random),
but it is NOT fully sound.

The gap: a cheating prover could pick arbitrary m and set c = A @ m - b * Δ,
which trivially satisfies the check.  In the full VolEITH protocol
(Baum et al., CRYPTO 2023), soundness is achieved by:
  (a) Running N virtual parties, each holding a share of Δ (GGM tree)
  (b) Committing to *all* N parties' views before seeing the challenge
  (c) The challenge asks the prover to open N-1 views; the remaining view
      is the "real" one.  A cheating prover cannot fake all N views
      consistently, so soundness error is 1/N.

This implementation focuses on demonstrating the VOLE correlation structure,
the Fiat-Shamir transform, and the linear check identity — the three ideas
that carry over directly to the full scheme.
"""

import os
from dataclasses import dataclass

import numpy as np

from ..relations.linear import LinearRelation
from ..vole.generator import generate_vole
from .commit import commit
from .transcript import derive_challenge


@dataclass
class Proof:
    """
    A VOLE-in-the-Head proof for a linear relation.

    Fields
    ------
    seed_commitment : bytes       — binding commitment to the PRG seed
    delta           : FieldArray  — VOLE key (public, derived via Fiat-Shamir)
    m               : FieldArray  — authenticated witness:  m_i = x_i * Δ + k_i
    correction      : FieldArray  — c = A @ k  (masks the linear combination)
    """

    seed_commitment: bytes
    delta: object       # galois FieldArray scalar
    m: object           # galois FieldArray, shape (n,)
    correction: object  # galois FieldArray, shape (rows of A,)


class Prover:
    """Generates VOLE-in-the-Head proofs for a fixed linear relation."""

    def __init__(self, relation: LinearRelation, field: object) -> None:
        self.relation = relation
        self.field = field

    def prove(self, witness: list[int]) -> Proof:
        """
        Generate a non-interactive proof that 'I know x with A @ x = b'.

        Parameters
        ----------
        witness : list[int] — the secret values (must satisfy A @ x = b)

        Returns
        -------
        Proof — can be sent to any Verifier; x is not included.
        """
        x = self.field(witness)
        if not self.relation.check(x):
            raise ValueError("Witness does not satisfy the relation A @ x = b")

        # Step 1 & 2: random seed (determines k = PRG(seed) implicitly)
        seed = os.urandom(32)
        seed_rand = os.urandom(32)  # blinding factor for the commitment

        # Step 3: commit to seed — this *binds* k before Δ is determined
        seed_commitment = commit(seed, seed_rand)

        # Step 4: derive Δ via Fiat-Shamir
        #   The challenge is a function of (statement, commitment), so the
        #   prover cannot have chosen seed/k to depend on Δ.
        stmt_bytes = self.relation.encode()
        delta = derive_challenge(stmt_bytes, seed_commitment, self.field)

        # Step 5: generate the full VOLE correlation "in the head"
        #   (In production this would be split: sender holds (x,k), receiver holds (Δ,m))
        vole = generate_vole(witness, seed, delta, self.field)

        # Step 6: compute correction c = A @ k
        correction = self.relation.compute_correction(vole.k)

        return Proof(
            seed_commitment=seed_commitment,
            delta=delta,
            m=vole.m,
            correction=correction,
        )
