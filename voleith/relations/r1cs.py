"""
R1CS (Rank-1 Constraint System) relation.

An R1CS over a field F is a list of constraints:

    (A_i · w) * (B_i · w) = C_i · w    for i = 0, …, n_constraints-1

where:
  - w  is the full witness vector;  w[0] = 1 by convention
  - A_i, B_i, C_i are sparse linear combinations represented as
    dicts  {wire_index: integer_coefficient}

How the Quicksilver VOLE check encodes R1CS
-------------------------------------------
With a VOLE the prover holds (w, k) and the verifier holds (Δ, m) where

    m_j = w_j * Δ + k_j   for every wire j

For constraint i, define:
    a_i  = A_i · w ,   ka_i = A_i · k ,   MA_i = A_i · m = a_i*Δ + ka_i
    b_i  = B_i · w ,   kb_i = B_i · k ,   MB_i = B_i · m = b_i*Δ + kb_i
    c_i  = C_i · w ,   kc_i = C_i · k ,   MC_i = C_i · m = c_i*Δ + kc_i

Expanding the product:
    MA_i * MB_i - MC_i * Δ
    = (a_i*Δ + ka_i)(b_i*Δ + kb_i) - (c_i*Δ + kc_i)*Δ
    = (a_i*b_i - c_i)*Δ² + (a_i*kb_i + b_i*ka_i - kc_i)*Δ + ka_i*kb_i
    =         0          +             t_i              *Δ +     v_i

(the Δ² term vanishes when a_i*b_i = c_i, i.e. when the constraint is satisfied)

The prover reveals (t_i, v_i) per constraint; the verifier checks the identity.
Batching with a random challenge χ reduces this to two field elements (T, V).

Loading from a circom .r1cs file
---------------------------------
    from voleith.utils.r1cs_parser import parse_r1cs
    from voleith.relations.r1cs import R1CSRelation

    r1cs_file = parse_r1cs("circuit.r1cs")
    relation  = R1CSRelation.from_r1cs_file(r1cs_file)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


# ── helpers ───────────────────────────────────────────────────────────────────

def eval_lc(lc: dict, w, field_cls) -> object:
    """
    Evaluate sparse linear combination  Σ_{j} coeff_j * w[j]  over field_cls.

    Parameters
    ----------
    lc        : {wire_index: int_coefficient}
    w         : galois FieldArray of shape (n_wires,)
    field_cls : galois.GF(p)
    """
    result = field_cls(0)
    for wire_idx, coeff in lc.items():
        result = result + field_cls(int(coeff)) * w[int(wire_idx)]
    return result


# ── relation ──────────────────────────────────────────────────────────────────

@dataclass
class R1CSRelation:
    """
    Public R1CS statement: the circuit structure (A, B, C matrices) plus
    the concrete values of all public wires.

    Attributes
    ----------
    n_wires       : total wire count; wire 0 is always the constant 1
    n_pub_out     : public output wires (wires 1 .. n_pub_out)
    n_pub_in      : public input wires (wires n_pub_out+1 .. n_pub_out+n_pub_in)
    constraints   : list of (A_i, B_i, C_i), each a dict {wire_idx: int_coeff}
    public_values : concrete integer values for wires 1 .. (n_pub_out + n_pub_in)
                    in order.  Empty list means "not yet bound" (demos only).
    """

    n_wires:       int
    n_pub_out:     int
    n_pub_in:      int
    constraints:   list = field(default_factory=list)
    public_values: list = field(default_factory=list)

    # ── witness helpers ───────────────────────────────────────────────────────

    def n_public(self) -> int:
        """Number of wires known to the verifier (constant + public outputs + public inputs)."""
        return 1 + self.n_pub_out + self.n_pub_in

    def check(self, w, field_cls) -> bool:
        """Return True iff every constraint (A_i·w)*(B_i·w) = C_i·w is satisfied."""
        for A, B, C in self.constraints:
            a = eval_lc(A, w, field_cls)
            b = eval_lc(B, w, field_cls)
            c = eval_lc(C, w, field_cls)
            if a * b != c:
                return False
        return True

    # ── prover-side computation ───────────────────────────────────────────────

    def compute_mult_proof(self, w, k, field_cls) -> tuple[list, list]:
        """
        Compute per-constraint Quicksilver terms for the prover.

            t_i = a_i*kb_i + b_i*ka_i - kc_i
            v_i = ka_i * kb_i

        Parameters
        ----------
        w         : galois FieldArray (n_wires,) — the witness
        k         : galois FieldArray (n_wires,) — the VOLE mask
        field_cls : galois.GF(p)

        Returns
        -------
        (ts, vs) — two lists of field elements, one per constraint
        """
        ts, vs = [], []
        for A, B, C in self.constraints:
            a  = eval_lc(A, w, field_cls)
            b  = eval_lc(B, w, field_cls)
            ka = eval_lc(A, k, field_cls)
            kb = eval_lc(B, k, field_cls)
            kc = eval_lc(C, k, field_cls)
            ts.append(a * kb + b * ka - kc)
            vs.append(ka * kb)
        return ts, vs

    # ── verifier-side computation ─────────────────────────────────────────────

    def compute_mult_check(self, m, delta, field_cls) -> list:
        """
        Compute per-constraint left-hand side of the Quicksilver check:

            check_i = MA_i * MB_i - MC_i * delta

        The verifier checks that  Σ χ^i * check_i  =  T*delta + V.

        Parameters
        ----------
        m         : galois FieldArray (n_wires,) — authenticated witness
        delta     : galois FieldArray scalar — the VOLE key
        field_cls : galois.GF(p)
        """
        checks = []
        for A, B, C in self.constraints:
            MA = eval_lc(A, m, field_cls)
            MB = eval_lc(B, m, field_cls)
            MC = eval_lc(C, m, field_cls)
            checks.append(MA * MB - MC * delta)
        return checks

    # ── serialisation ─────────────────────────────────────────────────────────

    def encode(self) -> bytes:
        """
        Deterministic encoding for use as input to Fiat-Shamir hashing.

        Includes public_values so that the VOLE key Δ is bound to the
        concrete public wire values (e.g. the Merkle root).  A prover
        claiming a different root would produce a different Δ and fail.
        """
        data = {
            "n_wires":       self.n_wires,
            "n_pub_out":     self.n_pub_out,
            "n_pub_in":      self.n_pub_in,
            "public_values": [int(v) for v in self.public_values],
            "constraints": [
                (
                    {str(k): int(v) for k, v in A.items()},
                    {str(k): int(v) for k, v in B.items()},
                    {str(k): int(v) for k, v in C.items()},
                )
                for A, B, C in self.constraints
            ],
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    # ── factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_r1cs_file(cls, r1cs_file, public_values: list | None = None) -> "R1CSRelation":
        """
        Build an R1CSRelation from a parsed R1CSFile (see r1cs_parser.py).

        Parameters
        ----------
        r1cs_file     : R1CSFile — from parse_r1cs()
        public_values : list[int] | None
            Concrete integer values for the public wires, in wire order
            (wires 1 .. n_pub_out + n_pub_in).  Pass the slice of the
            witness vector: witness[1 : 1 + n_pub_out + n_pub_in].
            If None or empty, public-wire binding is disabled (demos only).

        Note: the field prime in the .r1cs file is ignored here — use
        r1cs_file.prime to construct galois.GF(prime) for the prover/verifier.
        """
        return cls(
            n_wires=r1cs_file.n_wires,
            n_pub_out=r1cs_file.n_pub_out,
            n_pub_in=r1cs_file.n_pub_in,
            constraints=r1cs_file.constraints,
            public_values=list(public_values) if public_values else [],
        )
