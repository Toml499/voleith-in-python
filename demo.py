"""
VOLE-in-the-Head — end-to-end demo
====================================
Statement : I know x = [3, 5] such that A @ x = b  over GF(7).

    A = [[1, 1],   b = [1,   (1*3 + 1*5 = 8 = 1 mod 7)
         [1, 2]]       [6]]  (1*3 + 2*5 = 13 = 6 mod 7)

Each step is printed so you can trace the protocol.
"""

import numpy as np
import galois

from voleith.relations.linear import LinearRelation
from voleith.protocol.prover import Prover
from voleith.protocol.verifier import Verifier


# ── 0. Setup ─────────────────────────────────────────────────────────────────

F = galois.GF(7)

A = F([[1, 1],
       [1, 2]])
b = F([1, 6])
witness = [3, 5]

relation = LinearRelation(A=A, b=b)

print("=" * 60)
print("VOLE-in-the-Head — Linear Relation Demo")
print("=" * 60)
print(f"\nField     : GF(7)")
print(f"Statement : A @ x = b")
print(f"  A = {np.array(A).tolist()}")
print(f"  b = {np.array(b).tolist()}")
print(f"Witness   : x = {witness}  (kept secret)")

# Sanity check
assert bool(np.all(A @ F(witness) == b)), "Bug: witness doesn't satisfy relation!"
print(f"\n  Sanity check: A @ x = {np.array(A @ F(witness)).tolist()} = b ✓")


# ── 1. Prove ──────────────────────────────────────────────────────────────────

print("\n" + "-" * 60)
print("STEP 1 — Prover generates proof")
print("-" * 60)

prover = Prover(relation=relation, field=F)
proof = prover.prove(witness)

print(f"  commitment      : {proof.ggm_opening.commitment.hex()[:32]}...  (GGM Merkle root)")
print(f"  j* (party)      : {proof.ggm_opening.j_star}  (punctured party index)")
print(f"  Δ (VOLE key)    : {int(proof.delta)}  (Fiat-Shamir challenge)")
print(f"  m (auth. values): {np.array(proof.m).tolist()}  (= x*Δ + k, hides x)")
print(f"  correction_j    : {np.array(proof.correction_j).tolist()}  (= A @ k^{{j*}})")


# ── 2. Verify (honest proof) ──────────────────────────────────────────────────

print("\n" + "-" * 60)
print("STEP 2 — Verifier checks the proof")
print("-" * 60)

verifier = Verifier(relation=relation, field=F)
result = verifier.verify(proof)

print(f"\n  Check 1 — Fiat-Shamir: Δ = Hash(statement || comm)")
print(f"  Check 2 — Linear VOLE:  A @ m = b * Δ + c")
print(f"\n  Result: {'ACCEPTED ✓' if result else 'REJECTED ✗'}")
assert result, "Honest proof was rejected — something is wrong!"


# ── 3. Tampered proof ─────────────────────────────────────────────────────────

print("\n" + "-" * 60)
print("STEP 3 — Verifier rejects a tampered proof")
print("-" * 60)

from voleith.protocol.prover import Proof
import copy

# Flip one bit in the correction vector (simulates a cheating prover)
tampered_correction = F(np.array(proof.correction_j).tolist())
tampered_correction[0] = F((int(tampered_correction[0]) + 1) % 7)

tampered_proof = Proof(
    ggm_opening=proof.ggm_opening,
    delta=proof.delta,
    m=proof.m,
    correction_j=tampered_correction,
)

print(f"  Tampered correction: {np.array(tampered_proof.correction_j).tolist()}")
tampered_result = verifier.verify(tampered_proof)
print(f"\n  Result: {'ACCEPTED' if tampered_result else 'REJECTED ✗  (correct!)'}")
assert not tampered_result, "Tampered proof was accepted — something is wrong!"


# ── 4. Wrong witness ──────────────────────────────────────────────────────────

print("\n" + "-" * 60)
print("STEP 4 — Prover with wrong witness is caught")
print("-" * 60)
print("  (Note: this only works because the prover is honest about m.")
print("   See prover.py for the full soundness discussion.)")

wrong_witness = [1, 2]   # A @ [1,2] = [3, 5] ≠ b
print(f"  Wrong witness: x = {wrong_witness}")
print(f"  A @ x = {np.array(A @ F(wrong_witness)).tolist()}  ≠  b = {np.array(b).tolist()}")

try:
    bad_proof = prover.prove(wrong_witness)
    bad_result = verifier.verify(bad_proof)
    print(f"\n  Result: {'ACCEPTED' if bad_result else 'REJECTED ✗  (correct!)'}")
    assert not bad_result
except ValueError as e:
    print(f"\n  Prover raised: {e}")


print("\n" + "=" * 60)
print("Demo complete.")
print("=" * 60)
