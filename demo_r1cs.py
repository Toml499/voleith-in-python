"""
VOLE-in-the-Head — R1CS (Quicksilver) demo
===========================================
Statement : I know (a, b) such that  a² + b² = c  over GF(101),
            where c = 25 is the PUBLIC output.

Circuit (R1CS over GF(101))
---------------------------
Wire layout:
  w[0] = 1          (constant — always 1 by convention)
  w[1] = a          (private input)
  w[2] = b          (private input)
  w[3] = a²         (intermediate)
  w[4] = b²         (intermediate)
  w[5] = c = a²+b²  (public output)

Constraints:
  #0  a  * a  = a²    →  A={1:1}, B={1:1}, C={3:1}
  #1  b  * b  = b²    →  A={2:1}, B={2:1}, C={4:1}
  #2  (a²+b²) * 1 = c →  A={3:1, 4:1}, B={0:1}, C={5:1}

Why three constraints?
  Constraints #0 and #1 are genuine multiplications (non-linear).
  Constraint #2 is a "degenerate" multiplication (one side is the constant 1)
  that encodes the linear relation a² + b² = c.

Quicksilver check (per constraint)
-----------------------------------
  MA_i * MB_i - MC_i * Δ  =  t_i * Δ + v_i

Batched over all three constraints with random challenge χ:
  Σ_i χ^i * (MA_i * MB_i - MC_i * Δ)  =  T * Δ + V

Using a .r1cs file instead
---------------------------
If you compile a circom circuit and get circuit.r1cs, replace the manual
witness and relation construction with:

    from voleith.utils.r1cs_parser import parse_r1cs
    from voleith.relations.r1cs   import R1CSRelation
    import galois

    r1cs_file = parse_r1cs("circuit.r1cs")
    F         = galois.GF(r1cs_file.prime)
    relation  = R1CSRelation.from_r1cs_file(r1cs_file)

    # witness = full wire vector produced by circom's witness generator
    #   (snarkjs or the .wasm file).  wire[0] must be 1.
    prover   = R1CSProver(relation=relation, field=F)
    verifier = R1CSVerifier(relation=relation, field=F)
    proof    = prover.prove(witness)
    result   = verifier.verify(proof)
"""

import galois
import numpy as np

from voleith.relations.r1cs   import R1CSRelation
from voleith.protocol.r1cs_prover   import R1CSProver
from voleith.protocol.r1cs_verifier import R1CSVerifier


# ── 0. Setup ─────────────────────────────────────────────────────────────────

F = galois.GF(101)

# Witness:  [1,  a,  b,  a²,  b², c]
a, b = 3, 4
a2   = a * a          # 9
b2   = b * b          # 16
c    = a2 + b2        # 25

witness = [1, a, b, a2, b2, c]

# R1CS constraints (sparse dicts: {wire_idx: integer_coefficient})
constraints = [
    # #0  a * a = a²
    ({1: 1}, {1: 1}, {3: 1}),
    # #1  b * b = b²
    ({2: 1}, {2: 1}, {4: 1}),
    # #2  (a² + b²) * 1 = c
    ({3: 1, 4: 1}, {0: 1}, {5: 1}),
]

relation = R1CSRelation(
    n_wires=6,
    n_pub_out=1,   # wire 5 (c) is the public output
    n_pub_in=0,
    constraints=constraints,
)

print("=" * 60)
print("VOLE-in-the-Head — R1CS (Quicksilver) Demo")
print("=" * 60)
print(f"\nField     : GF(101)")
print(f"Statement : a² + b² = c  (c = {c} is public)")
print(f"Circuit   : {len(constraints)} R1CS constraints, {relation.n_wires} wires")
print(f"Witness   : a = {a}, b = {b}  (kept secret)")

# Sanity check
assert relation.check(F(witness), F), "Bug: witness doesn't satisfy the R1CS!"
print(f"\n  Sanity check: all constraints satisfied ✓")
print(f"    #0  {a} * {a} = {a2}  ✓")
print(f"    #1  {b} * {b} = {b2}  ✓")
print(f"    #2  {a2} + {b2} = {c}  ✓")


# ── 1. Prove ──────────────────────────────────────────────────────────────────

print("\n" + "-" * 60)
print("STEP 1 — Prover generates Quicksilver proof")
print("-" * 60)

prover = R1CSProver(relation=relation, field=F)
proof  = prover.prove(witness)

print(f"  seed_commitment : {proof.seed_commitment.hex()[:32]}...")
print(f"  Δ (VOLE key)    : {int(proof.delta)}")
print(f"  m (auth. wires) : {np.array(proof.m).tolist()}  (= w*Δ + k, hides w)")
print(f"  χ (batch key)   : {int(proof.chi)}")
print(f"  T (cross term)  : {int(proof.T)}  (= Σ χⁱ tᵢ)")
print(f"  V (quad term)   : {int(proof.V)}  (= Σ χⁱ vᵢ)")
print(f"\n  Proof size: 2 field elements (T, V) + authenticated wires (m)")
print(f"  (In a full implementation m would also be replaced by a commitment.)")


# ── 2. Verify (honest proof) ──────────────────────────────────────────────────

print("\n" + "-" * 60)
print("STEP 2 — Verifier checks the proof")
print("-" * 60)

verifier = R1CSVerifier(relation=relation, field=F)
result   = verifier.verify(proof)

print(f"\n  Check 1 — Fiat-Shamir Δ: Δ = Hash(statement || comm)")
print(f"  Check 2 — Fiat-Shamir χ: χ = Hash(statement || comm || m)")
print(f"  Check 3 — Quicksilver:   Σ χⁱ*(MAᵢ*MBᵢ - MCᵢ*Δ) = T*Δ + V")
print(f"\n  Result: {'ACCEPTED ✓' if result else 'REJECTED ✗'}")
assert result, "Honest proof was rejected — something is wrong!"


# ── 3. Tampered T ────────────────────────────────────────────────────────────

print("\n" + "-" * 60)
print("STEP 3 — Verifier rejects a tampered proof (wrong T)")
print("-" * 60)

from voleith.protocol.r1cs_prover import R1CSProof
import copy

tampered = R1CSProof(
    seed_commitment=proof.seed_commitment,
    delta=proof.delta,
    m=proof.m,
    chi=proof.chi,
    T=F((int(proof.T) + 1) % 101),   # flip T by 1
    V=proof.V,
)

tampered_result = verifier.verify(tampered)
print(f"  Tampered T: {int(tampered.T)}  (was {int(proof.T)})")
print(f"  Result: {'ACCEPTED' if tampered_result else 'REJECTED ✗  (correct!)'}")
assert not tampered_result


# ── 4. Wrong witness ──────────────────────────────────────────────────────────

print("\n" + "-" * 60)
print("STEP 4 — Prover with wrong witness is rejected")
print("-" * 60)

wrong_witness = [1, 3, 4, 9, 16, 99]   # c = 99 ≠ 25
print(f"  Wrong witness claims c = 99 (should be 25)")

try:
    bad_proof  = prover.prove(wrong_witness)
    bad_result = verifier.verify(bad_proof)
    print(f"  Result: {'ACCEPTED' if bad_result else 'REJECTED ✗  (correct!)'}")
    assert not bad_result
except ValueError as e:
    print(f"  Prover raised: {e}")


# ── 5. How to use a real .r1cs file ──────────────────────────────────────────

print("\n" + "-" * 60)
print("STEP 5 — Loading from a circom .r1cs file")
print("-" * 60)
print("""
  To use a real Poseidon (or any) circom circuit:

    1. Compile:
         circom poseidon_preimage.circom --r1cs --wasm --sym

    2. Generate witness (e.g. with snarkjs + the .wasm):
         node generate_witness.js circuit.wasm input.json witness.wtns

    3. Export witness to JSON:
         snarkjs wtns export json witness.wtns witness.json

    4. Load in Python:
         from voleith.utils.r1cs_parser import parse_r1cs
         from voleith.relations.r1cs    import R1CSRelation
         import galois, json

         r1cs_file = parse_r1cs("circuit.r1cs")
         F         = galois.GF(r1cs_file.prime)   # e.g. BN254 scalar field
         relation  = R1CSRelation.from_r1cs_file(r1cs_file)

         with open("witness.json") as f:
             w_raw = json.load(f)               # list of decimal strings
         witness = [int(x) for x in w_raw]     # wire 0 is always 1

         prover   = R1CSProver(relation=relation, field=F)
         verifier = R1CSVerifier(relation=relation, field=F)
         proof    = prover.prove(witness)
         result   = verifier.verify(proof)
""")


print("=" * 60)
print("Demo complete.")
print("=" * 60)
