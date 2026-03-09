"""
Poseidon preimage proof — end-to-end demo with correctness checks.

Statement : I know preimage such that Poseidon(preimage) = hash,
            where hash is a public output.

Correctness checks performed
-----------------------------
  1. Honest proof is accepted              (completeness)
  2. Tampered T is rejected                (soundness — flip one field element)
  3. Tampered m is rejected                (Fiat-Shamir χ catches it)
  4. Wrong preimage produces a DIFFERENT
     hash and its proof is still accepted  (each statement is independently valid)
  5. Public-wire binding note              (limitation of the simplified protocol)
"""

import galois

from voleith.utils.circom import compile_and_witness
from voleith.relations.r1cs import R1CSRelation
from voleith.protocol.r1cs_prover import R1CSProver, R1CSProof
from voleith.protocol.r1cs_verifier import R1CSVerifier


# ── 0. Compile circuit and generate witness ───────────────────────────────────

print("=" * 60)
print("Poseidon Preimage — VOLEitH demo")
print("=" * 60)

r1cs_file, witness = compile_and_witness(
    "poseidon_preimage.circom",
    {"preimage": "42"},
)

# wire 0 = constant 1 (circom convention)
# wire 1 = hash (public output, n_pub_out = 1)
# wire 2+ = Poseidon internals (private)
hash_42 = witness[1]
print(f"\nField     : BN254 scalar field (prime = {r1cs_file.prime})")
print(f"Preimage  : 42  (private)")
print(f"Hash      : Poseidon(42) = {hash_42}  (public output, wire 1)")
print(f"Circuit   : {r1cs_file.n_constraints} R1CS constraints, {r1cs_file.n_wires} wires")

F        = galois.GF(r1cs_file.prime)
relation = R1CSRelation.from_r1cs_file(r1cs_file)
prover   = R1CSProver(relation, F)
verifier = R1CSVerifier(relation, F)


# ── 1. Honest proof ───────────────────────────────────────────────────────────

print("\n" + "-" * 60)
print("CHECK 1 — Honest proof is accepted (completeness)")
print("-" * 60)

proof  = prover.prove(witness)
result = verifier.verify(proof)

print(f"  Result: {'ACCEPTED ✓' if result else 'REJECTED ✗'}")
assert result, "Honest proof was rejected — something is wrong!"


# ── 2. Tampered T ─────────────────────────────────────────────────────────────

print("\n" + "-" * 60)
print("CHECK 2 — Tampered T is rejected")
print("-" * 60)

tampered = R1CSProof(
    seed_commitment=proof.seed_commitment,
    delta=proof.delta,
    m=proof.m,
    chi=proof.chi,
    T=F((int(proof.T) + 1) % r1cs_file.prime),
    V=proof.V,
)
result2 = verifier.verify(tampered)
print(f"  Result: {'ACCEPTED' if result2 else 'REJECTED ✗  (correct!)'}")
assert not result2, "Tampered T was accepted — Quicksilver check is broken!"


# ── 3. Tampered m ─────────────────────────────────────────────────────────────

print("\n" + "-" * 60)
print("CHECK 3 — Tampered m is rejected (Fiat-Shamir χ)")
print("-" * 60)

import numpy as np
tampered_m = F(np.array(proof.m).tolist())
tampered_m[2] = F((int(tampered_m[2]) + 1) % r1cs_file.prime)   # flip wire 2

tampered3 = R1CSProof(
    seed_commitment=proof.seed_commitment,
    delta=proof.delta,
    m=tampered_m,
    chi=proof.chi,
    T=proof.T,
    V=proof.V,
)
result3 = verifier.verify(tampered3)
print(f"  Result: {'ACCEPTED' if result3 else 'REJECTED ✗  (correct!)'}")
assert not result3, "Tampered m was accepted — Fiat-Shamir χ check is broken!"


# ── 4. Different preimage → different hash ────────────────────────────────────

print("\n" + "-" * 60)
print("CHECK 4 — Different preimage produces a different hash")
print("-" * 60)

_, witness_99 = compile_and_witness(
    "poseidon_preimage.circom",
    {"preimage": "99"},
)
hash_99   = witness_99[1]
proof_99  = prover.prove(witness_99)
result_99 = verifier.verify(proof_99)

print(f"  Poseidon(99) = {hash_99}")
print(f"  hash(42) == hash(99) ? {hash_42 == hash_99}  (should be False)")
print(f"  Proof for preimage=99: {'ACCEPTED ✓' if result_99 else 'REJECTED ✗'}")
assert hash_42 != hash_99, "Hash collision — Poseidon broken or field too small!"
assert result_99, "Honest proof for preimage=99 was rejected!"


# ── 5. Public-wire binding note ───────────────────────────────────────────────

print("\n" + "-" * 60)
print("NOTE — Public-wire binding (current limitation)")
print("-" * 60)
print(f"""
  The verifier checks that all R1CS constraints are satisfied and that
  the Fiat-Shamir challenges are consistent — but it does NOT independently
  assert that wire 1 equals any specific hash value.

  Right now, 'relation.encode()' hashes the circuit *structure* only, not
  the public output values.  A verifier that cares which hash was proved
  must manually check:

      assert int(witness[1]) == expected_hash

  In the full VOLEitH protocol (Track A1/A4 in TODO.md), the GGM tree
  opening lets the verifier reconstruct the public-wire masks and enforce
  this binding automatically.  For now it is the caller's responsibility.

  Expected hash for preimage=42 : {hash_42}
""")


print("=" * 60)
print("All correctness checks passed.")
print("=" * 60)
