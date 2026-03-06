"""
Fiat-Shamir transform.

The Fiat-Shamir heuristic converts an interactive (commit -> challenge ->
response) sigma protocol into a non-interactive proof by replacing the
verifier's random challenge with a hash of the protocol transcript so far.

In the Random Oracle Model (ROM), this is provably sound: the adversary
cannot predict the challenge before committing, because the hash function
behaves like a truly random function.

Here we derive the VOLE key Δ as:
  Δ = H("voleith-fs-v1" || statement_bytes || seed_commitment)

This forces Δ to be determined *after* the prover has committed to the seed
(and therefore to k = PRG(seed)).  The prover cannot choose k to depend on Δ.
"""

import hashlib


def derive_challenge(
    statement_bytes: bytes,
    seed_commitment: bytes,
    field: object,   # galois.GF(p)
) -> object:
    """
    Derive the VOLE key Δ ∈ F via Fiat-Shamir.

    Parameters
    ----------
    statement_bytes : bytes       — deterministic encoding of the public statement
    seed_commitment : bytes       — commitment to the PRG seed (produced before calling this)
    field           : galois.GF(p) — the field to produce Δ in

    Returns
    -------
    Δ as a galois FieldArray scalar.
    """
    h = hashlib.sha3_256()
    h.update(b"voleith-fs-v1:")
    h.update(statement_bytes)
    h.update(b":")
    h.update(seed_commitment)
    digest = h.digest()

    p = int(field.characteristic)
    val = int.from_bytes(digest, "big") % p
    return field(val)
