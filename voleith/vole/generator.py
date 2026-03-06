"""
VOLE correlation generator.

The prover calls generate_vole() to create the full correlation "in the head".
In production, delta would be chosen by the verifier before the prover ever
sees it.  Here the caller supplies delta (which will be derived via
Fiat-Shamir from the prover's prior commitment, preserving the ordering
that makes the scheme secure).
"""

from .correlation import VOLECorrelation
from ..utils.prg import prg_expand


def generate_vole(
    witness: list[int],
    seed: bytes,
    delta: object,   # galois FieldArray scalar
    field: object,   # galois.GF(p)
) -> VOLECorrelation:
    """
    Generate a VOLE correlation for *witness* using a random *seed*.

    Steps
    -----
    1. Expand seed -> k  via PRG  (k is the "one-time pad" on the witness)
    2. Compute x = field(witness)
    3. Compute m = x * delta + k  (the authenticated values)

    The caller is responsible for ensuring that *delta* was derived AFTER
    committing to the seed, so the prover could not have tailored k to delta.

    Parameters
    ----------
    witness : list[int]  — the secret values, in [0, p-1]
    seed    : bytes      — 32-byte random seed (determines k via PRG)
    delta   : scalar FieldArray — the VOLE key (Fiat-Shamir challenge)
    field   : galois.GF(p)

    Returns
    -------
    VOLECorrelation with the constraint m = x * delta + k satisfied.
    """
    x = field(witness)
    k = prg_expand(seed, len(witness), field)
    m = x * delta + k
    return VOLECorrelation(x=x, k=k, delta=delta, m=m)
