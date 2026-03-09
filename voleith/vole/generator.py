"""
N-party VOLE correlation generator using the GGM tree.

Each of N=128 virtual parties contributes a mask k^p = prg_expand(seed_p).
The combined mask k = Σ_p k^p and the authenticated witness m = x·Δ + k.

Because each seed_p is committed via the GGM Merkle tree before Δ is
derived, a cheating prover cannot tailor any k^p to a chosen Δ.
"""

from .correlation import VOLECorrelation
from .ggm import ggm_expand, N_PARTIES
from ..utils.prg import prg_expand


def generate_vole(
    witness: list[int],
    root_seed: bytes,
    delta: object,   # galois FieldArray scalar
    field: object,   # galois.GF(p)
) -> VOLECorrelation:
    """
    Generate a VOLE correlation for *witness* using an N-party GGM mask.

    Steps
    -----
    1. Expand root_seed → N=128 leaf seeds via GGM tree
    2. Per party p: k^p = prg_expand(seed_p, n_witnesses)
    3. Combined mask: k = Σ_p k^p  (sum over the field)
    4. Compute x = field(witness)
    5. Compute m = x * delta + k

    Parameters
    ----------
    witness   : list[int]  — the secret values, in [0, p-1]
    root_seed : bytes      — 16-byte GGM root seed (must be committed before delta)
    delta     : scalar FieldArray — the VOLE key (Fiat-Shamir challenge)
    field     : galois.GF(p)

    Returns
    -------
    VOLECorrelation with m = x * delta + k  and  k = Σ_p prg_expand(seed_p).
    """
    n = len(witness)
    leaf_seeds = ggm_expand(root_seed)

    # Sum per-party masks over the field
    k = field([0] * n)
    for seed_p in leaf_seeds:
        k = k + prg_expand(seed_p, n, field)

    x = field(witness)
    m = x * delta + k
    return VOLECorrelation(x=x, k=k, delta=delta, m=m)


def generate_per_party_masks(
    root_seed: bytes,
    n: int,
    field: object,
) -> list:
    """
    Return the list of N per-party mask vectors [k^0, k^1, ..., k^{N-1}].

    Used by the prover when computing per-party Quicksilver T^p terms.

    Parameters
    ----------
    root_seed : bytes      — 16-byte GGM root seed
    n         : int        — number of field elements per mask (= n_wires)
    field     : galois.GF(p)

    Returns
    -------
    list of N_PARTIES FieldArrays, each of shape (n,).
    """
    leaf_seeds = ggm_expand(root_seed)
    return [prg_expand(seed_p, n, field) for seed_p in leaf_seeds]
