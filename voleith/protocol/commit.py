"""
Hash-based commitment scheme.

A commitment scheme has two phases:

  commit(value, randomness) -> commitment
      The committer publishes *commitment*.  This is *hiding*: the
      commitment reveals nothing about *value* (because randomness is secret).

  verify_commit(commitment, value, randomness) -> bool
      Anyone can verify that a commitment opens to a claimed value.
      This is *binding*: it is computationally hard to find two different
      values that open the same commitment.

We use SHA3-256:
  commitment = SHA3-256(randomness || value_bytes)

The prepended randomness (sometimes called the "blinding factor") ensures
hiding.  The collision resistance of SHA3-256 ensures binding.
"""

import hashlib


def commit(value_bytes: bytes, randomness: bytes) -> bytes:
    """
    Commit to *value_bytes* using *randomness* as a blinding factor.

    Parameters
    ----------
    value_bytes : bytes — the data to commit to (e.g. a serialised seed)
    randomness  : bytes — uniformly random bytes (>= 16 bytes recommended)

    Returns
    -------
    32-byte commitment (SHA3-256 digest).
    """
    h = hashlib.sha3_256()
    h.update(b"voleith-commit-v1:")
    h.update(randomness)
    h.update(b":")
    h.update(value_bytes)
    return h.digest()


def verify_commit(commitment: bytes, value_bytes: bytes, randomness: bytes) -> bool:
    """Return True iff *commitment* is a valid opening for (*value_bytes*, *randomness*)."""
    return commitment == commit(value_bytes, randomness)
