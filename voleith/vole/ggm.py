"""
GGM (Goldreich-Goldwasser-Micali) tree for VOLEitH.

Provides a compact way to commit to N = 2^λ per-party seeds and
efficiently open all-but-one of them (punctured opening) in O(λ) space.

Structure
---------
A binary tree of depth λ = 7 holds N = 128 leaf seeds (16 bytes each).
Each internal node expands to two children via AES-ECB:

    left_child  = AES_{K0}(node)
    right_child = AES_{K1}(node)

where K0 and K1 are fixed 16-byte keys derived from domain separators:

    K0 = SHA3-256("voleith-ggm-key-0")[:16]
    K1 = SHA3-256("voleith-ggm-key-1")[:16]

On top of the seed tree sits a commitment tree (a Merkle tree):

    leaf_com(i, seed) = SHA3-256("voleith-ggm-leaf:" || i.to_bytes(2) || seed)
    internal_com(L, R) = SHA3-256("voleith-ggm-int:" || L || R)

The binding commitment is the root of the commitment tree.

Punctured opening for party j*
--------------------------------
A punctured opening reveals every leaf seed except seed_{j*}, using
exactly DEPTH sibling seeds (one per level).  At each level the sibling
seed can be expanded into an entire sub-tree of leaves.

The opening also carries `leaf_com_{j*}` — the commitment hash for the
punctured leaf — so the verifier can reconstruct and check the root
commitment without ever learning seed_{j*} itself.

Node indexing
-------------
Nodes are 1-indexed:
  - root = 1
  - children of node i = (2i, 2i+1)
  - leaves = nodes N..2N-1  (leaf j ↔ node N+j)
"""

import hashlib
from dataclasses import dataclass

from Crypto.Cipher import AES

# ── constants ─────────────────────────────────────────────────────────────────

N_PARTIES: int = 128
DEPTH: int = 7        # log2(N_PARTIES)
SEED_BYTES: int = 16  # AES block size

# Fixed AES keys, derived from domain separators.
# Using SHA3-256 makes them fully auditable / reproducible.
K0: bytes = hashlib.sha3_256(b"voleith-ggm-key-0").digest()[:SEED_BYTES]
K1: bytes = hashlib.sha3_256(b"voleith-ggm-key-1").digest()[:SEED_BYTES]


# ── internal helpers ──────────────────────────────────────────────────────────

def _aes(seed: bytes, key: bytes) -> bytes:
    """AES-ECB: encrypt one 16-byte block (seed) with a 16-byte key."""
    return AES.new(key, AES.MODE_ECB).encrypt(seed)


def _leaf_com(i: int, seed: bytes) -> bytes:
    """Commitment hash for leaf i with a given seed."""
    h = hashlib.sha3_256()
    h.update(b"voleith-ggm-leaf:")
    h.update(i.to_bytes(2, "big"))
    h.update(seed)
    return h.digest()


def _internal_com(left: bytes, right: bytes) -> bytes:
    """Commitment hash for an internal node given children commitments."""
    h = hashlib.sha3_256()
    h.update(b"voleith-ggm-int:")
    h.update(left)
    h.update(right)
    return h.digest()


def _build_seed_tree(root_seed: bytes) -> list[bytes]:
    """
    Build the full GGM seed tree (1-indexed, length 2*N_PARTIES).

    tree[1] = root_seed
    tree[2i] = AES_{K0}(tree[i])
    tree[2i+1] = AES_{K1}(tree[i])
    Leaves: tree[N_PARTIES] .. tree[2*N_PARTIES - 1]
    """
    tree = [b""] * (2 * N_PARTIES)
    tree[1] = root_seed
    for i in range(1, N_PARTIES):
        tree[2 * i]     = _aes(tree[i], K0)
        tree[2 * i + 1] = _aes(tree[i], K1)
    return tree


def _build_com_tree(seed_tree: list[bytes]) -> list[bytes]:
    """
    Build the commitment (Merkle) tree on top of the seed tree.

    com[N+i] = leaf_com(i, seed_tree[N+i])
    com[i]   = internal_com(com[2i], com[2i+1])   for i in N-1..1
    """
    com = [b""] * (2 * N_PARTIES)
    for i in range(N_PARTIES):
        com[N_PARTIES + i] = _leaf_com(i, seed_tree[N_PARTIES + i])
    for i in range(N_PARTIES - 1, 0, -1):
        com[i] = _internal_com(com[2 * i], com[2 * i + 1])
    return com


def _expand_subtree(root_seed: bytes, depth_remaining: int) -> list[bytes]:
    """
    Expand root_seed into 2^depth_remaining leaf seeds.

    When depth_remaining == 0 the seed is already a leaf: return [root_seed].
    """
    if depth_remaining == 0:
        return [root_seed]
    left  = _aes(root_seed, K0)
    right = _aes(root_seed, K1)
    return (
        _expand_subtree(left,  depth_remaining - 1) +
        _expand_subtree(right, depth_remaining - 1)
    )


# ── public dataclass ──────────────────────────────────────────────────────────

@dataclass
class GGMOpening:
    """
    A punctured GGM opening for party j*.

    Attributes
    ----------
    sibling_seeds : list[bytes] of length DEPTH
        One 16-byte sibling seed per level (from depth 1 down to depth DEPTH).
        Each seed can be expanded to recover all leaf seeds in that sub-tree.
    leaf_com_j : bytes (32 bytes)
        SHA3-256 commitment to seed_{j*}. Lets the verifier reconstruct the
        Merkle root without learning seed_{j*} itself.
    j_star : int
        The index of the punctured party (0-based).
    commitment : bytes (32 bytes)
        The GGM commitment (Merkle root) — stored for convenience.
    """
    sibling_seeds: list
    leaf_com_j:    bytes
    j_star:        int
    commitment:    bytes


# ── public API ────────────────────────────────────────────────────────────────

def ggm_expand(root_seed: bytes) -> list[bytes]:
    """
    Expand root_seed into N_PARTIES = 128 leaf seeds.

    Parameters
    ----------
    root_seed : bytes — 16-byte root seed (uniformly random)

    Returns
    -------
    list of N_PARTIES 16-byte leaf seeds, leaf[j] = seed for party j.
    """
    tree = _build_seed_tree(root_seed)
    return [tree[N_PARTIES + j] for j in range(N_PARTIES)]


def ggm_commit(root_seed: bytes) -> bytes:
    """
    Compute the GGM commitment (Merkle root over all leaf commitments).

    Parameters
    ----------
    root_seed : bytes — 16-byte root seed

    Returns
    -------
    32-byte commitment.
    """
    seed_tree = _build_seed_tree(root_seed)
    com_tree  = _build_com_tree(seed_tree)
    return com_tree[1]


def ggm_puncture(root_seed: bytes, j_star: int) -> GGMOpening:
    """
    Produce a punctured opening that reveals all leaf seeds except seed_{j*}.

    The opening consists of DEPTH = 7 sibling seeds (one per tree level)
    plus the commitment hash for the punctured leaf.  Total size:
        7 * 16 + 32 = 144 bytes.

    Parameters
    ----------
    root_seed : bytes — 16-byte root seed
    j_star    : int   — index of the party to puncture (0 ≤ j* < N_PARTIES)

    Returns
    -------
    GGMOpening
    """
    if not (0 <= j_star < N_PARTIES):
        raise ValueError(f"j_star must be in [0, {N_PARTIES}), got {j_star}")

    seed_tree = _build_seed_tree(root_seed)
    com_tree  = _build_com_tree(seed_tree)
    commitment = com_tree[1]

    # At depth d (1 = just below root, DEPTH = leaf level), find the sibling
    # of the node on the path from root to leaf j_star.
    #
    # Node on path at depth d:   (1 << d) | (j_star >> (DEPTH - d))
    # Sibling at depth d:        path_node ^ 1   (flip last bit)
    sibling_seeds = []
    for d in range(1, DEPTH + 1):
        path_node    = (1 << d) | (j_star >> (DEPTH - d))
        sibling_node = path_node ^ 1
        sibling_seeds.append(seed_tree[sibling_node])

    leaf_com_j = com_tree[N_PARTIES + j_star]

    return GGMOpening(
        sibling_seeds=sibling_seeds,
        leaf_com_j=leaf_com_j,
        j_star=j_star,
        commitment=commitment,
    )


def ggm_recover(opening: GGMOpening) -> list[bytes | None]:
    """
    Recover all N_PARTIES leaf seeds from a punctured opening, and verify
    that the recovered seeds are consistent with opening.commitment.

    Parameters
    ----------
    opening : GGMOpening — as returned by ggm_puncture

    Returns
    -------
    list of N_PARTIES entries:
        entry j = 16-byte seed for party j  (bytes)
        entry j_star = None  (never revealed)

    Raises
    ------
    ValueError if the commitment check fails (tampered opening).
    """
    j_star        = opening.j_star
    sibling_seeds = opening.sibling_seeds
    leaf_com_j    = opening.leaf_com_j
    commitment    = opening.commitment

    if len(sibling_seeds) != DEPTH:
        raise ValueError(f"Expected {DEPTH} sibling seeds, got {len(sibling_seeds)}")

    leaf_seeds: list[bytes | None] = [None] * N_PARTIES

    # Recover leaf seeds from sibling sub-trees.
    # At depth d, the sibling seed covers a sub-tree of 2^(DEPTH-d) leaves.
    # The sub-tree root (1-indexed) has relative index sibling_subtree_root
    # within depth d, starting at 0 from the left.
    for d, sib_seed in enumerate(sibling_seeds, start=1):
        # Path node at depth d: (1 << d) | (j_star >> (DEPTH - d))
        path_node    = (1 << d) | (j_star >> (DEPTH - d))
        sibling_node = path_node ^ 1

        # Relative index of the sibling within its level (0-based left-to-right)
        sibling_rel = sibling_node - (1 << d)

        # Leaf range covered by this sibling sub-tree
        subtree_depth = DEPTH - d          # 0 at leaf level
        leaf_count    = 1 << subtree_depth
        leaf_start    = sibling_rel * leaf_count

        sub_leaves = _expand_subtree(sib_seed, subtree_depth)
        for i, s in enumerate(sub_leaves):
            leaf_seeds[leaf_start + i] = s

    # Reconstruct commitment tree and verify.
    com = [b""] * (2 * N_PARTIES)
    for i in range(N_PARTIES):
        if i == j_star:
            com[N_PARTIES + i] = leaf_com_j
        else:
            com[N_PARTIES + i] = _leaf_com(i, leaf_seeds[i])  # type: ignore[arg-type]
    for i in range(N_PARTIES - 1, 0, -1):
        com[i] = _internal_com(com[2 * i], com[2 * i + 1])

    if com[1] != commitment:
        raise ValueError("GGM commitment verification failed: opening is inconsistent.")

    return leaf_seeds
