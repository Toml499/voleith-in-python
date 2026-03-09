"""
Parser for the circom .r1cs binary format (version 1).

The .r1cs format is produced by:
    circom circuit.circom --r1cs

Reference: https://github.com/iden3/r1csfile

Binary layout
-------------
  4 bytes  — magic "r1cs" (0x72, 0x31, 0x63, 0x73)
  4 bytes  — version (must be 1), little-endian uint32
  4 bytes  — number of sections, LE uint32
  [sections ...]

Each section:
  4 bytes  — section type, LE uint32
  8 bytes  — section byte size, LE uint64
  N bytes  — section data

Section type 1 — Header
  4 bytes  — field element byte size (e.g. 32 for BN254)
  N bytes  — prime field modulus, little-endian
  4 bytes  — n_wires
  4 bytes  — n_pub_out  (public output wires: 1 .. n_pub_out)
  4 bytes  — n_pub_in   (public input wires)
  4 bytes  — n_prv_in   (private input wires)
  8 bytes  — n_labels
  4 bytes  — n_constraints

Section type 2 — Constraints
  For each of the n_constraints constraints, three linear combinations (A, B, C):
    4 bytes  — nnz (number of non-zero terms)
    For each term:
      4 bytes  — wire index, LE uint32
      N bytes  — coefficient, little-endian field element

Section type 3 — Wire-to-label map (parsed but not used here)
"""

import struct
from dataclasses import dataclass, field


@dataclass
class R1CSFile:
    """Parsed contents of a .r1cs file."""
    prime: int
    n_wires: int
    n_pub_out: int
    n_pub_in: int
    n_prv_in: int
    n_constraints: int
    # Each entry is (A, B, C) where each is {wire_idx: int_coefficient}
    constraints: list = field(default_factory=list)


def parse_r1cs(path: str) -> R1CSFile:
    """Parse a circom .r1cs file and return an R1CSFile."""
    with open(path, "rb") as f:
        data = f.read()
    return _parse(data)


# ── low-level readers ─────────────────────────────────────────────────────────

def _u32(data: bytes, offset: int):
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def _u64(data: bytes, offset: int):
    return struct.unpack_from("<Q", data, offset)[0], offset + 8


# ── section parsers ───────────────────────────────────────────────────────────

def _parse_header(data: bytes, offset: int):
    field_size, offset = _u32(data, offset)
    prime = int.from_bytes(data[offset : offset + field_size], "little")
    offset += field_size
    n_wires,    offset = _u32(data, offset)
    n_pub_out,  offset = _u32(data, offset)
    n_pub_in,   offset = _u32(data, offset)
    n_prv_in,   offset = _u32(data, offset)
    _n_labels,  offset = _u64(data, offset)
    n_constraints, offset = _u32(data, offset)
    return {
        "field_size":    field_size,
        "prime":         prime,
        "n_wires":       n_wires,
        "n_pub_out":     n_pub_out,
        "n_pub_in":      n_pub_in,
        "n_prv_in":      n_prv_in,
        "n_constraints": n_constraints,
    }, offset


def _parse_constraints(data: bytes, offset: int, field_size: int, n_constraints: int):
    constraints = []
    for _ in range(n_constraints):
        lcs = []
        for _ in range(3):  # A, B, C
            nnz, offset = _u32(data, offset)
            lc = {}
            for _ in range(nnz):
                wire_id, offset = _u32(data, offset)
                coeff = int.from_bytes(data[offset : offset + field_size], "little")
                offset += field_size
                lc[wire_id] = coeff
            lcs.append(lc)
        constraints.append(tuple(lcs))
    return constraints, offset


# ── top-level ─────────────────────────────────────────────────────────────────

def _parse(data: bytes) -> R1CSFile:
    offset = 0

    assert data[offset : offset + 4] == b"r1cs", "Not an r1cs file"
    offset += 4

    version, offset = _u32(data, offset)
    assert version == 1, f"Unsupported .r1cs version: {version}"

    nsections, offset = _u32(data, offset)

    # First pass: collect raw bytes for each section type.
    # The spec does not guarantee section ordering, and circom sometimes
    # emits the constraints section (type 2) before the header (type 1).
    raw: dict[int, bytes] = {}
    for _ in range(nsections):
        sec_type, offset = _u32(data, offset)
        sec_size, offset = _u64(data, offset)
        raw[sec_type] = data[offset : offset + sec_size]
        offset += sec_size

    if 1 not in raw:
        raise ValueError("No header section found in .r1cs file")
    if 2 not in raw:
        raise ValueError("No constraints section found in .r1cs file")

    # Second pass: parse in dependency order (header first, then constraints).
    hdr, _ = _parse_header(raw[1], 0)
    constraints, _ = _parse_constraints(raw[2], 0, hdr["field_size"], hdr["n_constraints"])

    return R1CSFile(
        prime=hdr["prime"],
        n_wires=hdr["n_wires"],
        n_pub_out=hdr["n_pub_out"],
        n_pub_in=hdr["n_pub_in"],
        n_prv_in=hdr["n_prv_in"],
        n_constraints=hdr["n_constraints"],
        constraints=constraints,
    )
