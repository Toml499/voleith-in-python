# VOLEitH Project — State, FAEST Comparison & Roadmap

## Current State

The project implements VOLE-in-the-Head (VOLEitH) as a non-interactive zero-knowledge proof
system in Python, covering two relation types:

### What is implemented

**Linear relation prover/verifier** (`demo.py`)
- Proves knowledge of x such that A @ x = b over a prime field GF(p)
- VOLE correlation: m = x·Δ + k (one authenticated value per witness element)
- Linear check: A @ m = b·Δ + c, where c = A @ k is the correction term
- Fiat-Shamir: Δ derived from Hash(statement || commitment)

**R1CS prover/verifier using Quicksilver** (`demo_r1cs.py`)
- Proves knowledge of a full wire assignment satisfying an R1CS constraint system
- Per-constraint Quicksilver check: MA_i · MB_i − MC_i · Δ = t_i · Δ + v_i
- Batched over all constraints with a second Fiat-Shamir challenge χ:
  Σ χ^i · (MA_i · MB_i − MC_i · Δ) = T · Δ + V
- Can parse real `.r1cs` files produced by circom

**Supporting infrastructure**
- PRG-based VOLE generation (seed → mask vector k via SHA-3)
- Hash-based seed commitment (hides seed before Δ is revealed)
- R1CS parser for binary `.r1cs` format (circom-compatible)

### Known limitations / simplifications

- **Soundness is not production-grade.** There is no GGM tree commitment. A cheating prover
  can pick arbitrary m and set the correction to match, trivially satisfying the linear check.
  (Noted explicitly in `prover.py`.)
- **m is sent in the clear.** In a complete protocol, m would itself be committed to (e.g.
  via a vector commitment) and opened selectively.
- **Field: prime fields only.** Everything runs over GF(p) for small primes. FAEST-style
  binary extension fields (GF(2^k)) are not supported.
- **VOLE generation: PRG-based only.** No OT-based or SoftSpokenVOLE protocol.


---

## Relation to the FAEST ZKP Step

FAEST is a post-quantum signature scheme whose ZKP core proves knowledge of an AES key k
such that AES_k(m) = c for public (m, c). It uses VOLEitH with Quicksilver.
Ignoring the signature wrapper, the ZKP step is directly comparable to this project.

### Similarities

| Component | This project | FAEST ZKP |
|---|---|---|
| Core VOLE correlation | m = w·Δ + k | m = w·Δ + k (identical) |
| Linear gate check | A @ m = b·Δ + c | Used for XOR, ShiftRows, MixColumns, AddRoundKey in AES |
| Quicksilver mult check | MA·MB − MC·Δ = T·Δ + V | Used for S-box (GF(2^8) inversion) — identical identity |
| Batching | Random χ via Fiat-Shamir over all constraints | Same batching strategy |
| Non-interactive transform | Fiat-Shamir on (statement ‖ commitment) | Same |

The R1CS demo (`demo_r1cs.py`) and FAEST's Quicksilver step are algebraically identical.
Each AES S-box produces one multiplication constraint a·b = 1 in GF(2^8), checked with the
same MA·MB − MC·Δ = t·Δ + v identity this project implements.

### Differences

| Aspect | This project | FAEST ZKP |
|---|---|---|
| **Field** | Prime fields GF(p) | GF(2) and GF(2^8) — binary, matches AES natively |
| **VOLE generation** | PRG-based (one seed → k via hash) | SoftSpokenVOLE: OT-based, uses quasi-cyclic codes, designed for GF(2^k); much more efficient |
| **Soundness** | Simplified — no GGM tree, unsound against adaptive prover | Full GGM tree with N virtual parties; soundness error 1/N |
| **Commitment to m** | m sent in clear | m committed via vector commitment; only N-1 of N views opened |
| **Circuit** | General R1CS (any circom circuit) | AES-specific: fixed topology of linear + S-box gates |
| **Proof size** | Linear in number of wires (m is full wire vector) | Compact: GGM opening + Quicksilver scalars only |


---

## Roadmap

The goal is to (1) close the gap with FAEST's architecture and (2) build an anonymous group
membership proof using Merkle trees and Poseidon hash on top of VOLEitH.

The two tracks are partly independent: the group membership application can be prototyped
with the current prime-field R1CS infrastructure (using circom + existing prover), while
the FAEST-style improvements harden the underlying proof system.

---

### Track A — Harden toward FAEST architecture

#### A1. Proper GGM tree commitment (soundness fix)
- Implement a binary GGM (Goldreich-Goldwasser-Micali) tree of depth log2(N)
- Each leaf is a party seed; internal nodes derived by PRG
- Prover commits to the root before seeing Δ
- After seeing Δ, prover opens N-1 leaves (all except the "real" one)
- Verifier reconstructs the N-1 views and checks consistency
- Soundness error drops to 1/N

#### A2. Binary extension field arithmetic GF(2^k)
- Implement GF(2^8) with the AES reduction polynomial x^8 + x^4 + x^3 + x + 1
- Implement GF(2^128) or GF(2^192) for the VOLE key Δ (FAEST uses 128-bit security)
- This is a prerequisite for SoftSpokenVOLE and for an AES circuit demo

#### A3. SoftSpokenVOLE (or a simplified OT-based VOLE)
- Replace the PRG-based VOLE generator with a proper subfield VOLE protocol
- SoftSpokenVOLE works over GF(2^k): uses random OT extensions + quasi-cyclic codes
- Intermediate step: implement a basic OT-based VOLE over GF(2^8) before the full protocol
- This is the main efficiency gap between this project and FAEST

#### A4. Vector commitment for m
- Replace sending m in clear with a Merkle-based or hash-based vector commitment
- Proof reveals only the challenge-selected views, not the full wire vector
- Reduces proof size from O(n_wires) to O(log n_wires · security_param)

---

### Track B — Anonymous group membership proof

The goal: prove "I know a secret identity that is a leaf in a public Merkle tree"
without revealing which leaf. The Merkle tree holds the public keys / identifiers of
all group members. The root is the public group identifier.

#### B1. Poseidon hash over a prime field
- Implement Poseidon permutation (the standard ZK-friendly hash) over GF(p) in Python
- Poseidon is preferred over SHA-2/SHA-3 here because it has far fewer R1CS constraints
  (multiplicative depth is much lower)
- Reference: Poseidon paper (Grassi et al.) and the circomlib implementation
- Parameters: use the BN254 scalar field (p = 21888...0001, the Groth16 / snarkjs standard)
  so that circom circuit compilation is straightforward

#### B2. Poseidon Merkle tree
- Build a binary Merkle tree where each internal node = Poseidon(left_child, right_child)
- Leaves are member identifiers (e.g. public keys or nullifiers)
- Expose: compute_root(leaves), get_path(leaf_index) → (sibling hashes, directions)

#### B3. Membership circuit in circom
- Write a circom template `MerkleProof(depth)` that:
  - Takes as private input: leaf value, sibling hashes along path, path directions (bits)
  - Takes as public input: Merkle root
  - Computes the root by hashing up the path with Poseidon
  - Asserts computed root == public root
- Compile with circom to get a `.r1cs` file
- Generate a witness with snarkjs or the circom WASM witness generator
- This circom circuit already exists in circomlib (`MerkleTreeChecker`)

#### B4. Prove membership with the existing R1CS prover
- Load the compiled `.r1cs` from B3 using `parse_r1cs`
- Construct `R1CSRelation.from_r1cs_file(...)`
- Run `R1CSProver.prove(witness)` and `R1CSVerifier.verify(proof)`
- At this point the full anonymous membership proof works end-to-end
- The prover knows the secret leaf and path; the verifier only sees the root

#### B5. (Optional) Replace the circom circuit with a native Python circuit
- Implement Poseidon and Merkle path hashing directly as R1CS constraints in Python
- Avoids the circom toolchain dependency
- Useful for experimentation and understanding constraint counts

---

### Suggested order of work

1. **B1 + B2** — Poseidon and Merkle tree in Python (self-contained, no toolchain needed)
2. **B3 + B4** — Circom circuit + end-to-end membership proof (achieves the main goal)
3. **A1** — GGM tree (fixes the soundness gap, most impactful correctness improvement)
4. **A2** — Binary field arithmetic (foundation for SoftSpokenVOLE)
5. **A3** — SoftSpokenVOLE (closes the main efficiency gap with FAEST)
6. **A4** — Vector commitment for m (closes the proof size gap)
7. **B5** — Native Python Merkle circuit (optional cleanup / research tool)
