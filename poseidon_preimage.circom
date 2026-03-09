pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// Proves knowledge of a secret preimage such that Poseidon(preimage) == hash.
//
// Public:  hash  — the committed digest
// Private: preimage — the value whose hash equals `hash`
//
// Test with:
//   compile_and_witness("poseidon_preimage.circom", {"preimage": "42"})
// The witness generator fills in `hash` automatically; read it back from
// wire index 1 of the returned witness vector (wire 0 is always 1).

template PoseidonPreimage() {
    signal input  preimage;  // private
    signal output hash;      // public

    component h = Poseidon(1);
    h.inputs[0] <== preimage;
    hash <== h.out;
}

component main = PoseidonPreimage();
