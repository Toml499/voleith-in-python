pragma circom 2.0.0;

include "../circomlib/circuits/poseidon.circom";  // or use MiMC, etc.

template MerkleProof(levels) {
    signal input secret;
    signal input pathElements[levels];
    signal input pathIndices[levels];   // 0 or 1 at each level
    signal output root;

    // Hash the secret to get the leaf
    component leafHash = Poseidon(1);
    leafHash.inputs[0] <== secret;

    component hashers[levels];
    component muxes[levels];
    
    signal hashes[levels + 1];
    hashes[0] <== leafHash.out;

    for (var i = 0; i < levels; i++) {
        // pathIndices[i] must be 0 or 1
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Conditional swap: pick left/right based on pathIndices
        // left  = (1 - bit) * current + bit * sibling
        // right = bit * current + (1 - bit) * sibling
        
        hashers[i] = Poseidon(2);
        
        // If pathIndices[i] == 0: I'm the left child
        // If pathIndices[i] == 1: I'm the right child
        hashers[i].inputs[0] <== hashes[i] + 
            pathIndices[i] * (pathElements[i] - hashes[i]);
        hashers[i].inputs[1] <== pathElements[i] + 
            pathIndices[i] * (hashes[i] - pathElements[i]);
        
        hashes[i + 1] <== hashers[i].out;
    }

    root <== hashes[levels];
}

component main {public [pathElements, pathIndices]} = MerkleProof(4);  // supports 2^20 members