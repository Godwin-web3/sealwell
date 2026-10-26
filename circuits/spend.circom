pragma circom 2.1.0;
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/bitify.circom";

// Sealwell shielded pool: prove ownership of an unspent note in the deposit tree.
// commitment = Poseidon(nullifier, secret); nullifierHash = Poseidon(nullifier).
// extHash binds the proof to the action (bid ciphertext, batch, payout, relayer, fee).
template Spend(levels) {
    signal input root;
    signal input nullifierHash;
    signal input extHash;
    signal input nullifier;
    signal input secret;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component nh = Poseidon(1);
    nh.inputs[0] <== nullifier;
    nh.out === nullifierHash;

    component cm = Poseidon(2);
    cm.inputs[0] <== nullifier;
    cm.inputs[1] <== secret;

    component h[levels];
    signal cur[levels + 1];
    signal l[levels]; signal r[levels];
    cur[0] <== cm.out;
    for (var i = 0; i < levels; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        l[i] <== cur[i] + pathIndices[i] * (pathElements[i] - cur[i]);
        r[i] <== pathElements[i] + pathIndices[i] * (cur[i] - pathElements[i]);
        h[i] = Poseidon(2);
        h[i].inputs[0] <== l[i];
        h[i].inputs[1] <== r[i];
        cur[i + 1] <== h[i].out;
    }
    root === cur[levels];

    // Bind extHash into the constraint system (prevents malleating it).
    signal extSq;
    extSq <== extHash * extHash;
}

component main {public [root, nullifierHash, extHash]} = Spend(16);
