include "../node_modules/circomlib/circuits/mux1.circom";
include "./hasherPoseidon.circom";
include "./identityCommitment.circom";
include "./incrementalMerkleTree.circom";
include "./sparseMerkleTree.circom";
include "./processAttestations.circom";

template UpdateNullifierTree(nullifier_tree_depth, NUM_NULLIFIERS) {
    signal input intermediate_nullifier_tree_roots[NUM_NULLIFIERS + 1];
    signal input nullifiers[NUM_NULLIFIERS];
    // Selector is used to determined if the nullifier should be processed
    signal input selectors[NUM_NULLIFIERS];
    signal input path_elements[NUM_NULLIFIERS][nullifier_tree_depth];

    // Leaf of an unseen nullifier has value hashLeftRight(0, 0)
    signal zero_leaf;
    component zero_leaf_hasher = HashLeftRight();
    zero_leaf_hasher.left <== 0;
    zero_leaf_hasher.right <== 0;
    zero_leaf <== zero_leaf_hasher.hash;

    // Leaf of an seen nullifier has value hashLeftRight(1, 0)
    signal one_leaf;
    component one_leaf_hasher = HashLeftRight();
    one_leaf_hasher.left <== 1;
    one_leaf_hasher.right <== 0;
    one_leaf <== one_leaf_hasher.hash;

    // If the nullifier is not to be processed, we check and verify leaf 0 instead.
    // Leaf 0 is reserved and has value hashLeftRight(1, 0)
    component which_leaf_index_to_check[NUM_NULLIFIERS];
    signal leaf_index_to_check[NUM_NULLIFIERS];
    component which_leaf_value_to_check[NUM_NULLIFIERS];
    signal leaf_value_to_check[NUM_NULLIFIERS];
    component non_membership_check[NUM_NULLIFIERS]; 
    component membership_check[NUM_NULLIFIERS]; 

    for (var i = 0; i < NUM_NULLIFIERS; i++) {
        which_leaf_index_to_check[i] = Mux1();
        // Check and verify the nullifier if the selector is true
        // Check and verify leaf 0 otherwise
        which_leaf_index_to_check[i].c[0] <== 0;  // Leaf index 0
        which_leaf_index_to_check[i].c[1] <== nullifiers[i];
        which_leaf_index_to_check[i].s <== selectors[i];
        leaf_index_to_check[i] <== which_leaf_index_to_check[i].out;

        which_leaf_value_to_check[i] = Mux1();
        // Nullifier to be checked should have value hashLeftRight(0, 0)
        // while leaf 0 should have value hashLeftRight(1, 0)
        which_leaf_value_to_check[i].c[0] <== one_leaf;
        which_leaf_value_to_check[i].c[1] <== zero_leaf;
        which_leaf_value_to_check[i].s <== selectors[i];
        leaf_value_to_check[i] <== which_leaf_value_to_check[i].out;

        // Verify merkle proof against pre_processing_tree_root
        non_membership_check[i] = SMTLeafExists(nullifier_tree_depth);
        non_membership_check[i].leaf_index <== leaf_index_to_check[i];
        non_membership_check[i].leaf <== leaf_value_to_check[i];
        for (var j = 0; j < nullifier_tree_depth; j++) {
            non_membership_check[i].path_elements[j] <== path_elements[i][j];
        }
        non_membership_check[i].root <== intermediate_nullifier_tree_roots[i];

        // Verify merkle proof against post_processing_tree_root
        // After the nullifier is marked seen, it's value should be hashLeftRight(1, 0), just like leaf 0
        membership_check[i] = SMTLeafExists(nullifier_tree_depth);
        membership_check[i].leaf_index <== leaf_index_to_check[i];
        membership_check[i].leaf <== one_leaf;
        for (var j = 0; j < nullifier_tree_depth; j++) {
            membership_check[i].path_elements[j] <== path_elements[i][j];
        }
        membership_check[i].root <== intermediate_nullifier_tree_roots[i + 1];
    }
}

template UserStateTransition(GST_tree_depth, epoch_tree_depth, nullifier_tree_depth, user_state_tree_depth, NUM_ATTESTATIONS) {
    signal input epoch;
    signal input max_nonce;  // max epoch key nonce
    signal private input nonce;  // epoch key nonce

    // User state tree
    // First intermediate root is the user state tree root before processing attestations
    // Last intermediate root is the new user state tree root
    signal private input intermediate_user_state_tree_roots[NUM_ATTESTATIONS + 1];
    // Inputs of old atttestation records
    signal private input old_pos_reps[NUM_ATTESTATIONS];
    signal private input old_neg_reps[NUM_ATTESTATIONS];
    signal private input old_graffities[NUM_ATTESTATIONS];
    signal private input UST_path_elements[NUM_ATTESTATIONS][user_state_tree_depth];

    // Global state tree leaf: Identity & user state root
    signal private input identity_pk[2];
    signal private input identity_nullifier;
    signal private input identity_trapdoor;
    // Global state tree
    signal private input GST_path_elements[GST_tree_depth];
    signal private input GST_path_index[GST_tree_depth];
    signal input GST_root;

    // Selector is used to determined if the attestation should be processed
    signal private input selectors[NUM_ATTESTATIONS];
    // Inputs of the atttestations
    signal private input attester_ids[NUM_ATTESTATIONS];
    signal private input pos_reps[NUM_ATTESTATIONS];
    signal private input neg_reps[NUM_ATTESTATIONS];
    signal private input graffities[NUM_ATTESTATIONS];
    signal private input overwrite_graffitis[NUM_ATTESTATIONS];

    // Epoch key & epoch tree
    signal private input epk_path_elements[epoch_tree_depth];
    signal private input hash_chain_result;
    signal input epoch_tree_root;

    // Nullifier tree
    // First intermediate root is the nullifier tree root before processing nullifiers
    // Last intermediate root is the new nullifier tree root
    signal input intermediate_nullifier_tree_roots[NUM_ATTESTATIONS + 1];
    signal private input nullifier_tree_path_elements[NUM_ATTESTATIONS][nullifier_tree_depth];

    signal output new_GST_leaf;
    // signal output completedUserStateTransition;


    /* 1. Check if user exists in the Global State Tree */
    component identity_commitment = IdentityCommitment();
    identity_commitment.identity_pk[0] <== identity_pk[0];
    identity_commitment.identity_pk[1] <== identity_pk[1];
    identity_commitment.identity_nullifier <== identity_nullifier;
    identity_commitment.identity_trapdoor <== identity_trapdoor;

    component leaf = HashLeftRight();
    leaf.left <== identity_commitment.out;
    leaf.right <== intermediate_user_state_tree_roots[0];

    component GST_leaf_exists = LeafExists(GST_tree_depth);
    GST_leaf_exists.leaf <== leaf.hash;
    for (var i = 0; i < GST_tree_depth; i++) {
        GST_leaf_exists.path_index[i] <== GST_path_index[i];
        GST_leaf_exists.path_elements[i] <== GST_path_elements[i];
    }
    GST_leaf_exists.root <== GST_root;
    /* End of check 1*/


    /* 2. Process the attestations of the epoch key specified by`nonce` and update nullifier tree */
    component epochKeyHasher = Hasher5();
    epochKeyHasher.in[0] <== identity_nullifier;
    epochKeyHasher.in[1] <== epoch;
    epochKeyHasher.in[2] <== nonce;
    epochKeyHasher.in[3] <== 0;
    epochKeyHasher.in[4] <== 0;

    signal quotient;
    signal epkModed;
    // circom's best practices state that we should avoid using <-- unless
    // we know what we are doing. But this is the only way to perform the
    // modulo operation.
    quotient <-- epochKeyHasher.hash \ (2 ** epoch_tree_depth);
    epkModed <-- epochKeyHasher.hash % (2 ** epoch_tree_depth);
    // Range check on moded epoch key
    component epk_lt = LessEqThan(epoch_tree_depth);
    epk_lt.in[0] <== epkModed;
    epk_lt.in[1] <== 2 ** epoch_tree_depth - 1;
    epk_lt.out === 1;
    // Range check on quotient
    component quot_lt = LessEqThan(254 - epoch_tree_depth);
    quot_lt.in[0] <== quotient;
    quot_lt.in[1] <== 2 ** (254 - epoch_tree_depth) - 1;
    quot_lt.out === 1;
    // Check equality
    epochKeyHasher.hash === quotient * (2 ** epoch_tree_depth) + epkModed;

    // 2.1 Check if hash chain of the epoch key exists in epoch tree
    component epk_exists = SMTLeafExists(epoch_tree_depth);
    epk_exists.leaf_index <== epkModed;
    epk_exists.leaf <== hash_chain_result;
    epk_exists.root <== epoch_tree_root;
    for (var i = 0; i < epoch_tree_depth; i++) {
        epk_exists.path_elements[i] <== epk_path_elements[i];
    }

    // 2.2 Begin processing attestations
    component process_attestations = ProcessAttestations(nullifier_tree_depth, user_state_tree_depth, NUM_ATTESTATIONS);
    process_attestations.epoch <== epoch;
    process_attestations.identity_nullifier <== identity_nullifier;
    process_attestations.hash_chain_result <== hash_chain_result;
    process_attestations.intermediate_user_state_tree_roots[0] <== intermediate_user_state_tree_roots[0];
    for (var i = 0; i < NUM_ATTESTATIONS; i++) {
        process_attestations.intermediate_user_state_tree_roots[i + 1] <== intermediate_user_state_tree_roots[i + 1];
        process_attestations.old_pos_reps[i] <== old_pos_reps[i];
        process_attestations.old_neg_reps[i] <== old_neg_reps[i];
        process_attestations.old_graffities[i] <== old_graffities[i];
        for (var j = 0; j < user_state_tree_depth; j++) {
            process_attestations.path_elements[i][j] <== UST_path_elements[i][j];
        }
        process_attestations.attester_ids[i] <== attester_ids[i];
        process_attestations.pos_reps[i] <== pos_reps[i];
        process_attestations.neg_reps[i] <== neg_reps[i];
        process_attestations.graffities[i] <== graffities[i];
        process_attestations.overwrite_graffitis[i] <== overwrite_graffitis[i];
        process_attestations.selectors[i] <== selectors[i];
    }

    // 2.3 Update nullifier tree
    component update_nullifier_tree = UpdateNullifierTree(nullifier_tree_depth, NUM_ATTESTATIONS);
    update_nullifier_tree.intermediate_nullifier_tree_roots[0] <== intermediate_nullifier_tree_roots[0];
    for (var i = 0; i < NUM_ATTESTATIONS; i++) {
        update_nullifier_tree.nullifiers[i] <== process_attestations.nullifiers[i];
        update_nullifier_tree.selectors[i] <== selectors[i];
        update_nullifier_tree.intermediate_nullifier_tree_roots[i + 1] <== intermediate_nullifier_tree_roots[i + 1];
        for (var j = 0; j < nullifier_tree_depth; j++) {
            update_nullifier_tree.path_elements[i][j] <== nullifier_tree_path_elements[i][j];
        }
    }
    /* End of 2. process the attestations of the epoch key specified by`nonce` and update nullifier tree */


    /* 3. Compute new GST leaf */
    component new_leaf = HashLeftRight();
    new_leaf.left <== identity_commitment.out;
    // Last intermediate root is the new user state tree root
    new_leaf.right <== intermediate_user_state_tree_roots[NUM_ATTESTATIONS];

    new_GST_leaf <== new_leaf.hash;
    /* End of 3. compute new GST leaf matches */
}