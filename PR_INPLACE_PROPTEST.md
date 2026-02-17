# Add Property Test for Private Storage with Small Values

## Problem

Existing prop tests use `any::<U256>()` which skews toward large values near 2^256. This leaves small value ranges under-tested.

## Solution

Add `prop_private_small_value_proof_verification` that:
- Generates small values (0 to 0xFFFFFF) 
- Tests mixed public/private flags
- Verifies correct flag passes, wrong flag fails

## Note

With B256 keys (64 nibbles), leaves are ~36+ bytes due to path encoding, so in-place encoding does not occur. The unit test `private_inplace_leaf_proof_verification` covers true in-place scenarios using short handcrafted keys.

## Files Changed

- `src/proof/verify.rs`
