use crate::{HashBuilder, EMPTY_ROOT_HASH};
use alloc::vec::Vec;
use alloy_primitives::{B256, U256};
use alloy_rlp::Encodable;
use nybbles::Nibbles;

/// Adjust the index of an item for rlp encoding.
pub const fn adjust_index_for_rlp(i: usize, len: usize) -> usize {
    if i > 0x7f {
        i
    } else if i == 0x7f || i + 1 == len {
        0
    } else {
        i + 1
    }
}

/// Compute a trie root of the collection of rlp encodable items.
/// This function does not support private nodes.
/// and is used for things like receipt roots rather than state roots.
pub fn ordered_trie_root<T: Encodable>(items: &[T]) -> B256 {
    ordered_trie_root_with_encoder(items, |item, buf| item.encode(buf))
}

/// Compute a trie root of the collection of items with a custom encoder.
/// This function does not support private nodes.
/// and is used for things like receipt roots rather than state roots.
pub fn ordered_trie_root_with_encoder<T, F>(items: &[T], mut encode: F) -> B256
where
    F: FnMut(&T, &mut Vec<u8>),
{
    if items.is_empty() {
        return EMPTY_ROOT_HASH;
    }

    let mut value_buffer = Vec::new();

    let mut hb = HashBuilder::default();
    let items_len = items.len();
    for i in 0..items_len {
        let index = adjust_index_for_rlp(i, items_len);

        let index_buffer = alloy_rlp::encode_fixed_size(&index);

        value_buffer.clear();
        encode(&items[index], &mut value_buffer);

        let is_private = false; // TODO: fix
        hb.add_leaf(Nibbles::unpack(&index_buffer), &value_buffer, is_private);
    }

    hb.root()
}

trait StorageValue {
    fn is_private(&self) -> bool {
        false
    }
    fn value(&self) -> &U256;
}

impl StorageValue for U256 {
    fn value(&self) -> &Self {
        self
    }
}
impl StorageValue for (U256, bool) {
    fn is_private(&self) -> bool {
        self.1
    }
    fn value(&self) -> &U256 {
        &self.0
    }
}

/// Ethereum specific trie root functions.
#[cfg(feature = "ethereum")]
pub use ethereum::*;
#[cfg(feature = "ethereum")]
mod ethereum {
    use super::*;
    use crate::TrieAccount;
    use alloy_primitives::{keccak256, Address, U256};

    /// Hashes storage keys, sorts them and them calculates the root hash of the storage trie.
    /// See [`storage_root_unsorted`] for more info.
    pub fn storage_root_unhashed<T: StorageValue>(storage: impl IntoIterator<Item = (B256, T)>) -> B256 {
        storage_root_unsorted(
            storage
                .into_iter()
                .map(|(slot, value)| (keccak256(slot), value)),
        )
    }

    /// Sorts and calculates the root hash of account storage trie.
    /// See [`storage_root`] for more info.
    pub fn storage_root_unsorted<T: StorageValue>(storage: impl IntoIterator<Item = (B256, T)>) -> B256 {
        // transform the storage keys
        let mut v = Vec::from_iter(storage);
        v.sort_unstable_by_key(|(key, _)| *key);
        storage_root(v)
    }

    /// Calculates the root hash of account storage trie.
    ///
    /// # Panics
    ///
    /// If the items are not in sorted order.
    pub fn storage_root<T: StorageValue>(storage: impl IntoIterator<Item = (B256, T)>) -> B256 {
        let mut hb = HashBuilder::default();
        for (hashed_slot, value) in storage {
            hb.add_leaf(
                Nibbles::unpack(hashed_slot),
                alloy_rlp::encode_fixed_size(value.value()).as_ref(),
                value.is_private(),
            );
        }
        hb.root()
    }

    /// Hashes and sorts account keys, then proceeds to calculating the root hash of the state
    /// represented as MPT.
    /// See [`state_root_unsorted`] for more info.
    pub fn state_root_ref_unhashed<'a, A: Into<TrieAccount> + Clone + 'a>(
        state: impl IntoIterator<Item = (&'a Address, &'a A)>,
    ) -> B256 {
        state_root_unsorted(
            state.into_iter().map(|(address, account)| (keccak256(address), account.clone())),
        )
    }

    /// Hashes and sorts account keys, then proceeds to calculating the root hash of the state
    /// represented as MPT.
    /// See [`state_root_unsorted`] for more info.
    pub fn state_root_unhashed<A: Into<TrieAccount>>(
        state: impl IntoIterator<Item = (Address, A)>,
    ) -> B256 {
        state_root_unsorted(
            state.into_iter().map(|(address, account)| (keccak256(address), account)),
        )
    }

    /// Sorts the hashed account keys and calculates the root hash of the state represented as MPT.
    /// See [`state_root`] for more info.
    pub fn state_root_unsorted<A: Into<TrieAccount>>(
        state: impl IntoIterator<Item = (B256, A)>,
    ) -> B256 {
        let mut vec = Vec::from_iter(state);
        vec.sort_unstable_by_key(|(key, _)| *key);
        state_root(vec)
    }

    /// Calculates the root hash of the state represented as MPT.
    ///
    /// Corresponds to [geth's `deriveHash`](https://github.com/ethereum/go-ethereum/blob/6c149fd4ad063f7c24d726a73bc0546badd1bc73/core/genesis.go#L119).
    ///
    /// # Panics
    ///
    /// If the items are not in sorted order.
    pub fn state_root<A: Into<TrieAccount>>(state: impl IntoIterator<Item = (B256, A)>) -> B256 {
        let mut hb = HashBuilder::default();
        let mut account_rlp_buf = Vec::new();
        let is_private = false; // account nodes are always public
        for (hashed_key, account) in state {
            account_rlp_buf.clear();
            account.into().encode(&mut account_rlp_buf);
            hb.add_leaf(Nibbles::unpack(hashed_key), &account_rlp_buf, is_private);
        }
        hb.root()
    }
}
