use std::collections::HashMap;

use eth_trie_utils::nibbles::Nibbles;
use ethereum_types::{Address, H256, U256};

use crate::edge_payloads::TxnDelta;

pub type BlockHeight = u64;
pub type TxnIdx = usize;

pub type TxnTraces = HashMap<Address, Option<TxnDelta>>;
pub type ContractCode = HashMap<H256, Vec<u8>>;

pub type StorageAddr = Nibbles;
pub type StorageVal = U256;
pub type HashedAccountAddr = H256;
