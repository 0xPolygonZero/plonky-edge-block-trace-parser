use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    str::FromStr,
};

use eth_trie_utils::{
    nibbles::{Nibble, Nibbles},
    partial_trie::HashedPartialTrie,
    trie_subsets::create_trie_subset,
};
use eth_trie_utils::{partial_trie::PartialTrie, trie_ops::ValOrHash};
use ethereum_types::{Address, H256, U256};
use keccak_hash::keccak;
use log::debug;
use plonky2_evm::{
    generation::{mpt::AccountRlp, TrieInputs},
    proof::{BlockMetadata, TrieRoots},
};
use plonky_block_proof_gen::proof_types::{ProofBeforeAndAfterDeltas, TxnProofGenIR};
use rlp::{decode, encode, Rlp};
use thiserror::Error;

use crate::{
    edge_payloads::{EdgeBlockResponse, EdgeBlockTrace},
    types::{BlockHeight, HashedAccountAddr, StorageAddr, StorageVal, TxnTraces},
};

const MATIC_CHAIN_ID: usize = 2001;

pub type TraceParsingResult<T> = Result<T, TraceParsingError>;

// EMPTY_CODE_HASH = keccak([]) -->
// 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
const EMPTY_TRIE_HASH: H256 = H256([
    86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153,
    108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33,
]);

const EMPTY_CODE_HASH: H256 = H256([
    197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202,
    130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
]);

// , acc_addr, mem_addrs_accessed_formatted
#[derive(Debug, Error)]
pub enum TraceParsingError {
    #[error("Failed to decode RLP bytes ({0}) as an Ethereum account due to the error: {1}")]
    AccountDecode(String, String),

    #[error("Missing account storage trie in base trie when constructing subset partial trie for txn (account: {0})")]
    MissingAccountStorageTrie(HashedAccountAddr),

    // TODO: Make this error nicer...
    #[error(
        "Non-existent account addr given when creating a sub partial trie from the base state trie"
    )]
    NonExistentAcctAddrsCreatingSubPartialTrie,

    #[error("Creating a subset partial trie for account storage for account {0}, mem addrs accessed: {1:?}")]
    NonExistentStorageAddrsCreatingStorageSubPartialTrie(HashedAccountAddr, Vec<String>, String),
}

#[derive(Debug)]
pub enum TrieType {
    State,
    Storage,
}

impl Display for TrieType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TrieType::State => "State",
            TrieType::Storage => "Storage",
        };

        write!(f, "{}", s)
    }
}

struct ProcessedTracesForTxn {
    contract_code: HashMap<H256, Vec<u8>>,
    nodes_used_by_txn: NodesUsedByTxn,
    deltas: Vec<ProcessedTxnTrace>,
}

struct ProcessedTxnTrace {
    _address: Address,
    hashed_addr: H256,
    balance: Option<U256>,
    nonce: Option<U256>,
    code: Option<Vec<u8>>,
    storage: Option<HashMap<StorageAddr, StorageVal>>,
}

impl From<EdgeBlockResponse> for BlockMetadata {
    fn from(v: EdgeBlockResponse) -> Self {
        let mut block_bloom = [U256::zero(); 8];

        // Note that bloom can be empty.
        for (i, v) in v.header.logs_bloom.iter().enumerate() {
            block_bloom[i] = *v;
        }

        Self {
            block_beneficiary: v.header.miner,
            block_timestamp: v.header.timestamp.into(),
            block_number: v.header.number.into(),
            block_difficulty: v.header.difficulty.into(),
            block_gaslimit: v.header.gas_limit.into(),
            block_chain_id: MATIC_CHAIN_ID.into(),
            block_base_fee: v.header.base_fee.into(),
            block_gas_used: v.header.gas_used.into(),
            block_bloom,
        }
    }
}

fn process_txn_deltas(
    txns_info: TxnTraces,
    addrs_to_code: &mut HashMap<H256, Vec<u8>>,
) -> TraceParsingResult<ProcessedTracesForTxn> {
    let mut state = HashSet::new();
    let mut storage = HashMap::new();
    let mut deltas = Vec::new();
    let mut c_hash_to_code_used_by_deltas = HashMap::new();

    for (acc_addr, trace_info) in txns_info {
        // Bug in Edge...
        if acc_addr.is_zero() {
            continue;
        }

        let hashed_acc_addr = hash(acc_addr.as_bytes());
        state.insert(hashed_acc_addr);

        if let Some(t_info) = trace_info {
            match &t_info.code {
                Some(code) => {
                    // Code was initialized during txn, so use whatever the code was set to here.
                    let c_hash = hash(code);
                    addrs_to_code.insert(hashed_acc_addr, code.clone());
                    c_hash_to_code_used_by_deltas.insert(c_hash, code.clone());
                }
                None => {
                    // Code was not initialized, so we need to get the code from the block code
                    // table.

                    // Addresses in the deltas may not exist in the initial trie, so we may need to
                    // add them here.
                    let code = addrs_to_code
                        .entry(hashed_acc_addr)
                        .or_insert_with(|| EMPTY_CODE_HASH.as_bytes().to_vec());
                    c_hash_to_code_used_by_deltas.insert(hash(code), code.clone());
                }
            }

            let nib_2 = Nibbles::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap();

            let s_writes: Option<HashMap<_, _>> = t_info.storage.map(|s_writes| {
                s_writes
                    .into_iter()
                    .map(|(s, v)| (string_to_nibbles_even_nibble_fixed(&s), v))
                    .filter(|(n, _)| *n != nib_2)
                    .collect()
            });

            // TODO: Remove parsing this initially as `String`s...
            let s_write_keys = s_writes.iter().flat_map(|h_map| h_map.keys().cloned());

            let s_read_keys = t_info
                .storage_read
                .iter()
                .flat_map(|v| v.iter().map(|s| string_to_nibbles_even_nibble_fixed(s)))
                .filter(|n| *n != nib_2);

            let storage_accesses: HashSet<_> = s_read_keys.chain(s_write_keys).collect();

            if !storage_accesses.is_empty() {
                let existing_val = storage.insert(hashed_acc_addr, storage_accesses);
                debug_assert!(existing_val.is_none());
            }

            let delta = ProcessedTxnTrace {
                _address: acc_addr,
                hashed_addr: hashed_acc_addr,
                balance: t_info.balance,
                nonce: t_info.nonce,
                code: t_info.code,
                storage: s_writes,
            };

            deltas.push(delta);
        };
    }

    let nodes_used_by_txn = NodesUsedByTxn {
        state: Vec::from_iter(state),
        storage,
    };

    Ok(ProcessedTracesForTxn {
        contract_code: c_hash_to_code_used_by_deltas,
        nodes_used_by_txn,
        deltas,
    })
}

impl EdgeBlockTrace {
    pub fn into_txn_proof_gen_payloads(
        mut self,
        b_height: BlockHeight,
    ) -> TraceParsingResult<Vec<TxnProofGenIR>> {
        let contract_code_accessed = self.extract_all_contract_bytecode_from_txn_traces();

        let mut c_hash_to_code = HashMap::from_iter(
            contract_code_accessed
                .iter()
                .map(|(c_hash, c)| (*c_hash, c.clone())),
        );
        c_hash_to_code.insert(EMPTY_CODE_HASH, vec![]);

        // Continuously update these tries as we process txns deltas.
        let (mut block_tries, mut addrs_to_code) =
            self.construct_initial_tries_and_account_to_code_map(&c_hash_to_code)?;

        let mut gas_used_before = 0;
        let mut block_bloom_before = [U256::zero(); 8];

        let mut tx_proof_gen_ir = self
            .txn_bytes_and_traces
            .into_iter()
            .enumerate()
            .map(move |(txn_idx, txn_trace_info)| {
                debug!("Processing txn {}...", txn_idx);

                let processed_txn_traces =
                    process_txn_deltas(txn_trace_info.traces, &mut addrs_to_code)?;

                let txn_partial_tries = Self::create_minimal_partial_tries_needed_by_txn(
                    &block_tries,
                    processed_txn_traces.nodes_used_by_txn,
                    txn_idx,
                )?;

                println!("Base storage tries:");
                for (acc_addr, trie) in block_tries.storage.iter() {
                    let s_addrs: Vec<_> = trie
                        .items()
                        .map(|(k, v_or_h)| {
                            let v_or_h_char = match v_or_h {
                                ValOrHash::Val(_) => 'L',
                                ValOrHash::Hash(_) => 'H',
                            };
                            format!("{} - {:x}", v_or_h_char, k)
                        })
                        .collect();
                    println!("Storage trie for {:x}: {:?}", acc_addr, s_addrs);
                }

                for (a_addr, s_trie) in txn_partial_tries.storage_tries.iter() {
                    let base_s_root = block_tries
                        .state
                        .get(Nibbles::from_h256_be(*a_addr))
                        .map(|bytes| decode::<AccountRlp>(bytes).unwrap())
                        .unwrap()
                        .storage_root;

                    assert_eq!(s_trie.hash(), base_s_root);
                }

                // Now apply the delta to the trie before we move onto the next proof gen.
                Self::apply_deltas_to_trie_state(
                    &mut block_tries,
                    processed_txn_traces.deltas,
                    &mut addrs_to_code,
                )?;

                Self::update_receipt_and_txn_tries(
                    &mut block_tries.receipt,
                    &mut block_tries.txn,
                    txn_trace_info.txn.clone(),
                    txn_trace_info.receipt,
                    txn_idx,
                );
                assert_eq!(block_tries.receipt.hash(), txn_trace_info.receipt_root);
                assert_eq!(block_tries.txn.hash(), txn_trace_info.txn_root);

                let trie_roots_after = TrieRoots {
                    state_root: block_tries.state.hash(),
                    transactions_root: txn_trace_info.txn_root,
                    receipts_root: txn_trace_info.receipt_root,
                };

                let gas_used_after = gas_used_before + txn_trace_info.gas_used;

                let deltas = ProofBeforeAndAfterDeltas {
                    gas_used_before: gas_used_before.into(),
                    gas_used_after: gas_used_after.into(),
                    block_bloom_before,
                    block_bloom_after: txn_trace_info.bloom,
                };

                gas_used_before = gas_used_after;
                block_bloom_before = txn_trace_info.bloom;

                let payload = TxnProofGenIR {
                    signed_txn: txn_trace_info.txn,
                    tries: txn_partial_tries,
                    trie_roots_after,
                    deltas,
                    contract_code: processed_txn_traces.contract_code,
                    b_height,
                    txn_idx,
                };

                Ok(payload)
            })
            .collect::<TraceParsingResult<Vec<_>>>()?;

        Ok(match tx_proof_gen_ir.len() {
            0 => vec![
                TxnProofGenIR::create_dummy(b_height, 0),
                TxnProofGenIR::create_dummy(b_height, 1),
            ],
            1 => {
                tx_proof_gen_ir.push(tx_proof_gen_ir[0].dummy_with_at(b_height, 1));
                tx_proof_gen_ir
            }
            _ => tx_proof_gen_ir,
        })
    }

    /// Edge gives us contract bytecode that was accessed
    fn extract_all_contract_bytecode_from_txn_traces(&self) -> HashMap<H256, Vec<u8>> {
        // TODO: Clean up and move to a map...
        let mut h_addr_to_contract_bytes = HashMap::new();

        for e in self.txn_bytes_and_traces.iter() {
            for (_addr, info) in e.traces.iter() {
                if let Some(info) = info {
                    if let Some(code_read) = info.code_read.as_ref().or(info.code.as_ref()) {
                        let h_addr = hash(code_read);
                        h_addr_to_contract_bytes.insert(h_addr, code_read.clone());
                    }
                }
            }
        }

        h_addr_to_contract_bytes
    }

    fn rlp_edge_trie_nodes(edge_nodes: &HashMap<H256, Vec<u8>>) -> HashMap<Nibbles, Rlp> {
        edge_nodes
            .iter()
            .map(|(a, v)| (Nibbles::from_h256_be(*a), Rlp::new(v)))
            .collect()
    }

    fn construct_initial_tries_and_account_to_code_map(
        &mut self,
        code_hash_to_code: &HashMap<H256, Vec<u8>>,
    ) -> TraceParsingResult<(BlockPartialTries, HashMap<H256, Vec<u8>>)> {
        let mut accounts_to_code = HashMap::new();

        let rlped_state_nodes: HashMap<_, _> = Self::rlp_edge_trie_nodes(&self.account_trie);
        let state_trie =
            Self::decode_edge_rlp_state_trie_nodes(&rlped_state_nodes, self.parent_state_root);

        let hashed_acct_to_storage_roots: Vec<_> = state_trie
            .items()
            .filter_map(|(k, v_or_h)| {
                v_or_h
                    .as_val()
                    .map(|v| (k, decode::<AccountRlp>(v).unwrap().storage_root))
            })
            .collect();

        let rlped_storage_nodes = Self::rlp_edge_trie_nodes(&self.storage_trie);

        let acc_storage_tries: HashMap<H256, HashedPartialTrie> = hashed_acct_to_storage_roots
            .into_iter()
            .map(|(addr, s_root)| {
                let s_tree: HashedPartialTrie =
                    Self::decode_edge_rlp_state_trie_nodes(&rlped_storage_nodes, s_root);
                assert_eq!(s_tree.hash(), s_root);

                (H256::from_slice(&addr.bytes_be()), s_tree)
            })
            .collect();

        // If we are given an empty state trie, the actual root is going to be the
        // previous parent root, but we have no info to calculate this, so skip the
        // check.
        if !rlped_state_nodes.is_empty() {
            assert_eq!(state_trie.hash(), self.parent_state_root);
        }

        for (acc_nibs, acc_info) in state_trie.items().filter_map(|(k, v_or_h)| {
            v_or_h
                .as_val()
                .map(|v| (k, decode::<AccountRlp>(v).unwrap()))
        }) {
            let code = code_hash_to_code
                .get(&acc_info.code_hash)
                .unwrap_or_else(|| {
                    panic!(
                        "No code provided for corresponding code hash {}!",
                        acc_info.code_hash
                    )
                })
                .clone();

            // Worry about efficiency later...
            accounts_to_code.insert(H256::from_slice(&acc_nibs.bytes_be()), code);
        }

        Ok((
            BlockPartialTries {
                state: state_trie,
                storage: acc_storage_tries,
                receipt: HashedPartialTrie::default(),
                txn: HashedPartialTrie::default(),
            },
            accounts_to_code,
        ))
    }

    fn decode_edge_rlp_state_trie_nodes_rec(
        curr_node: &Rlp,
        curr_k: Nibbles,
        trie: &mut HashedPartialTrie,
        rlped_nodes: &HashMap<Nibbles, Rlp>,
    ) {
        let num_items = curr_node.item_count().unwrap();
        let mut rlp_iter = curr_node.iter();

        match num_items {
            2 => {
                // Can be either an extension node or a leaf node.
                let field_1_bytes = rlp_iter.next().unwrap().data().unwrap();
                let field_1_compact = Nibbles::from_hex_prefix_encoding(field_1_bytes).unwrap();

                let field_2_rlp = rlp_iter.next().unwrap();

                let has_terminator = Self::has_terminator(field_1_compact);

                // It's possible that edge can produce an extension node with zero bytes in the extension... Not sure why this wouldn't just be a leaf, but this will cause an error in `eth_trie_utils`.
                let curr_k = match field_1_compact.is_empty() {
                    false => {
                        let post_k = match has_terminator {
                            false => field_1_compact,
                            true => field_1_compact.truncate_n_nibbles_back(2),
                        };

                        curr_k.merge_nibbles(&post_k)
                    },
                    true => curr_k,
                };

                match has_terminator {
                    false => {
                        // Extension node pointing to branch. Note that Edge extension nodes contain the leaf internally inside the extension node. If the extension points to a branch, then the child is the node key.
                        // Also ignore the extension node as we don't need it to reconstruct out `PartialTrie` version.                
                        let c_hash = field_2_rlp.data().unwrap();
                        match rlped_nodes.get(&Nibbles::from_bytes_be(c_hash).unwrap()) {
                            Some(child) => Self::decode_edge_rlp_state_trie_nodes_rec(child, curr_k, trie, rlped_nodes),
                            None => trie.insert(curr_k, H256::from_slice(c_hash)),
                        };

                    },
                    true => {
                        // Value node
                        trie.insert(curr_k, field_2_rlp.data().unwrap());
                    },
                }
            },
            17 => {
                for (i, c_rlp) in (0..16).map(|_| rlp_iter.next().unwrap()).enumerate() {
                    if c_rlp.is_empty() {
                        continue;
                    }

                    let c_hash = c_rlp.data().unwrap();
                    let curr_k = curr_k.merge_nibble(i as Nibble);

                    match rlped_nodes.get(&Nibbles::from_bytes_be(c_hash).unwrap()) {
                        // Hash node
                        None => {
                            trie.insert(curr_k, H256::from_slice(c_hash));
                        },

                        // Other node
                        Some(c_node) => {
                            Self::decode_edge_rlp_state_trie_nodes_rec(c_node, curr_k, trie, rlped_nodes);
                        },
                    }
                }

                // Also check the value field.
                let val_bytes = rlp_iter.next().unwrap();

                if !val_bytes.is_empty() {
                    // Impossible?
                    unreachable!()
                }
            },
            _ => panic!("Received an unexpected RLPed state node from edge that had {} elements (RLPed node: {})", num_items, curr_node),
        }
    }

    // Pretty inefficient, but we will worry about optimization as we need to later.
    fn decode_edge_rlp_state_trie_nodes(
        rlped_nodes: &HashMap<Nibbles, Rlp>,
        root_node_hash: H256,
    ) -> HashedPartialTrie {
        let mut trie = HashedPartialTrie::default();

        if rlped_nodes.is_empty() || root_node_hash == EMPTY_TRIE_HASH {
            return trie;
        }

        let root_k = Nibbles::from_h256_be(root_node_hash);
        let root_node = &rlped_nodes[&root_k];

        Self::decode_edge_rlp_state_trie_nodes_rec(
            root_node,
            Nibbles::default(),
            &mut trie,
            rlped_nodes,
        );
        trie
    }

    fn has_terminator(n: Nibbles) -> bool {
        let len = n.count;

        match len {
            0 | 1 => false,
            _ => n.get_nibble_range((len - 2)..(len)).bytes_be()[0] == 16,
        }
    }

    fn create_minimal_partial_tries_needed_by_txn(
        curr_block_tries: &BlockPartialTries,
        nodes_used_by_txn: NodesUsedByTxn,
        txn_idx: usize,
    ) -> TraceParsingResult<TrieInputs> {
        let subset_state_trie = create_trie_subset(
            &curr_block_tries.state,
            nodes_used_by_txn
                .state
                .into_iter()
                .map(Nibbles::from_h256_be),
        )
        .map_err(|_| TraceParsingError::NonExistentAcctAddrsCreatingSubPartialTrie)?;

        // Create the minimal account storage trie needed by the txn for the given
        // account. Multiple accounts may be involved, so we may have multiple storage
        // tries per txn.
        let subset_storage_tries = nodes_used_by_txn
            .storage
            .into_iter()
            .map(|(acc_addr, mem_addrs_accessed)| {
                let acc_storage_trie_base = curr_block_tries
                    .storage
                    .get(&acc_addr)
                    .ok_or(TraceParsingError::MissingAccountStorageTrie(acc_addr))?;

                // TODO: Remove clone after we're done debugging...
                let subset_acc_storage_trie =
                    create_trie_subset(acc_storage_trie_base, mem_addrs_accessed.clone()).map_err(
                        |err| {
                            let mem_addrs_accessed_formatted: Vec<_> = mem_addrs_accessed
                                .iter()
                                .map(|a| format!("{:x}", a))
                                .collect();
                            TraceParsingError::NonExistentStorageAddrsCreatingStorageSubPartialTrie(
                                acc_addr,
                                mem_addrs_accessed_formatted,
                                err.to_string(),
                            )
                        },
                    )?;

                Ok((acc_addr, subset_acc_storage_trie))
            })
            .collect::<TraceParsingResult<_>>()?;

        Ok(TrieInputs {
            state_trie: subset_state_trie,
            transactions_trie: Self::construct_partial_trie_from_idx(
                &curr_block_tries.receipt,
                txn_idx,
            ),
            receipts_trie: Self::construct_partial_trie_from_idx(&curr_block_tries.txn, txn_idx),
            storage_tries: subset_storage_tries,
        })
    }

    fn construct_partial_trie_from_idx(
        full_trie: &HashedPartialTrie,
        idx: usize,
    ) -> HashedPartialTrie {
        // Should be doing better errors here but this is currently just a hack.
        create_trie_subset(full_trie, once(idx as u64))
            .expect("Unable to create single element partial trie from an index")
    }

    fn apply_deltas_to_trie_state(
        trie_state: &mut BlockPartialTries,
        deltas: Vec<ProcessedTxnTrace>,
        addrs_to_code: &mut HashMap<H256, Vec<u8>>,
    ) -> TraceParsingResult<()> {
        for d in deltas {
            // Might be nicer to later adjust the library's API to make this into a single
            // operation...
            let val_k = Nibbles::from_h256_be(d.hashed_addr);
            let val_bytes = trie_state.state.get(val_k);

            let mut val: AccountRlp = match val_bytes {
                Some(b) => decode_account(b)?,
                None => AccountRlp::default(), // TODO: Hack due to likely bug in Edge...
            };

            update_val_if_some(&mut val.balance, d.balance);
            update_val_if_some(&mut val.nonce, d.nonce);
            update_val_if_some(
                &mut val.code_hash,
                d.code.map(|c| {
                    let c_hash = hash(&c);
                    addrs_to_code.insert(d.hashed_addr, c);

                    c_hash
                }),
            );

            if let Some(new_storage_deltas) = d.storage {
                // The account may not have any storage until this txn.
                let acc_storage_trie = trie_state.storage.entry(d.hashed_addr).or_default();

                for (k, v) in new_storage_deltas {
                    let rlped_v: Vec<_> = rlp::encode(&v).into();
                    acc_storage_trie.insert(k, rlped_v);
                }

                val.storage_root = acc_storage_trie.hash();
            }

            let updated_bytes = encode(&val);
            trie_state.state.insert(val_k, updated_bytes.to_vec());
        }

        Ok(())
    }

    fn update_receipt_and_txn_tries(
        receipt_trie: &mut HashedPartialTrie,
        txn_trie: &mut HashedPartialTrie,
        receipt_node: Vec<u8>,
        txn_node: Vec<u8>,
        txn_idx: usize,
    ) {
        Self::add_indexed_node_to_trie(receipt_trie, receipt_node, txn_idx);
        Self::add_indexed_node_to_trie(txn_trie, txn_node, txn_idx);
    }

    fn add_indexed_node_to_trie(trie: &mut HashedPartialTrie, node: Vec<u8>, txn_idx: usize) {
        trie.insert(txn_idx as u64, node)
    }

    pub fn num_txns(&self) -> usize {
        self.txn_bytes_and_traces.len()
    }
}

fn decode_account(b: &[u8]) -> TraceParsingResult<AccountRlp> {
    decode(b).map_err(|err| TraceParsingError::AccountDecode(format!("{:?}", b), err.to_string()))
}

fn update_val_if_some<T>(target: &mut T, opt: Option<T>) {
    if let Some(new_val) = opt {
        *target = new_val;
    }
}

#[derive(Debug)]
struct BlockPartialTries {
    state: HashedPartialTrie,
    storage: HashMap<H256, HashedPartialTrie>,
    receipt: HashedPartialTrie,
    txn: HashedPartialTrie,
}

#[derive(Debug)]
struct NodesUsedByTxn {
    state: Vec<H256>,
    storage: HashMap<H256, HashSet<StorageAddr>>,
}

fn hash(bytes: &[u8]) -> H256 {
    H256::from(keccak(bytes).0)
}

// TODO: Extreme hack! Please don't keep...
fn string_to_nibbles_even_nibble_fixed(s: &str) -> Nibbles {
    let mut n = Nibbles::from_str(s).unwrap();
    let odd_count = (n.count & 1) == 1;

    if odd_count {
        n.push_nibble_front(0);
    }

    n
}
