use std::collections::HashMap;

use ethereum_types::{Address, H160, H256, U256};
use hex::FromHex;
use rlp::{Decodable, DecoderError, Rlp, RlpIterator};
use rlp_derive::{RlpDecodable, RlpDecodableWrapper};
use rust_decimal::Decimal;
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Number;
use serde_with::{base64::Base64, serde_as, DefaultOnNull, FromInto, TryFromInto};

use crate::types::{StorageVal, TxnTraces};

/// The incoming block trace payload from Edge.
///
/// For both of the tries (account & storage), Edge sends us the minimal
/// internal trie state needed by all txns in the block. More specifically, the
/// nodes hit by all txns are included in this initial minimal trie state. Any
/// nodes that are not accessed are not included, but we still have the hashes
/// of the nodes that are missing.
///
/// It's important to note that Edge sends us tries in their own internal trie
/// format. To be more exact, Edge sends a map of each nodes root hash --> rlped
/// node data. Because we use our own partial trie format (see
/// [`eth_trie_utils`]), we must process the Edge tries into this format.
#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EdgeBlockTrace {
    /// The minimal state trie needed to process all txns.
    #[serde_as(as = "DefaultOnNull<HashMap<_, FromInto<ByteString>>>")]
    pub account_trie: HashMap<H256, Vec<u8>>,

    /// The minimal account tries needed to process all txns. All account
    /// storage trie nodes are merged into a single trie in the incoming account
    /// data. We need to parse out the individual storage tries on our own.
    #[serde_as(as = "DefaultOnNull<HashMap<_, FromInto<ByteString>>>")]
    pub storage_trie: HashMap<H256, Vec<u8>>,

    /// The root hash of the state trie. Parsing the state trie into our own
    /// format is a lot harder without this.
    pub parent_state_root: H256,

    /// "Traces" for each txn. All txns have a trace, and the index in the `Vec`
    /// corresponds to the txn index in the block.
    #[serde(rename(deserialize = "transactionTraces"))]
    pub txn_bytes_and_traces: Vec<TxnBytesAndTraces>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxnBytesAndTraces {
    /// Raw bytes of the txn.
    #[serde_as(as = "FromInto<ByteString>")]
    pub txn: Vec<u8>,

    /// The root of the txn trie after the txn has been executed.
    pub txn_root: H256,

    /// The root of the receipt trie after the txn has been executed.
    pub receipt_root: H256,

    // GasUsed is the amount of gas used by the transaction
    pub gas_used: u64,

    // Bloom is the bloom filter for the transaction
    pub bloom: [U256; 8],

    #[serde(rename(deserialize = "delta"))]
    /// All deltas for the txn.
    pub traces: TxnTraces,
}

/// A delta for a given txn.
///
/// A txn may have 0 - * deltas, and a delta contains the changes that occurred
/// associated with the account that occurred during the txn. We need to apply
/// these deltas to our tries after each txn before processing the following txn
/// in order for the tries to be in the correct initial state.
///
/// Since a trace may only change some state, many of these fields are
/// `Option`s. For example, a txn may or may not change the balance of an
/// account.
///
/// Also node that while a single delta only contains info related to a single
/// account, a single account may read/write to multiple storage addresses, and
/// therefore a single delta may contain an arbitrary number of storage address
/// changes.
#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TxnDelta {
    /// Redundant and can safely be removed from the incoming payload. The
    /// address is already provided as the key in the deltas for a txn.
    pub address: Address,

    /// If the balance changed, then the new balance will appear here.
    #[serde_as(as = "Option<TryFromInto<U256DecWrapper>>")]
    pub balance: Option<U256>,

    /// If the nonce changed, then the new nonce will appear here;
    #[serde_as(as = "Option<TryFromInto<U256DecWrapper>>")]
    pub nonce: Option<U256>,

    // TODO: Fight with `serde_as` some more and don't read in as a string initially...
    /// Account storage addresses that were mutated by the txn along with their
    /// new value.
    pub storage: Option<HashMap<String, StorageVal>>,

    // No idea why we're given a map of addrs to empty HashSets, but...
    /// Account addresses that were only read by the txn.
    #[serde_as(as = "Option<FromInto<HashMapToVecWrapper<HashMap<String, u8>>>>")]
    pub storage_read: Option<Vec<String>>,

    /// If the account's contract bytecode changed during the txn, it will
    /// appear here.
    #[serde_as(as = "Option<Base64>")]
    pub code: Option<Vec<u8>>,

    /// The bytecode at this address was read (but not created).
    #[serde_as(as = "Option<Base64>")]
    pub code_read: Option<Vec<u8>>,

    /// We don't need this, but it's given anyways.
    pub suicide: Option<bool>,

    /// Not sure when this is set, but we don't need it.
    pub touched: Option<bool>,

    /// Also not sure when this is set. If a delta appears for an account, then
    /// we can be sure it is a read.
    pub read: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct U256DecWrapper(Number);

impl From<U256DecWrapper> for U256 {
    fn from(v: U256DecWrapper) -> U256 {
        let s = v.0.to_string();

        // Sometimes the numbers can be in the format of `e+x`, and `from_dec_str`
        // doesn't support these.
        U256::from_dec_str(&s).unwrap_or_else(|_| {
            let d = Decimal::from_scientific(&s).unwrap();
            U256::from_dec_str(&d.to_string()).unwrap()
        })
    }
}

#[derive(Debug, Deserialize)]
struct HashMapToVecWrapper<V>(HashMap<String, V>);

impl<'a, V: Deserialize<'a>> From<HashMapToVecWrapper<V>> for Vec<String> {
    fn from(v: HashMapToVecWrapper<V>) -> Self {
        Vec::from_iter(v.0.into_keys())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ByteString(#[serde(with = "self")] pub(crate) Vec<u8>);

impl From<ByteString> for Vec<u8> {
    fn from(v: ByteString) -> Self {
        v.0
    }
}

// Gross, but there is no Serde crate that can both parse a hex string with a
// prefix and also deserialize from a `Vec<u8>`.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct PrefixHexStrVisitor();

    impl<'de> Visitor<'de> for PrefixHexStrVisitor {
        type Value = Vec<u8>;

        fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            FromHex::from_hex(Self::remove_prefix_if_present(data)).map_err(Error::custom)
        }

        fn visit_borrowed_str<E>(self, data: &'de str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            FromHex::from_hex(Self::remove_prefix_if_present(data)).map_err(Error::custom)
        }

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a hex encoded string with a prefix")
        }
    }

    impl PrefixHexStrVisitor {
        fn remove_prefix_if_present(data: &str) -> &str {
            let prefix = &data[..2];

            match matches!(prefix, "0x" | "0X") {
                false => data,
                true => &data[2..],
            }
        }
    }

    deserializer.deserialize_string(PrefixHexStrVisitor())
}

#[derive(Clone, Debug)]
pub struct EdgeBlockResponse {
    pub header: EdgeBlockResponseHeader,
    pub txns: Vec<EdgeResponseTxn>,
    pub uncles: Vec<EdgeBlockResponseHeader>,
}

impl Decodable for EdgeBlockResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            header: rlp.val_at(0)?,
            txns: decode_txn_stream(rlp.at(1)?.into_iter())?,
            uncles: rlp.list_at(2)?,
        })
    }
}

#[derive(Clone, Debug, RlpDecodable)]
pub struct EdgeBlockResponseHeader {
    pub parent_hash: H256,
    pub sha3_uncles: H256,
    pub miner: Address,
    pub state_root: H256,
    pub tx_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Vec<U256>,
    pub difficulty: u64,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: H256,
    pub nonce: Vec<u8>,
    pub base_fee: u64,
}

#[derive(Clone, Debug)]
pub enum EdgeResponseTxn {
    Legacy(LegacyTxn),
    State(StateTxn),
    Dynamic(DynamicTxn),
}

const STATE_TX_FLAG_BYTES: u8 = 0x7f;
const DYNAMIC_TX_FLAG_BYTES: u8 = 0x02;

fn decode_txn_stream(mut rlp_iter: RlpIterator) -> Result<Vec<EdgeResponseTxn>, DecoderError> {
    let mut edge_txns = Vec::new();

    while let Some(field) = rlp_iter.next() {
        match field.is_list() {
            // A single value that contains just a byte for txn type.
            false => {
                // Txn is either `State` or `Dynamic`.
                // TODO: Also clean up this dup.
                let txn_type: TxnType = field.as_val()?;
                let txn_payload = txn_stream_iter_next(&mut rlp_iter)?;

                // TODO: Cleanup code dup...
                match txn_type.0 {
                    STATE_TX_FLAG_BYTES => {
                        edge_txns.push(txn_payload.as_val::<StateTxn>()?.into());
                    }
                    DYNAMIC_TX_FLAG_BYTES => {
                        edge_txns.push(txn_payload.as_val::<DynamicTxn>()?.into());
                    }
                    _ => return Err(DecoderError::Custom("Unrecognized txn type flag!")),
                };
            }
            // An RLP list of a legacy txn.
            true => {
                let txn_payload: LegacyTxn = field.as_val()?;
                edge_txns.push(txn_payload.into());
            }
        }
    }

    Ok(edge_txns)
}

fn txn_stream_iter_next<'a>(rlp_iter: &'a mut RlpIterator) -> Result<Rlp<'a>, DecoderError> {
    rlp_iter.next().ok_or(DecoderError::Custom(
        "Unexpected end of rlp iterator when decoding rlped txns",
    ))
}

#[derive(Debug, RlpDecodableWrapper)]
struct TxnType(u8);

#[derive(Clone, Debug, RlpDecodable)]
pub struct LegacyTxn {
    pub nonce: u64,
    pub gas_price: U256,
    pub gas: u64,
    pub to: Vec<u8>,
    pub value: U256,
    pub input: Vec<u8>,
    pub v: U256,
    pub r: U256,
    pub s: U256,
}

impl From<LegacyTxn> for EdgeResponseTxn {
    fn from(v: LegacyTxn) -> Self {
        Self::Legacy(v)
    }
}

#[derive(Clone, Debug, RlpDecodable)]
pub struct StateTxn {
    pub nonce: u64,
    pub gas_price: u64,
    pub gas: u64,
    pub to: Vec<u8>,
    pub value: U256,
    pub input: Vec<u8>,
    pub v: U256,
    pub r: U256,
    pub s: U256,
    pub from: H160,
}

impl From<StateTxn> for EdgeResponseTxn {
    fn from(v: StateTxn) -> Self {
        Self::State(v)
    }
}

#[derive(Clone, Debug, RlpDecodable)]
pub struct DynamicTxn {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_tip: u64,
    pub gas_fee: u64,
    pub gas: u64,
    pub to: Vec<u8>,
    pub value: U256,
    pub input: Vec<u8>,
    pub access_list: Vec<u8>,
    pub v: U256,
    pub r: U256,
    pub s: U256,
}

impl From<DynamicTxn> for EdgeResponseTxn {
    fn from(v: DynamicTxn) -> Self {
        Self::Dynamic(v)
    }
}
