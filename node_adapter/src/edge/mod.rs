use std::{ops::Range, pin::Pin, time::Duration};

use anyhow::{anyhow, Context, Result};
use backoff::{future::retry, ExponentialBackoffBuilder};
use futures::{future::BoxFuture, stream::FuturesOrdered, Future, FutureExt, Stream, TryStreamExt};
use pin_project::{pin_project, pinned_drop};
use plonky2_evm::proof::BlockMetadata;
use plonky_edge_block_trace_parser::edge_payloads::{EdgeBlockResponse, EdgeBlockTrace};
use rlp::decode;
use tokio::{sync::mpsc::channel, task::JoinHandle, try_join};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use self::system::system_client::SystemClient;
use crate::adapter::{BlockHeight, NodeAdapter, StreamConfig};

pub mod system {
    tonic::include_proto!("v1");
}

#[derive(Default)]
pub struct EdgeConfig {
    /// The URI of the gRPC node.
    pub remote_uri: String,
    /// How often the chain produces new blocks.
    ///
    /// This will be used to determine how long to wait before polling the node
    /// for new block heights if the stream is caught up to the node.
    pub block_time: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct EdgeTraceWithMeta {
    pub trace: EdgeBlockTrace,
    pub b_meta: BlockMetadata,
}

/// The edge [`NodeAdapter`].
///
/// This adapter enables streaming [`EdgeTraceWithMeta`] instances starting from
/// the given block height.
///
/// # Example
/// ```no_run
/// use plonky_node_adapter::{
///     NodeAdapter, StreamConfig,
///     edge::{EdgeConfig, EdgeNodeAdapter}
/// };
/// use futures::StreamExt;
///
/// # use anyhow::Result;
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let edge = EdgeNodeAdapter::from_config(EdgeConfig {
///         remote_uri: "http://[::1]:50051".to_string(),
///         ..Default::default()
///     })
///     .await?;
///
///     let mut stream = edge
///         .get_stream(StreamConfig {
///             buffer_size: 1,
///             start_height: 4242,
///         })
///         .await?;
///
///     while let Some(block) = stream.next().await {
///         match block {
///             Ok((height, block)) => {
///                 println!("block {height}: {block:?}");
///             }
///             Err(e) => {
///                 println!("error: {:?}", e);
///             }
///         }
///     }
/// # Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct EdgeNodeAdapter {
    /// How often the chain produces new blocks.
    ///
    /// This will be used to determine how long to wait before polling the node
    /// for new block heights if the stream is caught up to the node.
    block_time: Duration,
    /// The gRPC client.
    client: SystemClient<Channel>,
}

/// A handle to a block stream that will abort the stream when dropped.
///
/// It implements [`Stream`], delegating to the given [`ReceiverStream`].
#[pin_project(PinnedDrop)]
pub struct StreamGuard<T> {
    #[pin]
    stream: ReceiverStream<T>,
    handle: JoinHandle<()>,
}

impl<T> Stream for StreamGuard<T> {
    type Item = T;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.project();
        this.stream.poll_next(cx)
    }
}

#[pinned_drop]
impl<T> PinnedDrop for StreamGuard<T> {
    fn drop(self: Pin<&mut Self>) {
        self.handle.abort();
    }
}

impl NodeAdapter for EdgeNodeAdapter {
    type Trace = Result<(BlockHeight, EdgeTraceWithMeta), Self::Error>;
    type Error = anyhow::Error;
    type St = StreamGuard<Self::Trace>;

    fn get_stream(
        &self,
        stream_config: StreamConfig,
    ) -> BoxFuture<'_, Result<Self::St, Self::Error>> {
        Box::pin(async move {
            let mut node_tip = self.fetch_cur_node_height().await?;
            let mut our_tip = stream_config.start_height;
            let block_time = self.block_time;
            let (tx, rx) = channel(stream_config.buffer_size);

            let this = self.clone();
            let handle = tokio::spawn(async move {
                loop {
                    // Update our version of the node tip once we've caught up to it.
                    // This is an optimization based on the assumption that processing blocks in the
                    // consumer will generally be slower than the rate at which the node produces
                    // them. In particular, rather than continuously polling the node for the
                    // current block height, we _lazily_ do so only when we've caught up to the last
                    // node tip we've seen.
                    if our_tip >= node_tip {
                        // Attempt to fetch the next node tip.
                        let next_node_tip = this.fetch_cur_node_height().await;

                        match next_node_tip {
                            Ok(next_node_tip) => {
                                // Success, update our tip.
                                node_tip = next_node_tip;
                            }
                            Err(err) => {
                                // Notify the receiver that we've encountered an error.
                                let send = tx.send(Err(err)).await;
                                // If send errors, the receiver has been dropped.
                                if send.is_err() {
                                    break;
                                }
                            }
                        }

                        if our_tip >= node_tip {
                            // If the node tip hasn't changed, sleep for the block time.
                            tokio::time::sleep(block_time).await;
                            continue;
                        }
                    }

                    let trace_with_meta = this.fetch_trace_with_metadata_for_height(our_tip).await;

                    // This will block if the buffer is full, waiting until there is space.
                    let send = tx.send(trace_with_meta.map(|t| (our_tip, t))).await;
                    // If send errors, the receiver has been dropped.
                    if send.is_err() {
                        break;
                    }

                    // Increment our tip.
                    our_tip += 1;
                }
            });

            Ok(StreamGuard {
                stream: ReceiverStream::new(rx),
                handle,
            })
        })
    }
}

const RETRY_MAX_ELAPSED_TIME: Duration = Duration::from_secs(60);
/// Retry the given async operation with exponential backoff.
async fn with_retry<F, Fut, R, E>(f: F) -> Result<R, E>
where
    Fut: Future<Output = Result<R, backoff::Error<E>>>,
    F: FnMut() -> Fut,
{
    retry(
        ExponentialBackoffBuilder::new()
            .with_max_elapsed_time(Some(RETRY_MAX_ELAPSED_TIME))
            .build(),
        f,
    )
    .await
}

const EDGE_DEFAULT_BLOCK_TIME: Duration = Duration::from_secs(2);

impl EdgeNodeAdapter {
    pub async fn from_config(
        EdgeConfig {
            remote_uri,
            block_time,
        }: EdgeConfig,
    ) -> Result<Self> {
        Ok(Self {
            block_time: block_time.unwrap_or(EDGE_DEFAULT_BLOCK_TIME),
            client: SystemClient::connect(remote_uri)
                .await
                .context("Failed to connect to gRPC node")?,
        })
    }

    /// Fetch the current block height from the node.
    pub async fn fetch_cur_node_height(&self) -> Result<BlockHeight> {
        with_retry(|| {
            let mut client = self.client.clone();
            async move {
                Ok(client
                    .get_status(())
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|r| {
                        r.into_inner()
                            .current
                            .ok_or_else(|| anyhow!("ServerStatus contained empty Block"))
                            .map(|c| c.number as BlockHeight)
                    })
                    .context("Failed to fetch node's current block height")?)
            }
        })
        .await
    }

    /// Fetch the trace for the given block height.
    ///
    /// The edge node returns a byte array containing a JSON-encoded trace. This
    /// function deserializes the JSON and returns an [`EdgeBlockTrace`].
    pub async fn fetch_trace_for_height(&self, height: BlockHeight) -> Result<EdgeBlockTrace> {
        with_retry(|| {
            let mut client = self.client.clone();
            async move {
                Ok(client
                    .get_trace(system::GetTraceRequest { number: height })
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|r| {
                        serde_json::from_slice(&r.into_inner().trace).map_err(anyhow::Error::from)
                    })
                    .with_context(|| format!("Failed to fetch trace for block {height}"))?)
            }
        })
        .await
    }

    /// Fetch the block metadata for the given block height.
    ///
    /// The edge node returns an RLP-encoded block metadata payload. This
    /// function decodes the payload and returns the decoded [`BlockMetadata`].
    pub async fn fetch_metadata_for_height(&self, height: BlockHeight) -> Result<BlockMetadata> {
        with_retry(|| {
            let mut client = self.client.clone();
            async move {
                Ok(client
                    .block_by_number(system::BlockByNumberRequest { number: height })
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|resp| {
                        let resp = resp.into_inner().data;
                        decode::<EdgeBlockResponse>(&resp)
                            .map(|resp| resp.into())
                            .map_err(|err| {
                                anyhow!(
                                    "Parsing block metadata for block {} with err: {} \n({:?})",
                                    height,
                                    err,
                                    hex::encode(&resp)
                                )
                            })
                    })
                    .context("Failed to fetch block by number")?)
            }
        })
        .await
    }

    /// Fetch the trace and metadata for the given block height.
    ///
    /// This returns a fully decoded and deserialized [`EdgeTraceWithMeta`]
    /// struct.
    pub async fn fetch_trace_with_metadata_for_height(
        &self,
        height: BlockHeight,
    ) -> Result<EdgeTraceWithMeta> {
        let (trace, b_meta) = try_join!(
            self.fetch_trace_for_height(height),
            self.fetch_metadata_for_height(height)
        )
        .context("Failed to join trace and block metadata")?;

        Ok(EdgeTraceWithMeta { trace, b_meta })
    }

    /// Execute an async function that accepts a `BlockHeight` over a range of
    /// `BlockHeight`s.
    async fn fetch_fn_for_range<F, Fut, R>(
        &self,
        range: Range<BlockHeight>,
        f: F,
    ) -> Result<Vec<(BlockHeight, R)>>
    where
        Fut: Future<Output = Result<R>>,
        F: Fn(BlockHeight) -> Fut,
    {
        let fs: FuturesOrdered<_> = range
            .into_iter()
            .map(|h| f(h).map(move |r| r.map(|x| (h, x))))
            .collect();
        fs.try_collect().await
    }

    /// Fetch the block metadata for the given block height range.
    ///
    /// The edge node returns an RLP-encoded block metadata payload. This
    /// function decodes the payload and returns the decoded [`BlockMetadata`]
    /// structs.
    pub async fn fetch_metadata_for_range(
        &self,
        range: Range<BlockHeight>,
    ) -> Result<Vec<(BlockHeight, BlockMetadata)>> {
        self.fetch_fn_for_range(range, |height| self.fetch_metadata_for_height(height))
            .await
    }

    /// Fetch the block trace for the given block height range.
    ///
    /// The edge node returns an RLP-encoded block metadata payload. This
    /// function decodes the payload and returns the decoded [`BlockMetadata`]
    /// structs.
    pub async fn fetch_trace_for_range(
        &self,
        range: Range<BlockHeight>,
    ) -> Result<Vec<(BlockHeight, EdgeBlockTrace)>> {
        self.fetch_fn_for_range(range, |height| self.fetch_trace_for_height(height))
            .await
    }

    /// Fetch the trace and metadata for the given block height range.
    ///
    /// This returns a fully decoded and deserialized [`EdgeTraceWithMeta`]
    /// structs.
    pub async fn fetch_trace_with_metadata_for_range(
        &self,
        range: Range<BlockHeight>,
    ) -> Result<Vec<(BlockHeight, EdgeTraceWithMeta)>> {
        self.fetch_fn_for_range(range, |height| {
            self.fetch_trace_with_metadata_for_height(height)
        })
        .await
    }
}
