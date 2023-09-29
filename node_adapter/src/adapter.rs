use futures::{future::BoxFuture, TryStream};

pub type BlockHeight = u64;

/// Configuration for the stream.
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    /// The starting block height.
    pub start_height: BlockHeight,
    /// The maximum number of traces to produce before blocking the sender.
    ///
    /// Once this limit is reached, the internal sending side of the channel
    /// should wait to produce new traces until additional space opens up in the
    /// buffer. This is to prevent unbounded memory consumption. Buffer space is
    /// freed as messages are pulled from the receiving side of the channel.
    ///
    /// The appropriate value will depend on the consumer's ability and desire
    /// to process traces concurrently.
    pub buffer_size: usize,
}

/// An adapter for a node that can produce traces.
pub trait NodeAdapter {
    /// The type of trace produced by the node.
    type Trace;
    /// The type of error produced while producing traces.
    type Error;
    /// The type of stream produced by the node.
    type St: TryStream<Item = Self::Trace, Error = Self::Error>;

    /// Create a new stream of traces.
    fn get_stream(&self, config: StreamConfig) -> BoxFuture<'_, Result<Self::St, Self::Error>>;
}
