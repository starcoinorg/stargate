extern crate futures;
extern crate star_types;

use futures::Stream;
use star_types::channel::SgChannel;

pub trait ChannelListener<S> where S: Stream<Item=SgChannel> {
    fn listener() -> Result<S, Box<dyn std::error::Error>>;
}
