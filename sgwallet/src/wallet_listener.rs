extern crate futures;
extern crate star_types;

use futures::Stream;
use star_types::channel::SgChannelInfo;

pub trait ChannelListener<S> where S: Stream<Item=SgChannelInfo> {
    fn listener() -> Result<S, Box<dyn std::error::Error>>;
}
