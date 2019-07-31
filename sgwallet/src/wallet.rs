extern crate star_types;

use star_types::channel::SgChannelStream;
use super::wallet_listener::ChannelListener;

struct WalletChannelListener {}

impl ChannelListener<SgChannelStream> for WalletChannelListener {
    fn listener() -> Result<SgChannelStream, Box<dyn std::error::Error>> {
        unimplemented!()
    }
}