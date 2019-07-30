use channel::channel::SgChannel;
use network::p2p::TTcpSteam;

pub struct ChannelLink <T:TTcpSteam>{
    sg_channel:SgChannel,
    up_stream: T,
    down_stream: T,
}

