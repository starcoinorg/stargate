use network::p2p::TTcpSteam;
use star_types::channel::SgChannel;

pub struct ChannelLink <T:TTcpSteam>{
    id:String,
    sg_channel:SgChannel,
    up_stream: T,
    down_stream: T,
}