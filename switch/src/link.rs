use network::p2p::TTcpSteam;
use types::account_address::AccountAddress;

pub struct SgChannel{
    local_addr:AccountAddress,
    remote_addr:AccountAddress,
}

pub struct ChannelLink <T:TTcpSteam>{
    id:String,
    sg_channel:SgChannel,
    up_stream: T,
    down_stream: T,
}