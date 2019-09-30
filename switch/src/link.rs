use futures::io::{AsyncRead, AsyncWrite};
use types::account_address::AccountAddress;

pub struct SgChannel {
    local_addr: AccountAddress,
    remote_addr: AccountAddress,
}

pub struct ChannelLink<T: AsyncRead + AsyncWrite + Send> {
    id: String,
    sg_channel: SgChannel,
    up_stream: T,
    down_stream: T,
}
