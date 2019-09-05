use network_libp2p::CustomMessage;
use parity_codec::{Encode, Decode};

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub enum Message {
    Ack(Vec<u8>),
    CustomData(Vec<u8>),
}

impl CustomMessage for Message
    where Self: Decode + Encode
{
    fn into_bytes(self) -> Vec<u8> {
        self.encode()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ()> where Self: Sized {
        Decode::decode(&mut &bytes[..]).ok_or(())
    }
}

