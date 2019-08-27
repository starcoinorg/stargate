use failure::prelude::*;
use network_libp2p::PeerId;
use std::convert::TryFrom;
use types::account_address::AccountAddress;

pub fn convert_peer_id_to_account_address(peer_id: PeerId) -> Result<AccountAddress> {
    let peer_id_bytes = &peer_id.into_bytes()[2..];
    AccountAddress::try_from(peer_id_bytes)
}

pub fn convert_account_address_to_peer_id(
    address: AccountAddress,
) -> std::result::Result<PeerId, Vec<u8>> {
    let mut peer_id_vec = address.to_vec();
    peer_id_vec.insert(0, 32);
    peer_id_vec.insert(0, 22);
    PeerId::from_bytes(peer_id_vec)
}
