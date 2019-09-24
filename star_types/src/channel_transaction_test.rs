use rand::prelude::*;
use canonical_serialization::{
    CanonicalDeserializer, CanonicalSerializer, SimpleDeserializer, SimpleSerializer,
};
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use crypto::test_utils::KeyPair;
use crypto::Uniform;
use failure::_core::time::Duration;
use types::account_address::AccountAddress;
use types::transaction::{ChannelScriptPayload, ChannelWriteSetPayload, RawTransaction, Script};
use types::transaction_helpers::ChannelPayloadSigner;
use types::write_set::WriteSet;

use crate::channel_transaction::{ChannelOp, ChannelTransactionRequest, ChannelTransactionRequestPayload, Witness};

//TODO(jole) use Arbitrary
#[test]
fn request_roundtrip_canonical_serialization() {
    let mut rng0: StdRng = SeedableRng::from_seed([0; 32]);
    let keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = KeyPair::generate_for_testing(&mut rng0);
    let sender = AccountAddress::from_public_key(&keypair.public_key);
    let receiver = AccountAddress::random();
    let script = Script::new(vec![], vec![]);
    let channel_script_payload = ChannelScriptPayload::new(0, WriteSet::default(), receiver, script);
    let signature = keypair.sign_script_payload(&channel_script_payload).unwrap();
    let txn = RawTransaction::new_channel_script(sender, 0, channel_script_payload, 0, 0, Duration::from_millis(1000));
    let witness = Witness {
        witness_payload: ChannelWriteSetPayload::new(0, WriteSet::default(), receiver),
        witness_signature: signature,
    };
    let request = ChannelTransactionRequest::new(0, ChannelOp::Open, txn,
                                                 ChannelTransactionRequestPayload::Offchain(witness), keypair.public_key.clone());
    let mut serializer = SimpleSerializer::<Vec<u8>>::new();
    serializer.encode_struct(&request).unwrap();
    let serialized_bytes = serializer.get_output();

    let mut deserializer = SimpleDeserializer::new(&serialized_bytes);
    let output: ChannelTransactionRequest = deserializer.decode_struct().unwrap();
    assert_eq!(request, output);
}