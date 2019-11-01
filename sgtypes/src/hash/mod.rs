// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crypto::define_hasher;
use crypto::hash::{CryptoHasher, DefaultHasher, HashValue};
use lazy_static::lazy_static;

define_hasher! {
/// The hasher used to compute the hash of an ChannelTransactionInfo object.
    (
        ChannelTransactionInfoHasher,
        CHANNEL_TRANSACTION_INFO_HASHER,
        b"ChannelTransactionInfo"
    )
}

define_hasher! {
/// The hasher used to compute the hash of an ChannelTransaction object.
    (
        ChannelTransactionAccumulatorHasher,
        CHANNEL_TRANSACTION_ACCUMULATOR_HASHER,
        b"ChannelTransactionAccumulator"
    )
}

define_hasher! {
    (WriteSetAccumulatorHasher, WRITE_SET_ACCUMULATOR_HASHER, b"WriteSetAccumulator")
}

define_hasher! {
   (SignedChannelTransactionHasher, SIGNED_CHANNEL_TRANSACTION_HASHER, b"SignedChannelTransaction")
}

define_hasher! {
    (ChannelTransactionHasher, CHANNEL_TRANSACTION_HASHER, b"ChannelTransaction")
}

define_hasher! { (WriteSetItemHasher, WRITE_SET_ITEM_HASHER, b"WriteSetItem") }

/// impl `CryptoHash` for `struct_type` using `hasher_type`
#[macro_export]
macro_rules! impl_hash {
    ($struct_type: ident, $hasher_type: ident) => {
        impl crypto::hash::CryptoHash for $struct_type {
            type Hasher = $hasher_type;

            fn hash(&self) -> crypto::hash::HashValue {
                let mut state = Self::Hasher::default();
                crypto::hash::CryptoHasher::write(
                    &mut state,
                    &canonical_serialization::SimpleSerializer::<Vec<u8>>::serialize(self)
                        .expect("Serialization should work."),
                );
                crypto::hash::CryptoHasher::finish(state)
            }
        }
    };
}
