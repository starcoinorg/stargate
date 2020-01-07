// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    channel::{access_local, channel::is_participant_channel_resource_modified},
    scripts::PackageRegistry,
    wallet::{
        execute_transaction, txn_expiration, GAS_UNIT_PRICE, MAX_GAS_AMOUNT_OFFCHAIN,
        MAX_GAS_AMOUNT_ONCHAIN,
    },
    ChannelStateView,
};
use anyhow::{bail, ensure, format_err, Result};
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue, SigningKey, VerifyingKey,
};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::{
    access_path::{AccessPath, DataPath},
    account_address::AccountAddress,
    channel::{
        ChannelChallengeBy, ChannelLockedBy, ChannelMirrorResource,
        ChannelParticipantAccountResource, ChannelResource, Witness, WitnessData,
    },
    identifier::Identifier,
    language_storage::ModuleId,
    libra_resource::{make_resource, LibraResource},
    transaction::{
        ChannelTransactionPayload, ChannelTransactionPayloadBody, RawTransaction, ScriptAction,
        SignedTransaction, TransactionArgument, TransactionOutput, TransactionPayload,
    },
    write_set::WriteSet,
};
use serde::de::DeserializeOwned;
use sgchain::star_chain_client::ChainClient;
use sgtypes::{
    channel::ChannelState,
    channel_transaction::{ChannelOp, ChannelTransaction, ChannelTransactionProposal},
    channel_transaction_sigs::ChannelTransactionSigs,
    pending_txn::{PendingTransaction, ProposalLifecycle},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use vm::gas_schedule::GasAlgebra;

/// Channel State Machine has no internal mutable state.
/// It is driven by `Channel`, so that we can mock channel state, and
/// test the sender/receiver logic separately.
/// Also, STM make more clear that what data is needed to make progress on channel state.   
pub struct ChannelStm {
    pub(crate) channel_address: AccountAddress,
    pub(crate) account_address: AccountAddress,
    // participant contains self address, use btree to preserve address order.
    pub(crate) participant_addresses: BTreeSet<AccountAddress>,
    participant_keys: BTreeMap<AccountAddress, Ed25519PublicKey>,
    channel_state: ChannelState,
    witness: Witness,

    keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
    script_registry: Arc<PackageRegistry>,
    chain_client: Arc<dyn ChainClient>,
}

impl ChannelStm {
    pub fn new(
        channel_address: AccountAddress,
        account_address: AccountAddress,
        participant_addresses: BTreeSet<AccountAddress>,
        participant_keys: BTreeMap<AccountAddress, Ed25519PublicKey>,
        channel_state: ChannelState,
        witness: Witness,

        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        script_registry: Arc<PackageRegistry>,
        chain_client: Arc<dyn ChainClient>,
    ) -> Self {
        Self {
            channel_address,
            account_address,
            participant_addresses,
            participant_keys,
            channel_state,
            witness,
            keypair,
            script_registry,
            chain_client,
        }
    }
    fn get_local<T>(&self, access_path: &AccessPath) -> Result<Option<T>>
    where
        T: LibraResource + DeserializeOwned,
    {
        let data = access_local(self.witness.write_set(), &self.channel_state, access_path)?;
        data.map(make_resource).transpose()
    }

    pub(crate) fn channel_sequence_number(&self) -> u64 {
        let channel_mirror_resource = self
            .get_local::<ChannelMirrorResource>(&AccessPath::new_for_data_path(
                self.channel_address,
                DataPath::channel_resource_path(
                    self.channel_address,
                    ChannelMirrorResource::struct_tag(),
                ),
            ))
            .unwrap();
        match channel_mirror_resource {
            None => 0,
            Some(r) => r.channel_sequence_number(),
        }
    }

    pub(crate) fn channel_resource(&self) -> Option<ChannelResource> {
        self.get_local::<ChannelResource>(&AccessPath::new_for_data_path(
            self.channel_address,
            DataPath::onchain_resource_path(ChannelResource::struct_tag()),
        ))
        .unwrap()
    }
    pub(crate) fn channel_lock_by_resource(&self) -> Option<ChannelLockedBy> {
        self.get_local::<ChannelLockedBy>(&AccessPath::new_for_data_path(
            self.channel_address,
            DataPath::onchain_resource_path(ChannelLockedBy::struct_tag()),
        ))
        .unwrap()
    }

    #[allow(dead_code)]
    fn channel_challenge_by_resource(&self) -> Option<ChannelChallengeBy> {
        self.get_local::<ChannelChallengeBy>(&AccessPath::new_for_data_path(
            self.channel_address,
            DataPath::onchain_resource_path(ChannelChallengeBy::struct_tag()),
        ))
        .unwrap()
    }

    #[allow(dead_code)]
    fn channel_account_resource(&self) -> Option<ChannelParticipantAccountResource> {
        self.get_local::<ChannelParticipantAccountResource>(&AccessPath::new_for_data_path(
            self.channel_address,
            DataPath::channel_resource_path(
                self.account_address,
                ChannelParticipantAccountResource::struct_tag(),
            ),
        ))
        .unwrap()
    }

    pub(crate) fn channel_state(&self) -> &ChannelState {
        &self.channel_state
    }
    pub(crate) fn witness(&self) -> &Witness {
        &self.witness
    }

    pub fn advance_state(
        &mut self,
        channel_state: Option<ChannelState>,
        witness: Witness,
        mut participant_keys: BTreeMap<AccountAddress, Ed25519PublicKey>,
    ) {
        if let Some(cs) = channel_state {
            self.channel_state = cs;
        }
        self.witness = witness;
        self.participant_keys.append(&mut participant_keys);
    }

    pub fn handle_new_proposal(
        &self,
        pending_txn: &mut Option<PendingTransaction>,
        proposal: ChannelTransactionProposal,
    ) -> Result<()> {
        if proposal.channel_txn.channel_sequence_number() < self.channel_sequence_number() {
            bail!("invalid channel proposal, proposal channel_sequence_number {} < local channel_sequence_number {}",proposal.channel_txn.channel_sequence_number(), self.channel_sequence_number());
        }
        match pending_txn {
            None => {
                // TODO: if I propose this, don't verify.
                self.verify_proposal(&proposal)?;

                debug!(
                    "{} - execute proposal: {}, {:?}",
                    &self.account_address,
                    proposal.channel_txn.operator(),
                    proposal.channel_txn.args()
                );
                // execute proposal to get txn payload and txn witness data for later use
                let (_payload_body, _payload_body_signature, output) =
                    self.execute_proposal(&proposal)?;

                let mut p = PendingTransaction::new(proposal, output, BTreeMap::new());
                p.set_lifecycle(ProposalLifecycle::Created);
                *pending_txn = Some(p);
            }
            Some(pending) => {
                if CryptoHash::hash(&pending.proposal().channel_txn)
                    != CryptoHash::hash(&proposal.channel_txn)
                {
                    bail!(
                        "already exists a different pending proposal, op: {}",
                        pending.proposal().channel_txn.operator()
                    );
                }
            }
        }
        Ok(())
    }

    pub fn handle_proposal_signature(
        &self,
        //        proposal: ChannelTransactionProposal,
        pending_txn: &mut PendingTransaction,
        proposal_id: HashValue,
        sigs: ChannelTransactionSigs,
    ) -> Result<()> {
        let proposal_lifecycle = pending_txn.lifecycle();
        //        let (proposal, output, mut signatures) = pending_txn.into();
        let proposal = pending_txn.proposal();
        ensure!(
            proposal.channel_txn.hash() == proposal_id,
            "proposal txn hash mismatched"
        );

        if pending_txn.get_signature(&sigs.address).is_none() {
            let (payload_body, _) =
                self.build_and_sign_channel_txn_payload_body(&proposal.channel_txn)?;
            self.verify_txn_sigs(&payload_body, pending_txn.output(), &sigs)?;
            pending_txn.add_signature(sigs);

            match proposal_lifecycle {
                ProposalLifecycle::Created => {
                    pending_txn.set_lifecycle(ProposalLifecycle::Negotiating);
                }
                ProposalLifecycle::Negotiating => {
                    pending_txn.try_reach_consensus(&self.participant_addresses);
                }
                _ => unreachable!(),
            }
        }
        return Ok(());
    }
    pub fn handle_apply_proposal(&self, pending_txn: &mut PendingTransaction) -> Result<()> {
        let can_be_offchain =
            pending_txn.consensus_reached() && !pending_txn.output().is_travel_txn();
        if can_be_offchain {
            // can directly apply offchain
            pending_txn.set_applying();
        } else {
            pending_txn.set_travelling();
        }
        Ok(())
    }

    pub fn can_auto_sign_pending_proposal(&self, pending_txn: &PendingTransaction) -> Result<bool> {
        let can_auto_signed = !is_participant_channel_resource_modified(
            self.witness.write_set(),
            pending_txn.output().write_set(),
            &self.account_address,
        );
        Ok(can_auto_signed)
    }

    /// build channel txn payload version 2.
    fn build_and_sign_channel_txn_payload_body(
        &self,
        channel_txn: &ChannelTransaction,
    ) -> Result<(ChannelTransactionPayloadBody, Ed25519Signature)> {
        let action =
            self.channel_op_to_action(channel_txn.operator(), channel_txn.args().to_vec())?;

        let body = ChannelTransactionPayloadBody::new(
            self.channel_address,
            channel_txn.proposer(),
            action,
            self.witness.clone(),
        );
        let body_hash = CryptoHash::hash(&body);
        let sig = self.keypair.private_key.sign_message(&body_hash);
        Ok((body, sig))
    }

    pub fn build_signed_txn(&self, pending_txn: &PendingTransaction) -> Result<SignedTransaction> {
        let channel_txn = &pending_txn.proposal().channel_txn;

        let (payload_body, _payload_signature) =
            self.build_and_sign_channel_txn_payload_body(channel_txn)?;
        let max_gas_amount = std::cmp::min(
            (pending_txn.output().gas_used() as f64 * 1.1) as u64,
            MAX_GAS_AMOUNT_ONCHAIN,
        );
        let signed_txn = self.build_raw_txn_from_channel_txn(
            payload_body,
            channel_txn,
            Some(pending_txn.signatures()),
            max_gas_amount,
        )?;
        Ok(signed_txn)
    }

    fn build_raw_txn_from_channel_txn(
        &self,
        channel_payload_body: ChannelTransactionPayloadBody,
        channel_txn: &ChannelTransaction,
        txn_signatures: Option<&BTreeMap<AccountAddress, ChannelTransactionSigs>>,
        max_gas_amount: u64,
    ) -> Result<SignedTransaction> {
        let channel_payload_signatures = txn_signatures.map(|s| {
            s.into_iter()
                .map(|(k, v)| {
                    let ChannelTransactionSigs {
                        public_key,
                        channel_payload_signature,
                        ..
                    } = v;
                    (
                        k.clone(),
                        (public_key.clone(), channel_payload_signature.clone()),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        });
        self.build_chain_txn(
            channel_payload_body,
            channel_payload_signatures,
            channel_txn.proposer(),
            channel_txn.sequence_number(),
            max_gas_amount,
            channel_txn.expiration_time(),
        )
    }
    fn build_chain_txn(
        &self,
        channel_payload_body: ChannelTransactionPayloadBody,
        txn_signatures: Option<BTreeMap<AccountAddress, (Ed25519PublicKey, Ed25519Signature)>>,
        txn_sender: AccountAddress,
        sender_seq_number: u64,
        max_gas_amount: u64,
        expiration_time: Duration,
    ) -> Result<SignedTransaction> {
        let channel_participant_size = self.participant_addresses.len();
        let mut participant_keys = self.participant_keys.clone();
        let mut sigs = Vec::with_capacity(channel_participant_size);
        if let Some(signatures) = txn_signatures {
            for addr in self.participant_addresses.iter() {
                let sig = signatures.get(&addr);
                if let Some(s) = sig {
                    participant_keys.insert(addr.clone(), s.0.clone());
                }
                sigs.push(sig.map(|s| s.1.clone()));
            }
        }

        if channel_payload_body.witness().channel_sequence_number() == 0 {
            //            debug_assert!(channel_txn.operator().is_open());
        } else {
            debug_assert!(channel_participant_size == participant_keys.len());
        }

        let keys = participant_keys
            .into_iter()
            .map(|p| p.1)
            .collect::<Vec<_>>();

        let channel_txn_payload = ChannelTransactionPayload::new(channel_payload_body, keys, sigs);
        let txn_payload = TransactionPayload::Channel(channel_txn_payload);

        let raw_txn = RawTransaction::new(
            txn_sender,
            sender_seq_number,
            txn_payload,
            max_gas_amount,
            GAS_UNIT_PRICE,
            expiration_time,
        );
        Ok(raw_txn
            .sign(&self.keypair.private_key, self.keypair.public_key.clone())?
            .into_inner())
    }

    fn channel_op_to_action(
        &self,
        op: &ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ScriptAction> {
        match op {
            ChannelOp::Open => {
                let module_id =
                    ModuleId::new(AccountAddress::default(), Identifier::new("ChannelScript")?);

                Ok(ScriptAction::new_call(
                    module_id,
                    Identifier::new("open")?,
                    args,
                ))
            }
            ChannelOp::Close => {
                let module_id =
                    ModuleId::new(AccountAddress::default(), Identifier::new("LibraAccount")?);

                Ok(ScriptAction::new_call(
                    module_id,
                    Identifier::new("close")?,
                    args,
                ))
            }
            ChannelOp::Execute {
                package_name,
                script_name,
            } => {
                let script_code = self
                    .script_registry
                    .get_script(package_name, script_name)
                    .ok_or(format_err!(
                        "Can not find script by package {} and script name {}",
                        package_name,
                        script_name
                    ))?;
                Ok(ScriptAction::new_code(
                    script_code.byte_code().clone(),
                    args,
                ))
            }
            ChannelOp::Action {
                module_address,
                module_name,
                function_name,
            } => {
                let module_id = ModuleId::new(
                    module_address.clone(),
                    Identifier::new(module_name.clone().into_boxed_str())?,
                );
                Ok(ScriptAction::new_call(
                    module_id,
                    Identifier::new(function_name.clone().into_boxed_str())?,
                    args,
                ))
            }
        }
    }

    pub fn generate_proposal(
        &self,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionProposal> {
        // TODO: state view should be shared to reduce fetching account state from layer1.
        let state_view = self.channel_view(None)?;

        // account state already cached in state view
        let account_seq_number = {
            let account_resource_blob = state_view
                .get(&AccessPath::new_for_account_resource(self.account_address))?
                .ok_or(format_err!(
                    "account resource for {} not exists on chain",
                    self.account_address,
                ))?;
            let account_resource =
                sgtypes::account_resource_ext::from_bytes(&account_resource_blob)?;
            account_resource.sequence_number()
        };

        let chain_version = state_view.version();
        // build channel_transaction first
        let channel_txn = ChannelTransaction::new(
            chain_version,
            self.channel_address,
            self.channel_sequence_number(),
            channel_op,
            args,
            self.account_address,
            account_seq_number,
            txn_expiration(),
        );
        let channel_txn_hash = CryptoHash::hash(&channel_txn);
        let channel_txn_signature = self.keypair.private_key.sign_message(&channel_txn_hash);

        let proposal = ChannelTransactionProposal {
            channel_txn,
            proposer_public_key: self.keypair.public_key.clone(),
            proposer_signature: channel_txn_signature,
        };
        Ok(proposal)
    }

    pub fn execute_proposal(
        &self,
        proposal: &ChannelTransactionProposal,
    ) -> Result<(
        ChannelTransactionPayloadBody,
        Ed25519Signature,
        TransactionOutput,
    )> {
        let channel_txn = &proposal.channel_txn;
        let (payload_body, payload_body_signature) =
            self.build_and_sign_channel_txn_payload_body(channel_txn)?;

        let output = {
            // create mocked txn to execute
            // execute txn on offchain vm, should mock sender and receiver signature with a local
            // keypair. the vm will skip signature check on offchain vm.
            let txn = self.build_raw_txn_from_channel_txn(
                payload_body.clone(),
                channel_txn,
                None,
                MAX_GAS_AMOUNT_OFFCHAIN,
            )?;

            let version = channel_txn.version();
            let state_view = self.channel_view(Some(version))?;
            execute_transaction(&state_view, txn)?
        };

        // check output gas
        let gas_used = output.gas_used();
        if gas_used > vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get() {
            warn!(
                "GasUsed {} > gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS {}",
                gas_used,
                vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get()
            );
        }

        Ok((payload_body, payload_body_signature, output))
    }

    pub fn generate_txn_sigs(
        &self,
        channel_txn: &ChannelTransaction,
        output: &TransactionOutput,
    ) -> Result<ChannelTransactionSigs> {
        let (_, payload_body_signature) =
            self.build_and_sign_channel_txn_payload_body(channel_txn)?;

        let ws = if output.is_travel_txn() {
            WriteSet::default()
        } else {
            output.write_set().clone()
        };
        let witness_data = WitnessData::new(self.channel_sequence_number() + 1, ws);
        let witness_data_hash = CryptoHash::hash(&witness_data);
        let witness_data_signature = self.keypair.private_key.sign_message(&witness_data_hash);

        let travel_output_witness_signature = if output.is_travel_txn() {
            let txn_output_witness_data = WitnessData::new(
                self.channel_sequence_number() + 1,
                output.write_set().clone(),
            );
            Some(
                self.keypair
                    .private_key
                    .sign_message(&CryptoHash::hash(&txn_output_witness_data)),
            )
        } else {
            None
        };

        let generated_sigs = ChannelTransactionSigs::new(
            self.account_address,
            self.keypair.public_key.clone(),
            payload_body_signature,
            witness_data_hash,
            witness_data_signature,
            travel_output_witness_signature,
        );

        Ok(generated_sigs)
    }

    fn verify_proposal(&self, proposal: &ChannelTransactionProposal) -> Result<()> {
        let channel_txn = &proposal.channel_txn;
        ensure!(
            self.channel_address == channel_txn.channel_address(),
            "invalid channel address"
        );
        let channel_sequence_number = self.channel_sequence_number();
        let smallest_allowed_channel_seq_number =
            channel_sequence_number.checked_sub(1).unwrap_or(0);
        ensure!(
            channel_txn.channel_sequence_number() >= smallest_allowed_channel_seq_number
                && channel_txn.channel_sequence_number() <= channel_sequence_number,
            "check channel_sequence_number fail."
        );
        proposal
            .proposer_public_key
            .verify_signature(&CryptoHash::hash(channel_txn), &proposal.proposer_signature)?;

        // TODO: check public key match proposer address
        if !channel_txn.operator().is_open() {
            ensure!(
                self.participant_addresses.contains(&channel_txn.proposer()),
                "proposer does not belong to the channel"
            );
        }
        Ok(())
    }

    fn verify_txn_sigs(
        &self,
        payload_body: &ChannelTransactionPayloadBody,
        output: &TransactionOutput,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<()> {
        channel_txn_sigs.public_key.verify_signature(
            &CryptoHash::hash(payload_body),
            &channel_txn_sigs.channel_payload_signature,
        )?;

        let ws = if output.is_travel_txn() {
            WriteSet::default()
        } else {
            output.write_set().clone()
        };
        let witness_data = WitnessData::new(self.channel_sequence_number() + 1, ws);

        ensure!(
            &CryptoHash::hash(&witness_data) == &channel_txn_sigs.witness_data_hash,
            "witness hash mismatched"
        );
        channel_txn_sigs.public_key.verify_signature(
            &channel_txn_sigs.witness_data_hash,
            &channel_txn_sigs.witness_data_signature,
        )?;

        if output.is_travel_txn() {
            match &channel_txn_sigs.travel_output_witness_signature {
                None => bail!("travel txn should have signer's signature on output"),
                Some(signature) => {
                    let txn_output_witness_data = WitnessData::new(
                        self.channel_sequence_number() + 1,
                        output.write_set().clone(),
                    );
                    channel_txn_sigs
                        .public_key
                        .verify_signature(&CryptoHash::hash(&txn_output_witness_data), signature)?;
                }
            }
        }

        Ok(())
    }

    fn channel_view(&self, version: Option<u64>) -> Result<ChannelStateView> {
        ChannelStateView::new(
            self.account_address,
            &self.channel_state,
            self.witness.write_set(),
            version,
            self.chain_client.as_ref(),
        )
    }
}
