use types::{transaction::{RawTransaction, SignedTransaction, TransactionStatus},
            contract_event::ContractEvent,
            write_set::{WriteSet, WriteSetMut},
            vm_error::{VMStatus, VMValidationStatus, VMInvariantViolationError, BinaryError, ExecutionStatus},
            proto::{transaction::WriteSet as WriteSetProto, vm_errors::{VMStatus as VMStatusProto, VMVerificationStatusList}, events::Event}};
use super::proto::transaction_output::{TransactionOutput as TransactionOutputProto, TransactionStatus as TransactionStatusProto,
                                       TransactionStatus_oneof_transaction_status};
use failure::Result;
use proto_conv::{FromProto, IntoProto};
use ::protobuf::RepeatedField;
use crate::change_set::{ChangeSet, ChangeSetMut};
use types::transaction::TransactionOutput;
use canonical_serialization::{SimpleDeserializer, SimpleSerializer};

pub fn from_pb(mut pb: TransactionOutputProto) -> Result<TransactionOutput> {
    let mut from_cs = pb.take_write_set();
    let ws = SimpleDeserializer::deserialize(from_cs.as_slice())?;

    let status = {
        if pb.has_status() {
            let mut from_status = pb.take_status();
            from_pb_status(from_status)?
        } else {
            panic!("no status err")
        }
    };

    let mut events: Vec<ContractEvent> = vec![];
    for e in (pb.take_events().into_vec()) {
        events.push(ContractEvent::from_proto(e).unwrap());
    }

    let mut output = TransactionOutput::new(ws, events, 0, status);
    Ok(output)
}

pub fn into_pb(tx_output: TransactionOutput) -> Result<TransactionOutputProto> {
    let mut output = TransactionOutputProto::new();

    let mut events: Vec<Event> = vec![];
    for e in tx_output.events() {
        let tmp = e.clone();
        events.push(ContractEvent::into_proto(tmp));
    }

    let status = to_pb_status(tx_output.status().clone())?;
    output.set_events(RepeatedField::from_vec(events.to_vec()));
    output.set_status(status);
    output.set_write_set(SimpleSerializer::serialize(tx_output.write_set())?);
    output.set_gas_used(tx_output.gas_used());
    Ok(output)
}

fn from_pb_status(mut pb: TransactionStatusProto) -> Result<TransactionStatus> {
    let from_vm_status = match pb.transaction_status {
        Some(tmp) => {
            match tmp {
                TransactionStatus_oneof_transaction_status::Discard(vm_status) => { vm_status }
                TransactionStatus_oneof_transaction_status::Keep(vm_status) => { vm_status }
            }
        }
        _ => {
            panic!("transaction status err")
        }
    };
    let to_vm_status = VMStatus::from_proto(from_vm_status)?;
    Ok(TransactionStatus::from(to_vm_status))
}

fn to_pb_status(mut status: TransactionStatus) -> Result<TransactionStatusProto> {
    let mut ts_pb = TransactionStatusProto::new();
    let (should_discard, to_vm_status) = match status {
        TransactionStatus::Discard(vm_status) => {
            (true, VMStatus::into_proto(vm_status))
        }
        TransactionStatus::Keep(vm_status) => {
            (false, VMStatus::into_proto(vm_status))
        }
    };

    if should_discard {
        ts_pb.set_Discard(to_vm_status);
    } else {
        ts_pb.set_Keep(to_vm_status);
    }

    Ok(ts_pb)
}