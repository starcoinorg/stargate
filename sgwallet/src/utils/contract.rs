use anyhow::{bail, Result};
use lazy_static::lazy_static;
use libra_types::{
    account_address::AccountAddress,
    account_config::{account_module_name, core_code_address},
    channel::ChannelEvent,
    contract_event::ContractEvent,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, TypeTag},
    libra_resource::{make_resource, LibraResource},
    transaction::{ScriptAction, TransactionArgument},
};

lazy_static! {
    static ref CHALLENGE_METHOD_NAME: Identifier = Identifier::new("challenge").unwrap();
    static ref RESOLVE_METHOD_NAME: Identifier = Identifier::new("resolve").unwrap();
    static ref CLOSE_METHOD_NAME: Identifier = Identifier::new("close").unwrap();
}

pub fn channel_challenge_name() -> &'static IdentStr {
    &*CHALLENGE_METHOD_NAME
}
pub fn channel_resolve_name() -> &'static IdentStr {
    &*RESOLVE_METHOD_NAME
}
pub fn channel_close_name() -> &'static IdentStr {
    &*CLOSE_METHOD_NAME
}

#[allow(dead_code)]
pub fn resolve_channel_action() -> ScriptAction {
    ScriptAction::new_call(
        ModuleId::new(core_code_address(), account_module_name().into()),
        channel_resolve_name().into(),
        vec![],
    )
}
#[allow(dead_code)]
pub fn challenge_channel_action() -> ScriptAction {
    ScriptAction::new_call(
        ModuleId::new(core_code_address(), account_module_name().into()),
        channel_challenge_name().into(),
        vec![],
    )
}

#[allow(dead_code)]
pub fn close_channel_action(violator: AccountAddress) -> ScriptAction {
    ScriptAction::new_call(
        ModuleId::new(core_code_address(), account_module_name().into()),
        channel_close_name().into(),
        vec![TransactionArgument::Address(violator)],
    )
}

pub fn parse_channel_event(event: &ContractEvent) -> Result<ChannelEvent> {
    match event.type_tag() {
        TypeTag::Struct(s) => {
            debug_assert_eq!(&ChannelEvent::struct_tag(), s);
        }
        t => bail!("channel event type should not be {:#?}", &t),
    }
    let channel_event = make_resource::<ChannelEvent>(event.event_data())?;
    Ok(channel_event)
}
