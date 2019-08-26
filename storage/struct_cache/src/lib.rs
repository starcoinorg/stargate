use failure::prelude::*;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crypto::HashValue;
use vm_runtime_types::loaded_data::{struct_def::StructDef, types::Type};
use vm_runtime::{code_cache::{module_adapter::{ModuleFetcherImpl, ModuleFetcher}}, loaded_data::loaded_module::LoadedModule};
use types::{access_path::AccessPath, language_storage::StructTag};
use state_view::StateView;
use types::language_storage::ModuleId;
use vm::{file_format::{SignatureToken, CompiledModule, StructDefinition, StructFieldInformation, StructHandleIndex, StructDefinitionIndex},
         errors::{VMInvariantViolation, VMResult, VMRuntimeResult, VMRuntimeError, VMErrorKind, VerificationStatus, Location},
         views::{FunctionHandleView, StructHandleView}};
use core::borrow::{Borrow, BorrowMut};
use vm::access::ModuleAccess;
use bytecode_verifier::VerifiedModule;
use atomic_refcell::AtomicRefCell;
use types::account_config::{account_struct_tag, coin_struct_tag};
use star_types::resource::*;
use star_types::change_set::StructDefResolve;
use star_types::resource_type::{resource_def::ResourceDef, resource_types::ResourceType};
use lazy_static::lazy_static;
use logger::prelude::*;

lazy_static!{
    pub static ref STATIC_STRUCT_DEF_RESOLVE: StaticStructDefResolve = StaticStructDefResolve::new();
}

pub struct StructCache {
    struct_map: AtomicRefCell<HashMap<StructTag, ResourceDef>>
}

impl StructCache {
    pub fn new() -> Self {
        let struct_map = AtomicRefCell::new(HashMap::new());
        StructCache { struct_map }
    }

    pub fn find_struct(&self, tag: &StructTag, state_view: &dyn StateView) -> Result<ResourceDef> {
        match STATIC_STRUCT_DEF_RESOLVE.resolve(tag){
            Ok(def) => return Ok(def),
            Err(_) => {
                //continue
            }
        }
        let exist = self.struct_map.borrow().contains_key(tag);
        if !exist {
            let module_fetcher = ModuleFetcherImpl::new(state_view);
            let module_id = ModuleId::new(tag.address, tag.module.clone());
            match Self::get_loaded_module_with_fetcher(&module_id, &module_fetcher)?{
                None => {
                    warn!("Get loaded module {:?} fail.", module_id)
                },
                Some(module) => {
                    let defs = Self::resource_def_from_module(&module_fetcher, &module)?;
                    for (tag, def) in defs{
                        self.struct_map.borrow_mut().insert(tag, def);
                    }
                }
            }
        };
        let map = self.struct_map.borrow();
        return map.get(tag).cloned().ok_or(format_err!("Can not find ResourceDef with StructTag: {:?}", tag));
    }

    fn resource_def_from_module(fetcher: &dyn ModuleFetcher, module: &LoadedModule) -> Result<Vec<(StructTag,ResourceDef)>> {
        let string_pool = module.string_pool();
        let struct_defs = module.struct_defs();
        let struct_handles = module.struct_handles();
        let mut results = vec![];
        for struct_def in struct_defs {
            let struct_handle_index = struct_def.struct_handle;
            let struct_handle = module.struct_handle_at(struct_handle_index);
            let struct_name = module.string_at(struct_handle.name);
            let struct_def_idx = module
                .struct_defs_table
                .get(struct_name)
                .ok_or(format_err!("VMInvariantViolation::LinkerError"))?;
            let (tag,def) = Self::resolve_struct_def_with_fetcher(module, *struct_def_idx, fetcher)?.ok_or(format_err!("resolve struct def fail."))?;
            results.push((tag,def));
        }
        Ok(results)
    }

    fn resolve_struct_handle_with_fetcher(
        module: &LoadedModule,
        idx: StructHandleIndex,
        fetcher: &dyn ModuleFetcher,
    ) -> Result<Option<(StructTag,ResourceDef)>> {
        let struct_handle = module.struct_handle_at(idx);
        let struct_name = module.string_at(struct_handle.name);
        let struct_def_module_id = StructHandleView::new(module, struct_handle).module_id();
        match Self::get_loaded_module_with_fetcher(&struct_def_module_id, fetcher) {
            Ok(Some(module)) => {
                let struct_def_idx = module
                    .struct_defs_table
                    .get(struct_name)
                    .ok_or(format_err!("VMInvariantViolation::LinkerError"))?;
                Self::resolve_struct_def_with_fetcher(&module, *struct_def_idx, fetcher)
            }
            Ok(None) => Ok(None),
            Err(errors) => Err(errors),
        }
    }

    fn resolve_signature_token_with_fetcher(
        module: &LoadedModule,
        tok: &SignatureToken,
        fetcher: &dyn ModuleFetcher,
    ) -> Result<Option<ResourceType>> {
        match tok {
            SignatureToken::Bool => Ok(Some(ResourceType::Bool)),
            SignatureToken::U64 => Ok(Some(ResourceType::U64)),
            SignatureToken::String => Ok(Some(ResourceType::String)),
            SignatureToken::ByteArray => Ok(Some(ResourceType::ByteArray)),
            SignatureToken::Address => Ok(Some(ResourceType::Address)),
            SignatureToken::Struct(sh_idx, _) => {
                Ok(match Self::resolve_struct_handle_with_fetcher(module, *sh_idx, fetcher)?{
                    Some((struct_tag,struct_def)) => {
                        Some(ResourceType::Resource(struct_tag,struct_def))
                    },
                    None => None
                })
            }
            _ => {
                bail!("Unsupported type")
            }
        }
    }

    fn resolve_struct_def_with_fetcher(
        module: &LoadedModule,
        idx: StructDefinitionIndex,
        fetcher: &dyn ModuleFetcher,
    ) -> Result<Option<(StructTag, ResourceDef)>> {
//        if let Some(def) = module.cached_struct_def_at(idx) {
//            return Ok(Ok(Some(def)));
//        }
        let def = {
            let struct_def = module.struct_def_at(idx);
            let struct_handle = module.struct_handle_at(struct_def.struct_handle);
            let struct_tag = StructTag{
                name: module.string_at(struct_handle.name).to_owned(),
                address: *module.address(),
                module: module.name().to_owned(),
                type_params: vec![]
            };
            match &struct_def.field_information {
                StructFieldInformation::Native => bail!("VMInvariantViolation::LinkerError"),
                StructFieldInformation::Declared {
                    field_count,
                    fields,
                } => {
                    let mut field_types = vec![];
                    for field in module.field_def_range(*field_count, *fields) {
                        let ty = Self::resolve_signature_token_with_fetcher(
                            module,
                            &module.type_signature_at(field.signature).0,
                            fetcher
                        )?;
                        if let Some(t) = ty {
                            field_types.push(t);
                        } else {
                            return Ok(None);
                        }
                    }

                    (struct_tag,ResourceDef::new(field_types))
                }
            }
        };
        Ok(Some(def))
    }

    fn get_loaded_module_with_fetcher(
        id: &ModuleId,
        fetcher: &dyn ModuleFetcher,
    ) -> Result<Option<LoadedModule>> {
            let module = match fetcher.get_module(id) {
            Some(module) => {
                module
            }
            None => return {
                Ok(None)
            },
        };

        let module = match VerifiedModule::new(module) {
            Ok(module) => {
                module
            }
            Err((_, errors)) => {
                let vm_err = VMRuntimeError {
                    loc: Location::new(),
                    err: VMErrorKind::Verification(
                        errors
                            .into_iter()
                            .map(|error| {
                                VerificationStatus::Dependency(id.clone(), error)
                            })
                            .collect(),
                    ),
                };
                return Err(format_err!("vm_err: {:?}", vm_err));
            }
        };

        Ok(Some(LoadedModule::new(module)))
    }
}



pub struct StaticStructDefResolve{
    register:HashMap<StructTag, ResourceDef>,
}

impl StaticStructDefResolve {

    pub fn new() -> Self{
        let mut register = HashMap::new();
        register.insert(account_struct_tag(), get_account_struct_def());
        register.insert(coin_struct_tag(), get_coin_struct_def());
        register.insert(get_market_cap_struct_tag(), get_market_cap_struct_def());
        register.insert(get_mint_capability_struct_tag(), get_mint_capability_struct_def());
        register.insert( get_event_handle_struct_tag(), get_event_handle_struct_def());
        register.insert(get_event_handle_id_generator_tag(), get_event_handle_id_generator_def());
        register.insert(get_block_module_tag(), get_block_module_def());
        Self{
            register
        }
    }
}

impl StructDefResolve for StaticStructDefResolve{

    fn resolve(&self, tag: &StructTag) -> Result<ResourceDef> {
        self.register.get(tag).cloned().ok_or(format_err!("Can not find StructDef by tag: {:?}", tag))
    }
}



#[cfg(test)]
mod tests {
    use failure::prelude::*;
    use compiler::Compiler;
    use state_view::StateView;
    use types::access_path::AccessPath;
    use crate::StructCache;
    use types::{language_storage::StructTag, account_address::AccountAddress};
    use vm_runtime_types::loaded_data::struct_def::StructDef;
    use vm::access::ModuleAccess;
    use std::collections::HashMap;
    use types::language_storage::ModuleId;
    use itertools::Itertools;

    struct MockStateView {
        modules: HashMap<AccessPath, Vec<u8>>
    }

    impl MockStateView {
        pub fn new() -> Self {
            let code =
                "
            modules:
            module B {
                struct T {g: u64}

                public new(g: u64): Self.T {
                    return T{g: move(g)};
                }

                public t(this: &Self.T) {
                    let g: &u64;
                    let y: u64;
                    g = &copy(this).g;
                    y = *move(g);
                    release(move(this));
                    return;
                }
            }

            script:

            import Transaction.B;

            main() {
                let x: B.T;
                let y: &B.T;
                x = B.new(5);
                y = &x;
                B.t(move(y));
                return;
            }
            ";

            let compiler = Compiler {
                code,
                ..Compiler::default()
            };

            let (mut program, mut deps) = compiler.into_compiled_program_and_deps().unwrap();
            let mut modules = deps.iter().map(|module|module.clone().into_inner()).collect_vec();
            modules.append(&mut program.modules);
            let mut cache = HashMap::new();
            modules.iter().for_each(|module|{
                let mut data = vec![];
                module.serialize(&mut data);
                let id = ModuleId::new(module.address().clone(), module.name().to_owned());
                let access_path = AccessPath::code_access_path(&id);
                println!("insert access path: {:?}, module_id:{:?}", access_path, id);
                cache.insert(access_path, data);
            });
            MockStateView { modules:cache }
        }
    }

    impl StateView for MockStateView {
        fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
            println!("get access path: {:?}, data_path:{:?}", access_path, access_path.data_path());
            Ok(Some(self.modules.get(access_path).unwrap().clone()))
        }

        fn multi_get(&self, access_paths: &[AccessPath]) -> Result<Vec<Option<Vec<u8>>>> {
            Ok(access_paths.iter().map(|path| -> Option<Vec<u8>> {
                Some(self.modules.get(path).unwrap().clone())
            }).collect())
        }

        fn is_genesis(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_struct_cache() {
        let mut struct_cache = StructCache::new();
        let state_view = MockStateView::new();
        let address = AccountAddress::default();
        let struct_tag = StructTag { address, module: "B".to_string(), name: "T".to_string(), type_params: vec![] };
        let struct_def = struct_cache.find_struct(&struct_tag, &state_view).unwrap();
        println!("{:?}", struct_def)
    }
}