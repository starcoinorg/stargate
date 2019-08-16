use failure::prelude::*;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crypto::HashValue;
use vm_runtime_types::loaded_data::{struct_def::StructDef, types::Type};
use vm_runtime::{code_cache::{module_adapter::{ModuleFetcherImpl, ModuleFetcher}}, loaded_data::loaded_module::LoadedModule};
use types::{access_path::AccessPath, language_storage::StructTag};
use state_view::StateView;
use types::language_storage::ModuleId;
use vm::{try_runtime, file_format::{SignatureToken, CompiledModule, StructDefinition, StructFieldInformation, StructHandleIndex, StructDefinitionIndex},
         errors::{VMInvariantViolation, VMResult, VMRuntimeResult, VMRuntimeError, VMErrorKind, VerificationStatus, Location},
         views::{FunctionHandleView, StructHandleView}};
use core::borrow::{Borrow, BorrowMut};
use vm::access::ModuleAccess;
use bytecode_verifier::VerifiedModule;
use atomic_refcell::AtomicRefCell;
use types::account_config::{account_struct_tag, coin_struct_tag};
use star_types::resource::*;
use star_types::change_set::StructDefResolve;
use lazy_static::lazy_static;

lazy_static!{
    pub static ref STATIC_STRUCT_DEF_RESOLVE: StaticStructDefResolve = StaticStructDefResolve::new();
}

pub struct StructCache {
    struct_map: AtomicRefCell<HashMap<StructTag, StructDef>>
}

impl StructCache {
    pub fn new() -> Self {
        let struct_map = AtomicRefCell::new(HashMap::new());
        StructCache { struct_map }
    }

    pub fn find_struct(&self, tag: &StructTag, state_view: &dyn StateView) -> Result<StructDef> {
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
            let module = self.get_loaded_module_with_fetcher(&module_id, &module_fetcher).map_err(|vm_error|format_err!("${:?}", vm_error))?;
            match module {
                None => {},
                Some(module) => self.struct_def_from_module(tag.clone(), &module_fetcher, &module)
            }
        };
        let map = self.struct_map.borrow();
        return map.get(tag).cloned().ok_or(format_err!("Can not find StructDef with StructTag: {:?}", tag));
    }

    fn struct_def_from_module(&self, find_tag: StructTag, fetcher: &dyn ModuleFetcher, module: &LoadedModule) {
        let string_pool = module.string_pool();
        let struct_defs = module.struct_defs();
        let struct_handles = module.struct_handles();

        struct_defs.iter().for_each(|struct_def| {
            let struct_handle_index = struct_def.struct_handle;
            let struct_handle = module.struct_handle_at(struct_handle_index);
            let struct_name = module.string_at(struct_handle.name);
            let struct_def_idx = module
                .struct_defs_table
                .get(struct_name)
                .ok_or(VMInvariantViolation::LinkerError).unwrap();
            let def = self.resolve_struct_def_with_fetcher(module, *struct_def_idx, fetcher).unwrap().unwrap().unwrap();

            let tag = StructTag {
                address: find_tag.address,
                module: find_tag.module.clone(),
                name: struct_name.to_string(),
                type_params: vec![],
            };

            self.struct_map.borrow_mut().insert(tag, def);
        });
    }

    fn resolve_struct_handle_with_fetcher(
        &self,
        module: &LoadedModule,
        idx: StructHandleIndex,
        fetcher: &dyn ModuleFetcher,
    ) -> VMResult<Option<StructDef>> {
        let struct_handle = module.struct_handle_at(idx);
        let struct_name = module.string_at(struct_handle.name);
        let struct_def_module_id = StructHandleView::new(module, struct_handle).module_id();
        match self.get_loaded_module_with_fetcher(&struct_def_module_id, fetcher) {
            Ok(Some(module)) => {
                let struct_def_idx = module
                    .struct_defs_table
                    .get(struct_name)
                    .ok_or(VMInvariantViolation::LinkerError)?;
                self.resolve_struct_def_with_fetcher(&module, *struct_def_idx, fetcher)
            }
            Ok(None) => Ok(Ok(None)),
            Err(errors) => Ok(Err(errors)),
        }
    }

    fn resolve_signature_token_with_fetcher(
        &self,
        module: &LoadedModule,
        tok: &SignatureToken,
        fetcher: &dyn ModuleFetcher,
    ) -> VMResult<Option<Type>> {
        match tok {
            SignatureToken::Bool => Ok(Ok(Some(Type::Bool))),
            SignatureToken::U64 => Ok(Ok(Some(Type::U64))),
            SignatureToken::String => Ok(Ok(Some(Type::String))),
            SignatureToken::ByteArray => Ok(Ok(Some(Type::ByteArray))),
            SignatureToken::Address => Ok(Ok(Some(Type::Address))),
            SignatureToken::TypeParameter(_) => unimplemented!(),
            SignatureToken::Struct(sh_idx, _) => {
                let struct_def =
                    try_runtime!(self
                        .resolve_struct_handle_with_fetcher(module, *sh_idx, fetcher));
                Ok(Ok(struct_def.map(Type::Struct)))
            }
            SignatureToken::Reference(sub_tok) => {
                let inner_ty =
                    try_runtime!(self
                        .resolve_signature_token_with_fetcher(module, sub_tok, fetcher));
                Ok(Ok(inner_ty.map(|t| Type::Reference(Box::new(t)))))
            }
            SignatureToken::MutableReference(sub_tok) => {
                let inner_ty =
                    try_runtime!(self
                        .resolve_signature_token_with_fetcher(module, sub_tok, fetcher));
                Ok(Ok(inner_ty.map(|t| Type::MutableReference(Box::new(t)))))
            }
        }
    }

    fn resolve_struct_def_with_fetcher(
        &self,
        module: &LoadedModule,
        idx: StructDefinitionIndex,
        fetcher: &dyn ModuleFetcher,
    ) -> VMResult<Option<StructDef>> {
        if let Some(def) = module.cached_struct_def_at(idx) {
            return Ok(Ok(Some(def)));
        }
        let def = {
            let struct_def = module.struct_def_at(idx);
            match &struct_def.field_information {
                StructFieldInformation::Native => return Err(VMInvariantViolation::LinkerError),
                StructFieldInformation::Declared {
                    field_count,
                    fields,
                } => {
                    let mut field_types = vec![];
                    for field in module.field_def_range(*field_count, *fields) {
                        let ty = try_runtime!(self.resolve_signature_token_with_fetcher(
                            module,
                            &module.type_signature_at(field.signature).0,
                            fetcher
                        ));
                        if let Some(t) = ty {
                            field_types.push(t);
                        } else {
                            return Ok(Ok(None));
                        }
                    }
                    StructDef::new(field_types)
                }
            }
        };
        module.cache_struct_def(idx, def.clone());
        Ok(Ok(Some(def)))
    }

    fn get_loaded_module_with_fetcher(
        &self,
        id: &ModuleId,
        fetcher: &dyn ModuleFetcher,
    ) -> VMRuntimeResult<Option<LoadedModule>> {
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
                return Err(VMRuntimeError {
                    loc: Location::new(),
                    err: VMErrorKind::Verification(
                        errors
                            .into_iter()
                            .map(|error| {
                                VerificationStatus::Dependency(id.clone(), error)
                            })
                            .collect(),
                    ),
                });
            }
        };

        Ok(Some(LoadedModule::new(module)))
    }
}



pub struct StaticStructDefResolve{
    register:HashMap<StructTag, StructDef>,
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
        Self{
            register
        }
    }
}

impl StructDefResolve for StaticStructDefResolve{

    fn resolve(&self, tag: &StructTag) -> Result<StructDef> {
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

            let (program, module) = compiler.into_compiled_program_and_deps().unwrap();
            let mut modules = HashMap::new();
            module.iter().for_each(|v_m| {
                let tmp = v_m.clone().into_inner();
                let mut data = vec![];
                tmp.serialize(&mut data);

                let index = modules.len();
                let id = ModuleId::new(v_m.clone().address().clone(), format!("LibraCoin:{}", index));
                let access_path = AccessPath::code_access_path(&id);
                modules.insert(access_path, data);
            });

            MockStateView { modules }
        }
    }

    impl StateView for MockStateView {
        fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
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
        let struct_tag = StructTag { address, module: "LibraCoin:0".to_string(), name: "T".to_string(), type_params: vec![] };
        let struct_def = struct_cache.find_struct(&struct_tag, &state_view).unwrap();
        println!("{:?}", struct_def)
    }
}