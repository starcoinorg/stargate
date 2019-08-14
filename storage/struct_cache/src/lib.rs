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

pub struct StructCache {
    struct_map: HashMap<StructTag, StructDef>
}

impl StructCache {
    pub fn new() -> Self {
        let struct_map = HashMap::new();
        StructCache { struct_map }
    }

    pub fn find_struct(&mut self, tag: StructTag, state_view: &dyn StateView) -> StructDef {
        let exist = self.struct_map.contains_key(&tag);
        let tag_clone_1 = tag.clone();
        if !exist {
            let module_fetcher = ModuleFetcherImpl::new(state_view);
            let tag_clone_2 = tag.clone();
            let module_id = ModuleId::new(tag_clone_2.address, tag_clone_2.module);
            let module = self.get_loaded_module_with_fetcher(&module_id, &module_fetcher).unwrap().unwrap();

            self.struct_def_from_module(tag_clone_1, &module_fetcher, &module);
        };

        return self.struct_map.get(&tag).unwrap().clone();
    }

    fn struct_def_from_module(&mut self, find_tag: StructTag, fetcher: &ModuleFetcher, module: &LoadedModule) {
        let string_pool = module.string_pool().clone();
        let struct_defs = module.struct_defs();
        let struct_handles = module.struct_handles();

        struct_defs.iter().map(|struct_def| {
            let struct_handle_index = struct_def.struct_handle;
            let struct_handle_index_usize = struct_handle_index.0 as usize;
            let def = self.resolve_struct_handle_with_fetcher(module, struct_handle_index, fetcher).unwrap().unwrap().unwrap();
            let struct_handle = struct_handles.clone()[struct_handle_index_usize].clone();
            let struct_name_index = struct_handle.name.0 as usize;
            let struct_name = string_pool.clone()[struct_name_index].clone();

            let tag = StructTag {
                address: find_tag.address,
                module: find_tag.module.clone(),
                name: struct_name,
                type_params: vec![],
            };

            self.struct_map.insert(tag, def);
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
            Some(module) => module,
            None => return Ok(None),
        };

        let module = match VerifiedModule::new(module) {
            Ok(module) => module,
            Err((_, errors)) => {
                return Err(VMRuntimeError {
                    loc: Location::new(),
                    err: VMErrorKind::Verification(
                        errors
                            .into_iter()
                            .map(|error| VerificationStatus::Dependency(id.clone(), error))
                            .collect(),
                    ),
                });
            }
        };

        Ok(Some(LoadedModule::new(module)))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_struct_cache() {

    }
}