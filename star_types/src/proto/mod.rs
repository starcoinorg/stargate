#![allow(bare_trait_objects)]

pub mod star_types {
    include!(concat!(env!("OUT_DIR"), "/star_types.rs"));
}
