use ::libra_types::proto::*;
use ::sgtypes::proto::*;

pub mod node {
    include!(concat!(env!("OUT_DIR"), "/node.rs"));
}
