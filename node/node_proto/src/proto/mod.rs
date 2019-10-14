use ::libra_types::proto::*;
use ::star_types::proto::*;

pub mod node {
    include!(concat!(env!("OUT_DIR"), "/node.rs"));
}
