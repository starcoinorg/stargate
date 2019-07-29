use std::time::Duration;

use crypto::hash::Hash;

type Vertex=[u8; 33];

struct SgPayment {
	target:Vertex,
    amout:u64,
    fee_limit:u64,
    cltv_limit:u32,
    r_hash:[u8;32],
	final_cltv_delta:u16,
	pay_attempt_timeout:Duration,
}

struct SgNode {
	pub_key_bytes:Vertex,
    id:String,
}

struct SgEdge{
    channel_id:String,
    chain_hash:Hash,
    nodes:[SgNode;2],
}