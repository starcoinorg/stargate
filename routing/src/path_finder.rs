use std::time::Duration;

type vertex=[u8; 33];

struct SgPayment {
	target:vertex,
    amout:u64,
    fee_limit:u64,
    cltv_limit:u32,
    r_hash:[u8;32],
	final_cltv_delta:u16,
	pay_attempt_timeout:Duration,
}

