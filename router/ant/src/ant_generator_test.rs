#[test]
fn ant_router_test() {
    use crate::seed_generator::*;
    use libra_logger::prelude::*;

    libra_logger::init_for_e2e_testing();

    let ra = generate();
    let rb = generate();

    info!("ra is {} rb is {}", ra, rb);
}
