use rand::Rng;

pub fn generate() -> u128 {
    let mut rng = rand::thread_rng();

    rng.gen::<u128>()
}
