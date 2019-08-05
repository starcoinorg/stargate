use super::wallet::*;
use nextgen_crypto::test_utils::KeyPair;
use nextgen_crypto::Uniform;
use rand::prelude::*;

#[test]
fn test_wallet(){
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let keypair = KeyPair::generate_for_testing(&mut rng);
    let wallet = Wallet::new(keypair, "localhost", 1234);
}