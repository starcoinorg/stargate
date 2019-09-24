use admission_control_proto::proto::admission_control_client::AdmissionControlClientTrait;
use std::sync::Arc;

pub struct MockStarClient {
    ac_client: Arc<dyn AdmissionControlClientTrait>
}

impl MockStarClient {
    pub fn new(client: Box<AdmissionControlClientTrait>) -> Self {
        let ac_client = Arc::new(client.into());
        MockStarClient { ac_client }
    }
}