pub mod scoped_node_key;
pub mod scoped_stale_node_index;

use schemadb::ColumnFamilyName;

pub const SCOPED_STALE_NODE_INDEX_CF_NAME: ColumnFamilyName = "scoped_stale_node_index";
pub const SCOPED_JELLYFISH_MERKLE_NODE_CF_NAME: ColumnFamilyName = "scoped_jellyfish_merkle_node";
