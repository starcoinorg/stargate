#[test]
fn graph_test() {
    use crate::edge::Edge;
    use crate::graph_store::GraphStore;
    use crate::vertex::{Type, Vertex};
    use libra_types::account_address::AccountAddress;

    libra_logger::init_for_e2e_testing();

    let vertex1 = Vertex::new(AccountAddress::random(), Type("a".to_string()));
    let vertex2 = Vertex::new(AccountAddress::random(), Type("b".to_string()));
    let vertex3 = Vertex::new(AccountAddress::random(), Type("c".to_string()));

    let edge1 = Edge::new(vertex1.clone(), Type("a".to_string()), vertex2.clone());
    let edge2 = Edge::new(vertex2.clone(), Type("a".to_string()), vertex3.clone());

    let graph_store = GraphStore::new(false, None).unwrap();
    graph_store.put_edge(&edge1, 1, false).unwrap();
    graph_store.put_edge(&edge2, 1, false).unwrap();

    graph_store.print_nodes(&vertex1);
    let result = graph_store.find_path(&vertex1, &vertex3);

    assert_eq!(result.unwrap().expect("should have").len(), 3);
}

#[test]
fn graph_storage_test() {
    use crate::edge::Edge;
    use crate::graph_store::GraphStore;
    use crate::vertex::{Type, Vertex};
    extern crate rand;
    use libra_logger::prelude::*;
    use libra_types::account_address::AccountAddress;
    use rand::Rng;
    use std::path::Path;

    libra_logger::init_for_e2e_testing();

    let mut rng = rand::thread_rng();

    let vertex1 = Vertex::new(AccountAddress::random(), Type("a".to_string()));
    let vertex2 = Vertex::new(AccountAddress::random(), Type("b".to_string()));
    let vertex3 = Vertex::new(AccountAddress::random(), Type("c".to_string()));

    let edge1 = Edge::new(vertex1.clone(), Type("a".to_string()), vertex2.clone());
    let edge2 = Edge::new(vertex2.clone(), Type("a".to_string()), vertex3.clone());

    let dir_str = format!("/tmp/data/{}", rng.gen::<u32>());

    info!("tmp dir is {}", dir_str);
    let dir = Path::new(&dir_str);
    let graph_store = GraphStore::new(true, Some(dir.clone())).unwrap();
    graph_store.put_edge(&edge1, 1, false).unwrap();
    graph_store.put_edge(&edge2, 1, false).unwrap();

    graph_store.print_nodes(&vertex1);

    let result = graph_store.find_path(&vertex1, &vertex3);

    assert_eq!(result.unwrap().expect("should have").len(), 3);
    drop(graph_store);

    info!("graph db droped.");

    let graph_store = GraphStore::new(true, Some(dir)).unwrap();
    graph_store.print_nodes(&vertex1);

    let result = graph_store.find_path(&vertex1, &vertex3);

    assert_eq!(result.unwrap().expect("should have").len(), 3);
}
