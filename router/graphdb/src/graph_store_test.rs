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
fn graph_path_all_test() {
    use crate::edge::Edge;
    use crate::graph_store::GraphStore;
    use crate::vertex::{Type, Vertex};
    use libra_types::account_address::AccountAddress;

    libra_logger::init_for_e2e_testing();

    let vertex1 = Vertex::new(AccountAddress::random(), Type("a".to_string()));
    let vertex2 = Vertex::new(AccountAddress::random(), Type("b".to_string()));
    let vertex3 = Vertex::new(AccountAddress::random(), Type("c".to_string()));
    let vertex4 = Vertex::new(AccountAddress::random(), Type("d".to_string()));
    let vertex5 = Vertex::new(AccountAddress::random(), Type("e".to_string()));
    let vertex6 = Vertex::new(AccountAddress::random(), Type("f".to_string()));
    let vertex7 = Vertex::new(AccountAddress::random(), Type("g".to_string()));

    let edge1 = Edge::new(vertex1.clone(), Type("a".to_string()), vertex2.clone());
    let edge2 = Edge::new(vertex2.clone(), Type("a".to_string()), vertex3.clone());
    let edge3 = Edge::new(vertex3.clone(), Type("a".to_string()), vertex7.clone());
    let edge4 = Edge::new(vertex1.clone(), Type("a".to_string()), vertex3.clone());
    let edge5 = Edge::new(vertex3.clone(), Type("a".to_string()), vertex5.clone());
    let edge6 = Edge::new(vertex5.clone(), Type("a".to_string()), vertex7.clone());
    let edge7 = Edge::new(vertex1.clone(), Type("a".to_string()), vertex4.clone());
    let edge8 = Edge::new(vertex3.clone(), Type("a".to_string()), vertex6.clone());
    let edge9 = Edge::new(vertex6.clone(), Type("a".to_string()), vertex7.clone());
    let edge10 = Edge::new(vertex4.clone(), Type("a".to_string()), vertex7.clone());

    let graph_store = GraphStore::new(false, None).unwrap();
    graph_store.put_edge(&edge1, 1, false).unwrap();
    graph_store.put_edge(&edge2, 1, false).unwrap();
    graph_store.put_edge(&edge3, 1, false).unwrap();
    graph_store.put_edge(&edge4, 1, false).unwrap();
    graph_store.put_edge(&edge5, 1, false).unwrap();
    graph_store.put_edge(&edge6, 1, false).unwrap();
    graph_store.put_edge(&edge7, 1, false).unwrap();
    graph_store.put_edge(&edge8, 1, false).unwrap();
    graph_store.put_edge(&edge9, 1, false).unwrap();
    graph_store.put_edge(&edge10, 1, false).unwrap();

    graph_store.print_nodes(&vertex1);
    let result = graph_store
        .find_all_path(&vertex1, &vertex7, 5)
        .unwrap()
        .expect("should have");

    assert_eq!(result.len(), 7);
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
