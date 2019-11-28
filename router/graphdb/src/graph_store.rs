use crate::edge::Edge;
use crate::storage::{EdgeSchema, Storage, VertexSchema};
use crate::vertex::Vertex;
use failure::prelude::*;
use libra_logger::prelude::*;
use petgraph::algo::astar;
use petgraph::prelude::*;
use petgraph::stable_graph::{EdgeIndex, NodeIndex};
use petgraph::visit::Walker;
use petgraph::Graph;
use schemadb::ReadOptions;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;

pub struct GraphStore {
    graph: RefCell<Graph<Vertex, Edge, Undirected>>,
    node_index_map: RefCell<HashMap<Vertex, NodeIndex>>,
    index_node_map: RefCell<HashMap<NodeIndex, Vertex>>,
    edge_index_map: RefCell<HashMap<Edge, EdgeIndex>>,
    persist_data: bool,
    storage: Option<Storage>,
}

impl GraphStore {
    pub fn new(persist_data: bool, path: Option<&Path>) -> Result<Self> {
        if persist_data {
            let storage = Storage::new(path.expect("should have path"));

            let result = Self {
                graph: RefCell::new(Graph::new_undirected()),
                node_index_map: RefCell::new(HashMap::new()),
                index_node_map: RefCell::new(HashMap::new()),
                edge_index_map: RefCell::new(HashMap::new()),
                persist_data,
                storage: Some(storage),
            };

            result.recovery_data()?;
            return Ok(result);
        }
        Ok(Self {
            graph: RefCell::new(Graph::new_undirected()),
            node_index_map: RefCell::new(HashMap::new()),
            index_node_map: RefCell::new(HashMap::new()),
            edge_index_map: RefCell::new(HashMap::new()),
            persist_data,
            storage: None,
        })
    }

    pub fn recovery_data(&self) -> Result<()> {
        let mut edge_iter = self
            .storage
            .as_ref()
            .expect("should have edge storage")
            .iter::<EdgeSchema>(ReadOptions::default())?;

        while let Some(Ok((key, value))) = edge_iter.next() {
            self.put_edge(&key, value, true)?;
        }

        Ok(())
    }

    pub fn put_vertex(&self, node: &Vertex) -> Result<NodeIndex> {
        if self.persist_data {
            self.storage
                .as_ref()
                .expect("should have vertex storage")
                .put::<VertexSchema>(&node.id, node)?;
        }
        let node_index = self.graph.borrow_mut().add_node(node.clone());
        self.node_index_map
            .borrow_mut()
            .insert(node.clone(), node_index);
        self.index_node_map
            .borrow_mut()
            .insert(node_index, node.clone());

        Ok(node_index)
    }

    pub fn put_edge(&self, edge: &Edge, weight: u64, memory_only: bool) -> Result<EdgeIndex> {
        let start_index;
        let end_index;

        let has_start = self.node_index_map.borrow().contains_key(&edge.inbound_id);
        if has_start {
            start_index = self
                .node_index_map
                .borrow()
                .get(&edge.inbound_id)
                .expect("should have ")
                .clone();
        } else {
            start_index = self.put_vertex(&edge.inbound_id)?;
        }

        let has_start = self.node_index_map.borrow().contains_key(&edge.outbound_id);
        if has_start {
            end_index = self
                .node_index_map
                .borrow()
                .get(&edge.outbound_id)
                .expect("should have ")
                .clone();
        } else {
            end_index = self.put_vertex(&edge.outbound_id)?;
        }

        let edge_index = self
            .graph
            .borrow_mut()
            .add_edge(start_index, end_index, edge.clone());

        self.edge_index_map
            .borrow_mut()
            .insert(edge.clone(), edge_index);
        if self.persist_data && !memory_only {
            self.storage
                .as_ref()
                .expect("should have edege storage")
                .put::<EdgeSchema>(edge, &weight)?;
        }

        Ok(edge_index)
    }

    pub fn remove_vertex(&self, node: &Vertex) -> Result<()> {
        match self.node_index_map.borrow().get(node) {
            Some(node_index) => {
                self.graph.borrow_mut().remove_node(*node_index);
                self.index_node_map.borrow_mut().remove(node_index);
                self.node_index_map.borrow_mut().remove(node);
            }
            None => {
                info!("no such node in map {:?}", node);
            }
        }
        self.storage
            .as_ref()
            .expect("should have vertex storage")
            .delete::<VertexSchema>(&node.id)?;
        Ok(())
    }

    pub fn remove_edge(&self, edge: &Edge) -> Result<()> {
        match self.edge_index_map.borrow().get(edge) {
            Some(edge_index) => {
                self.graph.borrow_mut().remove_edge(*edge_index);
            }
            None => {
                info!("no such edge in map {:?}", edge);
            }
        }
        self.storage
            .as_ref()
            .expect("should have edge storage")
            .delete::<EdgeSchema>(edge)?;
        Ok(())
    }

    pub fn find_path(&self, start_node: &Vertex, end_node: &Vertex) -> Result<Option<Vec<Vertex>>> {
        let start_index;
        let end_index;
        match self.node_index_map.borrow().get(&start_node) {
            Some(index) => {
                start_index = index.clone();
            }
            None => {
                bail!("no such node {:?}", start_node);
            }
        }

        match self.node_index_map.borrow().get(&end_node) {
            Some(index) => {
                end_index = index.clone();
            }
            None => {
                bail!("no such node {:?}", end_node);
            }
        }

        let path = astar(
            &(*self.graph.borrow()),
            start_index,
            |finish| finish == end_index,
            |_| 1,
            |_| 1,
        );

        match path {
            Some((_count, node_indexes)) => {
                let mut result = Vec::new();
                for node_index in node_indexes.iter() {
                    let node = self
                        .index_node_map
                        .borrow()
                        .get(node_index)
                        .expect(
                            format!("should have such node with index {:?}", node_index).as_str(),
                        )
                        .clone();
                    result.push(node);
                }
                return Ok(Some(result));
            }
            None => {
                bail!("no path from {:?} to {:?}", start_node, end_node);
            }
        };
    }

    pub fn print_nodes(&self, start_node: &Vertex) {
        let mut start_index = NodeIndex::new(0);
        match self.node_index_map.borrow().get(&start_node) {
            Some(index) => {
                start_index = index.clone();
            }
            None => {
                warn!("no such node {:?}", start_node);
            }
        }

        for no in Bfs::new(&(*self.graph.borrow()), start_index).iter(&(*self.graph.borrow())) {
            info!("Visit {:?} = {:?}", no, self.graph.borrow().node_weight(no));
        }
    }
}

impl Drop for GraphStore {
    fn drop(&mut self) {
        if self.persist_data {
            drop(self.storage.take());
        }
    }
}
