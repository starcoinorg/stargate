use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::fs;
use std::fs::File;
use std::io::prelude::*;

#[derive(Debug, Deserialize, PartialEq, Serialize, Clone)]
struct KeyConf {
    pri_file: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize, Clone)]
struct ServerConf {
    host: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize, Clone)]
struct ChainConf {
    rpc_host: Option<String>,
    rpc_port: Option<u16>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize, Clone)]
pub struct FaucetConf {
    key_conf: Option<KeyConf>,
    ser_conf: Option<ServerConf>,
    chain_conf: Option<ChainConf>,
}

impl FaucetConf {
    pub(crate) fn pri_file(&self) -> Option<String> {
        match self.key_conf.clone() {
            Some(key_conf) => key_conf.pri_file,
            _ => None,
        }
    }

    pub fn server(&self) -> (String, u16) {
        let ser_conf = self.ser_conf.clone().expect("server conf is none.");
        let host = ser_conf.host.expect("address is none.");
        let port = ser_conf.port.expect("port is none.");
        (host, port)
    }

    pub(crate) fn chain(&self) -> (String, u16) {
        let ser_conf = self.chain_conf.clone().expect("server conf is none.");
        let host = ser_conf.rpc_host.expect("address is none.");
        let port = ser_conf.rpc_port.expect("port is none.");
        (host, port)
    }

    pub fn set_key_file(&mut self, key_file: String) {
        let key_conf = KeyConf {
            pri_file: Some(key_file),
        };
        self.key_conf = Some(key_conf);
    }
}

pub fn load_faucet_conf(path: String) -> FaucetConf {
    let file_path = "conf/faucet.toml";

    let mut file = match File::open(format!("{}/{}", path, file_path)) {
        Ok(f) => f,
        Err(e) => panic!("no such file {} exception:{}", file_path, e),
    };
    let mut str_val = String::new();
    match file.read_to_string(&mut str_val) {
        Ok(s) => s,
        Err(e) => panic!("Error Reading file: {}", e),
    };
    toml::from_str(&str_val).unwrap()
}

#[test]
fn test_faucet_conf() {
    let current_dir = PathBuf::from("./");
    println!("{:?}", fs::canonicalize(&current_dir));
    //    let path = ;
    let conf = load_faucet_conf(
        fs::canonicalize(&current_dir)
            .expect("path err.")
            .to_str()
            .expect("str err.")
            .to_string(),
    );
    println!("conf: {:?}", conf);
}
