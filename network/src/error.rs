use std::fmt;
use std::fmt::Formatter;

#[derive(Debug)]
pub enum Error {
    NetworkError,

}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result { write!(f, "{}", self) }
}
