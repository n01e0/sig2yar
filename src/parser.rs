pub mod hash;
pub mod logical;
pub mod ndb;

use clap::ValueEnum;

#[derive(Debug, ValueEnum, Clone)]
pub enum DbType {
    Hash,
    Logical,
    Ndb,
}
