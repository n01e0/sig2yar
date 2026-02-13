pub mod cdb;
pub mod hash;
pub mod idb;
pub mod logical;
pub mod ndb;

use clap::ValueEnum;

#[derive(Debug, ValueEnum, Clone)]
pub enum DbType {
    Hash,
    Logical,
    Ndb,
    Idb,
    Cdb,
}
