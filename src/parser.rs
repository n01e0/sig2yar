pub mod hash;
pub mod logical;

use clap::ValueEnum;

#[derive(Debug, ValueEnum, Clone)]
pub enum DbType {
    Hash,
    Logical,
}
