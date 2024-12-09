use crate::parser::DbType;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    pub db_type: DbType,
    pub signature: String,
}
