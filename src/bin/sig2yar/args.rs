use clap::Parser;
use sig2yar::parser::DbType;

#[derive(Debug, Parser)]
pub struct Args {
    pub db_type: DbType,
    pub signature: String,
}
