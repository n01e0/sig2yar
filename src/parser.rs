pub mod cbc;
pub mod cdb;
pub mod crb;
pub mod fp;
pub mod ftm;
pub mod hash;
pub mod idb;
pub mod logical;
pub mod ndb;
pub mod pdb;
pub mod sfp;
pub mod wdb;

use clap::ValueEnum;

#[derive(Debug, ValueEnum, Clone)]
pub enum DbType {
    Hash,
    Logical,
    Ndb,
    Idb,
    Cbc,
    Cdb,
    Crb,
    Pdb,
    Wdb,
    Ftm,
    Fp,
    Sfp,
}
