pub mod cbc;
pub mod cdb;
pub mod cfg;
pub mod crb;
pub mod fp;
pub mod ftm;
pub mod hash;
pub mod hdu;
pub mod hsu;
pub mod idb;
pub mod ign;
pub mod ign2;
pub mod imp;
pub mod info;
pub mod ldu;
pub mod logical;
pub mod mdu;
pub mod msu;
pub mod ndb;
pub mod ndu;
pub mod pdb;
pub mod sfp;
pub mod wdb;

use clap::ValueEnum;

#[derive(Debug, ValueEnum, Clone)]
pub enum DbType {
    #[value(alias = "hdb", alias = "hsb", alias = "mdb", alias = "msb")]
    Hash,
    Imp,
    #[value(alias = "ldb")]
    Logical,
    Hdu,
    Hsu,
    Ldu,
    Mdu,
    Msu,
    Ndb,
    Ndu,
    Idb,
    Cbc,
    Cdb,
    Cfg,
    Crb,
    Pdb,
    Wdb,
    Ftm,
    Fp,
    Sfp,
    Ign,
    Ign2,
    Info,
}
