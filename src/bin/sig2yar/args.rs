use clap::Parser;
use sig2yar::parser::DbType;

#[derive(Debug, Parser)]
pub struct Args {
    pub db_type: DbType,
    pub signature: String,

    /// Optional linked NDB signatures used to resolve logical macro-groups in strict subset mode.
    ///
    /// Example:
    ///   sig2yar logical '<lsig>' --ndb-context 'D1:0:$12:626262' --ndb-context 'D2:0:$12:636363'
    #[arg(long = "ndb-context", value_name = "NDB_SIG")]
    pub ndb_context: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser;
    use sig2yar::parser::DbType;

    #[test]
    fn parses_repeated_ndb_context_args() {
        let args = Args::try_parse_from([
            "sig2yar",
            "logical",
            "Foo.Bar-1;Target:1;0&1;616161;${6-7}12$",
            "--ndb-context",
            "D1:0:$12:626262",
            "--ndb-context",
            "D2:0:$12:636363",
        ])
        .expect("failed to parse args with repeated --ndb-context");

        assert_eq!(args.ndb_context.len(), 2);
        assert_eq!(args.ndb_context[0], "D1:0:$12:626262");
        assert_eq!(args.ndb_context[1], "D2:0:$12:636363");
    }

    #[test]
    fn parses_ldb_alias_for_logical() {
        let args = Args::try_parse_from([
            "sig2yar",
            "ldb",
            "Foo.Bar-1;Target:1;0;41424344",
        ])
        .expect("failed to parse ldb alias");

        assert!(matches!(args.db_type, DbType::Logical));
    }

    #[test]
    fn parses_hash_family_aliases() {
        for alias in ["hdb", "hsb", "mdb", "msb"] {
            let args = Args::try_parse_from([
                "sig2yar",
                alias,
                "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature",
            ])
            .unwrap_or_else(|_| panic!("failed to parse hash alias {alias}"));

            assert!(matches!(args.db_type, DbType::Hash));
        }
    }
}
