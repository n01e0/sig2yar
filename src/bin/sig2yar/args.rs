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
}
