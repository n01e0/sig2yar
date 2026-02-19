use anyhow::{Result, anyhow};
use clap::{Parser, ValueEnum};
use sig2yar::parser::DbType;

#[derive(Debug, Parser)]
pub struct Args {
    /// Optional DB type. If omitted, sig2yar auto-detects from signature syntax.
    #[arg(value_name = "DB_TYPE_OR_SIGNATURE")]
    pub db_type_or_signature: String,

    /// Signature body (required when DB type is provided explicitly).
    #[arg(value_name = "SIGNATURE")]
    pub signature: Option<String>,

    /// Optional linked NDB signatures used to resolve logical macro-groups in strict subset mode.
    ///
    /// Example:
    ///   sig2yar logical '<lsig>' --ndb-context 'D1:0:$12:626262' --ndb-context 'D2:0:$12:636363'
    #[arg(long = "ndb-context", value_name = "NDB_SIG")]
    pub ndb_context: Vec<String>,

    /// Best-effort mode for logical lowering: replace strict-false guard tokens (`false`) with
    /// `true` where possible, to emit a more permissive representable subset.
    ///
    /// This intentionally relaxes strict-safe guarantees and may increase false positives.
    #[arg(
        long = "relax-strict-false",
        alias = "non-strict",
        default_value_t = false
    )]
    pub relax_strict_false: bool,
}

#[derive(Debug)]
pub struct ResolvedArgs {
    pub db_type: Option<DbType>,
    pub signature: String,
    pub ndb_context: Vec<String>,
    pub relax_strict_false: bool,
}

impl Args {
    pub fn resolve(self) -> Result<ResolvedArgs> {
        let Args {
            db_type_or_signature,
            signature,
            ndb_context,
            relax_strict_false,
        } = self;

        let (db_type, signature) = match signature {
            Some(signature) => {
                let db_type = DbType::from_str(&db_type_or_signature, false).map_err(|_| {
                    anyhow!(
                        "invalid db_type '{}'; pass a supported db type or omit it for auto-detect",
                        db_type_or_signature
                    )
                })?;
                (Some(db_type), signature)
            }
            None => (None, db_type_or_signature),
        };

        Ok(ResolvedArgs {
            db_type,
            signature,
            ndb_context,
            relax_strict_false,
        })
    }
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
        .expect("failed to parse args with repeated --ndb-context")
        .resolve()
        .expect("failed to resolve args");

        assert!(matches!(args.db_type, Some(DbType::Logical)));
        assert_eq!(args.signature, "Foo.Bar-1;Target:1;0&1;616161;${6-7}12$");
        assert_eq!(args.ndb_context.len(), 2);
        assert_eq!(args.ndb_context[0], "D1:0:$12:626262");
        assert_eq!(args.ndb_context[1], "D2:0:$12:636363");
    }

    #[test]
    fn parses_auto_mode_when_db_type_omitted() {
        let args = Args::try_parse_from(["sig2yar", "Foo.Bar-1;Target:1;0;41424344"])
            .expect("failed to parse signature-only args")
            .resolve()
            .expect("failed to resolve signature-only args");

        assert!(args.db_type.is_none());
        assert_eq!(args.signature, "Foo.Bar-1;Target:1;0;41424344");
    }

    #[test]
    fn parses_ldb_alias_for_logical() {
        let args = Args::try_parse_from(["sig2yar", "ldb", "Foo.Bar-1;Target:1;0;41424344"])
            .expect("failed to parse ldb alias")
            .resolve()
            .expect("failed to resolve ldb alias");

        assert!(matches!(args.db_type, Some(DbType::Logical)));
    }

    #[test]
    fn parses_hash_family_aliases() {
        for alias in ["hdb", "hsb", "mdb", "msb"] {
            let args = Args::try_parse_from([
                "sig2yar",
                alias,
                "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature",
            ])
            .unwrap_or_else(|_| panic!("failed to parse hash alias {alias}"))
            .resolve()
            .unwrap_or_else(|_| panic!("failed to resolve hash alias {alias}"));

            assert!(matches!(args.db_type, Some(DbType::Hash)));
        }
    }

    #[test]
    fn parses_relax_strict_false_alias() {
        let args = Args::try_parse_from([
            "sig2yar",
            "ldb",
            "Foo.Bar-1;Target:1;0;41424344",
            "--non-strict",
        ])
        .expect("failed to parse --non-strict alias")
        .resolve()
        .expect("failed to resolve --non-strict alias");

        assert!(args.relax_strict_false);
    }

    #[test]
    fn invalid_explicit_db_type_returns_error_on_resolve() {
        let err = Args::try_parse_from(["sig2yar", "not-a-db", "payload"])
            .expect("parse should succeed before db_type resolution")
            .resolve()
            .expect_err("resolve should fail for invalid explicit db_type");

        assert!(err.to_string().contains("invalid db_type"));
    }
}
