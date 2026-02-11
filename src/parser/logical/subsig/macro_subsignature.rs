use anyhow::{anyhow, Result};
use nom::{
    character::complete::{char, hex_digit1},
    combinator::map_res,
    sequence::delimited,
    IResult, Parser,
};
use std::str::FromStr;

#[derive(Debug, Eq, PartialEq)]
pub struct MacroSubsignature {
    pub min: usize,
    pub max: usize,
    pub macroid: usize,
}

impl MacroSubsignature {
    pub fn parse(input: &str) -> Result<MacroSubsignature> {
        match parse_macro(input) {
            Ok((_, (min, max, macroid))) => Ok(MacroSubsignature { min, max, macroid }),
            Err(e) => Err(anyhow!("Can't parse MacroSubsignature: {}", e)),
        }
    }
}

fn parse_usize(input: &str) -> IResult<&str, usize> {
    map_res(hex_digit1, FromStr::from_str).parse(input)
}

pub fn parse_macro(input: &str) -> IResult<&str, (usize, usize, usize)> {
    delimited(
        char('$'),
        (
            delimited(char('{'), parse_usize, char('-')),
            parse_usize,
            delimited(char('}'), parse_usize, char('$')),
        ),
        nom::combinator::eof,
    )
    .parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_macro_example() {
        let sig = "${6-7}12$";
        let parsed = MacroSubsignature::parse(sig).unwrap();
        assert_eq!(
            MacroSubsignature {
                min: 6,
                max: 7,
                macroid: 12
            },
            parsed
        );
    }
}
