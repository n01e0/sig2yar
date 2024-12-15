use anyhow::{anyhow, Result};
use nom::{
    bytes::complete::{tag, take_while},
    combinator::{map, opt},
    sequence::tuple,
    IResult,
};

mod byte_comparison;
mod macro_subsignature;
mod pcre;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subsignature<'s> {
    pattern: &'s str,
    modifiers: Vec<Modifier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modifier {
    CaseInsensitive,
    Wide,
    Fullword,
    Ascii,
    Unknown(char),
}

impl<'s> Subsignature<'s> {
    pub fn parse(input: &'s str) -> Result<Subsignature<'s>> {
        parse_subsignature(&input)
            .map_err(|e| anyhow!("Can't parse Subsignature: {}", e))
            .map(|(_, subsig)| subsig)
    }
}

fn parse_modifier(input: &str) -> IResult<&str, Vec<Modifier>> {
    let (input, m) = take_while(|c: char| c.is_alphabetic())(input)?;
    let mut modifiers = Vec::new();

    for c in m.chars() {
        match c {
            'i' => modifiers.push(Modifier::CaseInsensitive),
            'w' => modifiers.push(Modifier::Wide),
            'f' => modifiers.push(Modifier::Fullword),
            'a' => modifiers.push(Modifier::Ascii),
            c => modifiers.push(Modifier::Unknown(c)),
        }
    }

    Ok((input, modifiers))
}

fn parse_subsignature<'s>(input: &'s str) -> IResult<&'s str, Subsignature<'s>> {
    let (remaining, (pattern, modifiers)) = tuple((
        take_while(|c: char| c.is_digit(16)),
        opt(map(tuple((tag("::"), parse_modifier)), |(_, mods)| mods)),
    ))(input)?;

    let modifiers = modifiers.unwrap_or_else(Vec::new);
    Ok((remaining, Subsignature { pattern, modifiers }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nocase() {
        let sig = Subsignature::parse("424242424242::i").unwrap();
        assert_eq!(
            Subsignature {
                pattern: "424242424242",
                modifiers: vec![Modifier::CaseInsensitive]
            },
            sig
        );
    }

    #[test]
    fn parse_fullword() {
        let sig = Subsignature::parse("68656c6c6f::f").unwrap();
        assert_eq!(
            Subsignature {
                pattern: "68656c6c6f",
                modifiers: vec![Modifier::Fullword]
            },
            sig
        );
    }

    #[test]
    fn parse_simple() {
        let sig = Subsignature::parse("41414141").unwrap();
        assert_eq!(
            Subsignature {
                pattern: "41414141",
                modifiers: vec![]
            },
            sig
        );
    }

    #[test]
    fn parse_nocase_wide_fullword_ascii() {
        let sig = Subsignature::parse("68656c6c6f::iwfa").unwrap();
        assert_eq!(
            Subsignature {
                pattern: "68656c6c6f",
                modifiers: vec![
                    Modifier::CaseInsensitive,
                    Modifier::Wide,
                    Modifier::Fullword,
                    Modifier::Ascii
                ]
            },
            sig
        );
    }
}
