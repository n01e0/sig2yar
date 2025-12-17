use anyhow::{anyhow, Result};

mod byte_comparison;
mod fuzzy_img;
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
        if input.is_empty() {
            return Err(anyhow!("Subsignature is empty"));
        }

        let (pattern, modifiers) = split_modifiers(input);
        Ok(Subsignature { pattern, modifiers })
    }
}

fn parse_modifier_chars(input: &str) -> Vec<Modifier> {
    let mut modifiers = Vec::new();

    for c in input.chars() {
        match c {
            'i' => modifiers.push(Modifier::CaseInsensitive),
            'w' => modifiers.push(Modifier::Wide),
            'f' => modifiers.push(Modifier::Fullword),
            'a' => modifiers.push(Modifier::Ascii),
            c => modifiers.push(Modifier::Unknown(c)),
        }
    }

    modifiers
}

fn split_modifiers<'s>(input: &'s str) -> (&'s str, Vec<Modifier>) {
    if let Some((pattern, suffix)) = input.rsplit_once("::") {
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_alphabetic()) {
            return (pattern, parse_modifier_chars(suffix));
        }
    }

    (input, Vec::new())
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
