use nom::{
    branch::alt,
    bytes::complete::take_while,
    character::complete::{char, none_of},
    combinator::{map, recognize},
    multi::many0,
    sequence::preceded,
    IResult,
};

use crate::parser::logical::expression::{parse_expression, LogicalExpression};

#[derive(Debug, Eq, PartialEq)]
pub enum Flag {
    Global,
    Rolling,
    Encompass,
    Caseless,
    Dotall,
    Multiline,
    Extended,
    Anchored,
    DollarEnodnly,
    Ungreedy,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PCRE<'p> {
    pub trigger: LogicalExpression,
    pub pcre: &'p str,
    pub flag: Vec<Flag>,
}

fn parse_flags(input: &str) -> IResult<&str, Vec<Flag>> {
    map(
        many0(alt((
            map(char('g'), |_| Flag::Global),
            map(char('r'), |_| Flag::Rolling),
            map(char('E'), |_| Flag::Encompass),
            map(char('i'), |_| Flag::Caseless),
            map(char('s'), |_| Flag::Dotall),
            map(char('m'), |_| Flag::Multiline),
            map(char('e'), |_| Flag::Extended),
            map(char('a'), |_| Flag::Anchored),
            map(char('d'), |_| Flag::DollarEnodnly),
            map(char('U'), |_| Flag::Ungreedy),
        ))),
        |flags| flags,
    )(input)
}

fn parse_pcre<'p>(input: &'p str) -> IResult<&'p str, PCRE<'p>> {
    let (input, trigger) = take_while(|c: char| c != '/')(input)?;
    let trigger = parse_expression(trigger)?.1;
    let (input, _) = char('/')(input)?;
    let (input, pattern) = recognize(many0(alt((
        preceded(char('\\'), none_of("")),
        none_of("\\/"),
    ))))(input)?;
    let (input, _) = char('/')(input)?;
    let (input, flags) = parse_flags(input)?;

    Ok((
        input,
        PCRE {
            trigger,
            pcre: pattern,
            flag: flags,
        },
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parser::logical::LogicalExpression::*;

    #[test]
    fn parse_pcre_sample() {
        let parsed = parse_pcre("0&1&2/\\/bin\\/clamav/ge").unwrap();
        assert_eq!(
            PCRE {
                trigger: And(vec![SubExpression(0), SubExpression(1), SubExpression(2)]),
                pcre: "\\/bin\\/clamav",
                flag: vec![Flag::Global, Flag::Extended]
            },
            parsed.1,
        );

        let parsed = parse_pcre("0/^\\x2e(only|lowerBound|upperBound|bound)\\x28.*?\\x29.*?\\x2e(lower|upper|lowerOpen|upperOpen)/smi").unwrap();
        assert_eq!(
            PCRE {
                trigger: SubExpression(0),
                pcre: "^\\x2e(only|lowerBound|upperBound|bound)\\x28.*?\\x29.*?\\x2e(lower|upper|lowerOpen|upperOpen)",
                flag: vec![Flag::Dotall, Flag::Multiline, Flag::Caseless]
            },
            parsed.1
        );
    }
}
