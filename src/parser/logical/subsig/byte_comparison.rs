use nom::{
    character::complete::{char, hex_digit1, one_of},
    combinator::{map, map_res, opt},
    multi::separated_list0,
    IResult, Parser,
};
use std::str::FromStr;

#[derive(Debug, Eq, PartialEq)]
pub enum Offset {
    Positive(usize),
    Negative(usize),
}

#[derive(Debug, Eq, PartialEq)]
pub enum Base {
    Hex,
    Decimal,
    Auto,
    Raw,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ByteOptions {
    base: Option<Base>,
    endian: Option<Endian>,
    evaluate: bool,
    num_bytes: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Comparison {
    Gt(usize),
    Lt(usize),
    Eq(usize),
}

#[derive(Debug, Eq, PartialEq)]
pub struct ByteComparison {
    subsigid_trigger: usize,
    offset: Offset,
    byte_options: ByteOptions,
    comparisons: Vec<Comparison>,
}

impl ByteComparison {
    pub fn parse(input: &str) -> anyhow::Result<ByteComparison> {
        match parse_byte_comparison(input) {
            Ok((_, byte_comparison)) => Ok(byte_comparison),
            Err(e) => Err(anyhow::anyhow!("Can't parse byte comparison: {}", e)),
        }
    }
}

fn parse_usize(input: &str) -> IResult<&str, usize> {
    map_res(hex_digit1, FromStr::from_str).parse(input)
}

fn parse_offset(input: &str) -> IResult<&str, Offset> {
    let (input, direction) = one_of("><")(input)?;
    let (input, _) = char(char::from(direction.to_ascii_lowercase()))(input)?;
    let (input, value) = parse_usize(input)?;
    let offset = if direction == '>' {
        Offset::Positive(value)
    } else {
        Offset::Negative(value)
    };
    Ok((input, offset))
}

fn parse_base(input: &str) -> IResult<&str, Option<Base>> {
    opt(map(one_of("hdai"), |c| match c {
        'h' => Base::Hex,
        'd' => Base::Decimal,
        'a' => Base::Auto,
        'i' => Base::Raw,
        _ => unreachable!(),
    }))
    .parse(input)
}

fn parse_endian(input: &str) -> IResult<&str, Option<Endian>> {
    opt(map(one_of("lb"), |c| match c {
        'l' => Endian::Little,
        'b' => Endian::Big,
        _ => unreachable!(),
    }))
    .parse(input)
}

fn parse_byte_options(input: &str) -> IResult<&str, ByteOptions> {
    let (input, base) = parse_base(input)?;
    let (input, endian) = parse_endian(input)?;
    let (input, evaluate) = map(opt(char('e')), |o| o.is_some()).parse(input)?;
    let (input, num_bytes) = parse_usize(input)?;
    Ok((
        input,
        ByteOptions {
            base,
            endian,
            evaluate,
            num_bytes,
        },
    ))
}

fn parse_comparison(input: &str) -> IResult<&str, Comparison> {
    let (input, op) = one_of("><=")(input)?;
    let (input, value) = parse_usize(input)?;
    let comparison = match op {
        '>' => Comparison::Gt(value),
        '<' => Comparison::Lt(value),
        '=' => Comparison::Eq(value),
        _ => unreachable!(),
    };
    Ok((input, comparison))
}

fn parse_comparisons(input: &str) -> IResult<&str, Vec<Comparison>> {
    separated_list0(char(','), parse_comparison).parse(input)
}

pub fn parse_byte_comparison(input: &str) -> IResult<&str, ByteComparison> {
    let (input, subsigid_trigger) = parse_usize(input)?;
    let (input, _) = char('(')(input)?;
    let (input, offset) = parse_offset(input)?;
    let (input, _) = char('#')(input)?;
    let (input, byte_options) = parse_byte_options(input)?;
    let (input, _) = char('#')(input)?;
    let (input, comparisons) = parse_comparisons(input)?;
    let (input, _) = char(')')(input)?;

    Ok((
        input,
        ByteComparison {
            subsigid_trigger,
            offset,
            byte_options,
            comparisons,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_byte_comparison_example() {
        let sig = ByteComparison::parse("0(>>26#ib2#>512)").unwrap();
        assert_eq!(
            ByteComparison {
                subsigid_trigger: 0,
                offset: Offset::Positive(26),
                byte_options: ByteOptions {
                    base: Some(Base::Raw),
                    endian: Some(Endian::Big),
                    evaluate: false,
                    num_bytes: 2
                },
                comparisons: vec![Comparison::Gt(512),],
            },
            sig
        );
    }
}
