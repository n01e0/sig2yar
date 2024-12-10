use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::digit1,
    combinator::{map, map_res, opt},
    multi::many0,
    sequence::{pair, separated_pair},
    IResult,
};
use anyhow::{Result, anyhow};

#[derive(Debug, PartialEq)]
pub enum LogicalExpression {
    SubExpression(usize),
    And(Vec<LogicalExpression>),
    Or(Vec<LogicalExpression>),
    MatchCount(usize, usize),
    MultiMatchCount(usize, usize, usize),
    Gt(usize, usize),
    MultiGt(usize, usize, usize),
    Lt(usize, usize),
    MultiLt(usize, usize, usize),
}

impl LogicalExpression {
    pub fn parse(input: String) -> Result<LogicalExpression> {
        match parse_expression(&input) {
            Ok(res) => Ok(res.1),
            Err(e) => Err(anyhow!("Can't parse LogicalExpression: {}", e)),
        }
    }
}

fn parse_number(input: &str) -> IResult<&str, usize> {
    map_res(digit1, str::parse::<usize>)(input)
}

fn parse_sub_expression<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    map(parse_number, LogicalExpression::SubExpression)(input)
}

fn parse_comparison<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    let (input, a) = parse_number(input)?;
    let (input, op) = alt((tag("="), tag(">"), tag("<")))(input)?;
    let (input, (x, y)) = separated_pair(parse_number, opt(tag(",")), opt(parse_number))(input)?;

    match (op, y) {
        ("=", Some(y_val)) => Ok((input, LogicalExpression::MultiMatchCount(a, x, y_val))),
        ("=", None) => Ok((input, LogicalExpression::MatchCount(a, x))),
        (">", Some(y_val)) => Ok((input, LogicalExpression::MultiGt(a, x, y_val))),
        (">", None) => Ok((input, LogicalExpression::Gt(a, x))),
        ("<", Some(y_val)) => Ok((input, LogicalExpression::MultiLt(a, x, y_val))),
        ("<", None) => Ok((input, LogicalExpression::Lt(a, x))),
        _ => unreachable!(),
    }
}


fn parse_single_expression<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    alt((
        parse_comparison,
        parse_sub_expression,
    ))(input)
}

fn parse_expression<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    let (input, mut initial) = parse_single_expression(input)?;
    let (input, ops) = many0(pair(alt((tag("&"), tag("|"))), parse_single_expression))(input)?;

    for (op, expr) in ops {
        match op {
            "&" => {
                if let LogicalExpression::And(mut vec) = initial {
                    vec.push(expr);
                    initial = LogicalExpression::And(vec);
                } else {
                    initial = LogicalExpression::And(vec![initial, expr]);
                }
            }
            "|" => {
                if let LogicalExpression::Or(mut vec) = initial {
                    vec.push(expr);
                    initial = LogicalExpression::Or(vec);
                } else {
                    initial = LogicalExpression::Or(vec![initial, expr]);
                }
            }
            _ => unreachable!(),
        }
    }

    Ok((input, initial))
}

#[cfg(test)]
mod tests {
    use crate::parser::logical::expression::{
        parse_expression,
        LogicalExpression::{
            SubExpression,
            And,
            MultiMatchCount
        }
    };

    #[test]
    fn parse_only_and() {
        let expression = "0&1&2&3&4";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(And(vec![SubExpression(0), SubExpression(1), SubExpression(2), SubExpression(3), SubExpression(4)]), parsed.1);
    }

    #[test]
    fn parse_multi_match() {
        let expression = "1=2,3";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(MultiMatchCount(1,2,3), parsed.1);
    }
}

