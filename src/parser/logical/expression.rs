use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{digit1, multispace0},
    combinator::{map, map_res, opt},
    multi::separated_list0,
    sequence::{delimited, preceded},
    IResult,
};

#[derive(Debug, PartialEq)]
pub enum LogicalExpression {
    SubExpression(usize),
    And(Vec<LogicalExpression>),
    Or(Vec<LogicalExpression>),
    MatchCount(Box<LogicalExpression>, usize),
    MultiMatchCount(Box<LogicalExpression>, usize, usize),
    Gt(Box<LogicalExpression>, usize),
    MultiGt(Box<LogicalExpression>, usize, usize),
    Lt(Box<LogicalExpression>, usize),
    MultiLt(Box<LogicalExpression>, usize, usize),
}

impl LogicalExpression {
    pub fn parse(input: String) -> anyhow::Result<LogicalExpression> {
        match parse_expression(&input) {
            Ok(res) => Ok(res.1),
            Err(e) => Err(anyhow::anyhow!("Can't parse LogicalExpression: {}", e)),
        }
    }
}

fn parse_number<'i>(input: &'i str) -> IResult<&'i str, usize> {
    map_res(digit1, str::parse::<usize>)(input)
}

fn parse_sub_expression<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    alt((
        map(parse_number, LogicalExpression::SubExpression),
        parse_paren_expression,
    ))(input)
}

fn parse_paren_expression<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    delimited(
        preceded(multispace0, tag("(")),
        parse_expression,
        preceded(multispace0, tag(")")),
    )(input)
}

fn parse_comparison<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    let (input, expr) = parse_sub_expression(input)?;
    let (input, op) = opt(alt((tag("="), tag(">"), tag("<"))))(input)?;
    if let Some(op) = op {
        let (input, x) = parse_number(input)?;
        let (input, y) = opt(preceded(tag(","), parse_number))(input)?;
        match (op, y) {
            ("=", Some(y_val)) => Ok((
                input,
                LogicalExpression::MultiMatchCount(Box::new(expr), x, y_val),
            )),
            ("=", None) => Ok((input, LogicalExpression::MatchCount(Box::new(expr), x))),
            (">", Some(y_val)) => Ok((input, LogicalExpression::MultiGt(Box::new(expr), x, y_val))),
            (">", None) => Ok((input, LogicalExpression::Gt(Box::new(expr), x))),
            ("<", Some(y_val)) => Ok((input, LogicalExpression::MultiLt(Box::new(expr), x, y_val))),
            ("<", None) => Ok((input, LogicalExpression::Lt(Box::new(expr), x))),
            _ => unreachable!(),
        }
    } else {
        Ok((input, expr))
    }
}

fn parse_single_expression<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    parse_comparison(input)
}

fn parse_expression<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    parse_and_expression(input)
}

fn parse_and_expression<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    let (input, exprs) =
        separated_list0(preceded(multispace0, tag("&")), parse_or_expression)(input)?;
    if exprs.len() == 1 {
        Ok((input, exprs.into_iter().next().unwrap()))
    } else {
        Ok((input, LogicalExpression::And(exprs)))
    }
}

fn parse_or_expression<'i>(input: &'i str) -> IResult<&'i str, LogicalExpression> {
    let (input, exprs) =
        separated_list0(preceded(multispace0, tag("|")), parse_single_expression)(input)?;
    if exprs.len() == 1 {
        Ok((input, exprs.into_iter().next().unwrap()))
    } else {
        Ok((input, LogicalExpression::Or(exprs)))
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::logical::expression::{
        parse_expression,
        LogicalExpression::{
            And, Gt, Lt, MatchCount, MultiGt, MultiLt, MultiMatchCount, Or, SubExpression,
        },
    };

    #[test]
    fn parse_only_and() {
        let expression = "0&1&2&3&4";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![
                SubExpression(0),
                SubExpression(1),
                SubExpression(2),
                SubExpression(3),
                SubExpression(4)
            ]),
            parsed.1
        );
    }

    #[test]
    fn parse_only_or() {
        let expression = "(0|1|2|3|4|5|6|7|8|9|10|11)";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(Or((0..=11).map(|n| SubExpression(n)).collect()), parsed.1)
    }

    #[test]
    fn parse_multi_match() {
        let expression = "1=2,3";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(MultiMatchCount(Box::new(SubExpression(1)), 2, 3), parsed.1);

        let expression = "(1&2)=2,2";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            MultiMatchCount(
                Box::new(And(vec![SubExpression(1), SubExpression(2)])),
                2,
                2
            ),
            parsed.1
        );
    }

    #[test]
    fn parse_and_or() {
        let expression = "(0&1&2&3)&(4|1)";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![
                And(vec![
                    SubExpression(0),
                    SubExpression(1),
                    SubExpression(2),
                    SubExpression(3)
                ]),
                Or(vec![SubExpression(4), SubExpression(1)])
            ]),
            parsed.1
        )
    }

    #[test]
    fn parse_gt() {
        let expression = "(0>20)&1&2";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![
                Gt(Box::new(SubExpression(0)), 20),
                SubExpression(1),
                SubExpression(2)
            ]),
            parsed.1
        )
    }

    #[test]
    fn parse_multi() {
        let expression = "((0|1|2)>5,2)&(3|1)";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![
                MultiGt(
                    Box::new(Or(vec![
                        SubExpression(0),
                        SubExpression(1),
                        SubExpression(2)
                    ])),
                    5,
                    2
                ),
                Or(vec![SubExpression(3), SubExpression(1)])
            ],),
            parsed.1
        );
        let expression = "((0|1|2)<5,2)&(3|1)";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![
                MultiLt(
                    Box::new(Or(vec![
                        SubExpression(0),
                        SubExpression(1),
                        SubExpression(2)
                    ])),
                    5,
                    2
                ),
                Or(vec![SubExpression(3), SubExpression(1)])
            ],),
            parsed.1
        )
    }

    #[test]
    fn parse_count() {
        let expression = "((0|1|2|3)=2)&(4|1)";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![
                MatchCount(
                    Box::new(Or(vec![
                        SubExpression(0),
                        SubExpression(1),
                        SubExpression(2),
                        SubExpression(3)
                    ])),
                    2
                ),
                Or(vec![SubExpression(4), SubExpression(1)])
            ]),
            parsed.1
        );
    }

    #[test]
    fn parse_and() {
        let expression = "((0|1)&(2|3))&4";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![
                And(vec![
                    Or(vec![SubExpression(0), SubExpression(1)]),
                    Or(vec![SubExpression(2), SubExpression(3)])
                ]),
                SubExpression(4)
            ]),
            parsed.1
        );

        let expression = "0>2&1";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![Gt(Box::new(SubExpression(0)), 2), SubExpression(1)]),
            parsed.1
        )
    }

    #[test]
    fn parse_doc_trojan() {
        let expression = "0&1>50";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![SubExpression(0), Gt(Box::new(SubExpression(1)), 50)],),
            parsed.1
        )
    }

    #[test]
    fn parse_obfus_macro() {
        let expression = "0&1>200&2<1000&3>50&4>200";
        let parsed = parse_expression(expression).unwrap();
        assert_eq!(
            And(vec![
                SubExpression(0),
                Gt(Box::new(SubExpression(1)), 200),
                Lt(Box::new(SubExpression(2)), 1000),
                Gt(Box::new(SubExpression(3)), 50),
                Gt(Box::new(SubExpression(4)), 200)
            ]),
            parsed.1
        )
    }
}
