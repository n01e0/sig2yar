use nom::{
    bytes::complete::{tag, take_while1},
    character::complete::{char, digit1},
    combinator::{map_res, opt},
    sequence::preceded,
    IResult, Parser,
};
use std::str::FromStr;

const DEFAULT_DISTANCE: usize = 0;

#[derive(Debug, PartialEq, Eq)]
pub struct FuzzyImg<'f> {
    pub hash: &'f str,
    pub distance: usize,
}

fn parse_fuzzy_img(input: &str) -> IResult<&str, FuzzyImg<'_>> {
    let (input, _) = tag("fuzzy_img#")(input)?;
    let (input, hash) = take_while1(|c: char| c.is_alphanumeric())(input)?;

    let (input, distance) = opt(preceded(
        char('#'),
        map_res(digit1, |dist_str: &str| usize::from_str(dist_str)),
    ))
    .parse(input)?;

    Ok((
        input,
        FuzzyImg {
            hash,
            distance: distance.unwrap_or(DEFAULT_DISTANCE),
        },
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_fuzzy_img_example_with_distance() {
        let parsed = parse_fuzzy_img("fuzzy_img#af2ad01ed42993c7#0").unwrap();
        assert_eq!(
            FuzzyImg {
                hash: "af2ad01ed42993c7",
                distance: 0
            },
            parsed.1
        );
    }

    #[test]
    fn parse_fuzzy_img_example_without_distance() {
        let parsed = parse_fuzzy_img("fuzzy_img#af2ad01ed42993c7").unwrap();
        assert_eq!(
            FuzzyImg {
                hash: "af2ad01ed42993c7",
                distance: 0
            },
            parsed.1
        );
    }
}
