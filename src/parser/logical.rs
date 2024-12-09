use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Display;
use std::ops::Range;

#[derive(Debug)]
pub struct LogicalSignature<'p> {
    pub name: &'p str,
    pub target_description: TargetDescription<'p>,
    pub logical_expression: &'p str,
    pub sigs: Vec<&'p str>,
}

#[derive(Debug)]
struct TargetDescription<'t> {
    engine: Range<u32>,
    target: TargetType,
    file_size: Option<Range::<usize>>,
    entry_point: Option<usize>,
    number_of_sections: Option<usize>,
    container: Option<&'t str>,
    intermediates: Option<&'t str>,
    icon_group1: Option<Range<usize>>,
    icon_group2: Option<Range<usize>>,
}

#[derive(Debug)]
pub enum TargetType {
    Any,
    PE,
    OLE2,
    HTML,
    Mail,
    Graphics,
    ELF,
    ASCII,
    Unused,
    MachO,
    PDF,
    Flash,
    Java,
}

impl<'t> TargetDescription<'t> {
    pub fn parse(target_description: &'t str) -> Result<Self> {
        let parts = target_description.split(',').collect::<Vec<&str>>();
        if parts.len() < 2 {
            return Err(anyhow::anyhow!(
                "Invalid target description: not enough parts"
            ));
        }

        let mut map = HashMap::new();
        for pair in parts {
            let mut split_iter = pair.split(':');
            if let (Some(key), Some(value)) = (split_iter.next(), split_iter.next()) {
                map.insert(key, value);
            }
        }

        let engine = parse_range(
            map.get("Engine")
                .with_context(|| "Can't find Engine block")?,
        )?;
        let target = TargetType::try_from(
            map.get("Target")
                .with_context(|| "Can't find Target Type block")?
                .parse::<u8>().with_context(|| "Can't parse TargetType number")?,
        )
        .with_context(|| "Can't parse TargetType")?;

        Ok({
            TargetDescription {
                engine,
                target,
                file_size: map.get("FileSize").and_then(|n| parse_range::<usize>(n).ok()),
                entry_point: map.get("EntryPoint").and_then(|n| n.parse::<usize>().ok()),
                number_of_sections: map.get("NumberOfSections").and_then(|n| n.parse::<usize>().ok()),
                container: map.get("Container").map(|v| *v),
                intermediates: map.get("Intermediates").map(|v| *v),
                icon_group1: map.get("IconGroup1").and_then(|n| parse_range::<usize>(n).ok()),
                icon_group2: map.get("IconGroup2").and_then(|n| parse_range::<usize>(n).ok()),
            }
        })
    }
}

impl<'p> LogicalSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        let mut parts = sig.split(';').collect::<Vec<&str>>();
        if parts.len() < 4 {
            return Err(anyhow::anyhow!("Invalid signature: not enough parts"));
        }
        let name = parts[0];
        let target_description_block = parts[1];
        let logical_expression = parts[2];
        let sigs = parts.split_off(3);

        Ok(Self {
            name,
            target_description: TargetDescription::parse(target_description_block)?,
            logical_expression,
            sigs,
        })
    }
}

impl Display for TargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TargetType::Any => "any",
            TargetType::PE => "pe",
            TargetType::OLE2 => "ole2",
            TargetType::HTML => "html",
            TargetType::Mail => "mail",
            TargetType::Graphics => "graphics",
            TargetType::ELF => "elf",
            TargetType::ASCII => "ascii",
            TargetType::Unused => "unused",
            TargetType::MachO => "macho",
            TargetType::PDF => "pdf",
            TargetType::Flash => "flash",
            TargetType::Java => "java",
        };
        write!(f, "{}", s)
    }
}

impl TryFrom<u8> for TargetType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TargetType::Any),
            1 => Ok(TargetType::PE),
            2 => Ok(TargetType::OLE2),
            3 => Ok(TargetType::HTML),
            4 => Ok(TargetType::Mail),
            5 => Ok(TargetType::Graphics),
            6 => Ok(TargetType::ELF),
            7 => Ok(TargetType::ASCII),
            8 => Ok(TargetType::Unused),
            9 => Ok(TargetType::MachO),
            10 => Ok(TargetType::PDF),
            11 => Ok(TargetType::Flash),
            12 => Ok(TargetType::Java),
            _ => Err(anyhow::anyhow!("Invalid TargetType")),
        }
    }
}

impl<'p> Display for LogicalSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "
rule {}
{{
    meta:
        original_ident: \"{}\"
    condition:
        \"{:?}\"
}}",
            self.name.replace(".","_").replace("-","_"),
            self.name,
            self.sigs
        )
    }
}

fn parse_range<T>(s: &str) -> Result<Range<T>>
where T: std::str::FromStr + std::ops::Add<Output = T> + Copy + PartialOrd + From<u8>,
{
    let parts: Vec<_> = s.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid Engine range!: {}", s));
    }
    if let (Ok(start), Ok(end)) = (parts[0].parse::<T>(), parts[1].parse::<T>()) {
        Ok(start..end + T::from(1))
    } else {
        Err(anyhow!("Can't parse Engine range"))
    }
}
