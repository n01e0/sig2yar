use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Display;
use std::ops::Range;

#[derive(Debug)]
pub struct TargetDescription<'t> {
    engine: Option<Range<u32>>,
    target: TargetType,
    file_size: Option<Range<usize>>,
    entry_point: Option<Range<usize>>,
    number_of_sections: Option<Range<usize>>,
    container: Option<FileType>,
    container_raw: Option<&'t str>,
    intermediates: Option<&'t str>,
    icon_group1: Option<&'t str>,
    icon_group2: Option<&'t str>,
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

#[derive(Debug)]
pub enum FileType {
    ZipArchive,
    SelfExtractingZipArchive,
    SevenZipArchive,
    SelfExtractingSevenZipArchive,
    DiskImageApplePartitionMap,
    ArjArchive,
    SelfExtractingArjArchive,
    AutoItAutomationExecutable,
    BinaryData,
    BinHexMacintosh,
    BZipCompressedFile,
    SelfExtractingMicrosoftCabArchive,
    CpioArchiveCrc,
    CpioArchiveNewc,
    CpioArchiveOdc,
    CpioArchiveOld,
    FilesEncryptedByCryptffMalware,
    AppleDmgArchive,
    EstSoftEggArchive,
    ElfExecutable,
    GifGraphicsFile,
    DiskImageGuidPartitionTable,
    OtherGraphicsFiles,
    GZipCompressedFile,
    HtmlUtf16,
    HtmlData,
    HangulWordProcessor3X,
    HangulWordProcessorEmbeddedOle2,
    InternalProperties,
    WindowsInstallShieldMsiInstaller,
    Iso9660FileSystem,
    JavaClassFile,
    JpegGraphicsFile,
    MicrosoftWindowsShortcutFile,
    UniversalBinaryJavaBytecode,
    AppleMachOExecutableFile,
    EmailFile,
    DiskImageMasterBootRecord,
    MhtmlSavedWebPage,
    MicrosoftCabArchive,
    MicrosoftChmHelpArchive,
    MicrosoftExeDllExecutableFile,
    MicrosoftOle2ContainerFile,
    MicrosoftCompressedExe,
    NullSoftScriptedInstallerProgram,
    TarArchiveOld,
    MicrosoftOneNoteDocumentSectionFile,
    HangulOfficeOpenWordProcessor5X,
    MicrosoftOfficeOpenXmlPowerpoint,
    MicrosoftOfficeOpenWord2007Plus,
    MicrosoftOfficeOpenExcel2007Plus,
    AppleHfsPlusPartition,
    AdobePdfDocument,
    PngGraphicsFile,
    PosixTarArchive,
    Postscript,
    PythonByteCompiledExecutable,
    RarArchive,
    SelfExtractingRarArchive,
    ResourceInterchangeFileFormat,
    RichTextFormatDocument,
    FilesEncryptedByScrencMalware,
    GenericTypeForScripts,
    SymbianOsSoftwareInstallationScriptArchive,
    AdobeFlashFile,
    AsciiText,
    Utf16BeText,
    Utf16LeText,
    Utf8Text,
    TiffGraphicsFile,
    MicrosoftOutlookExchangeEmailAttachmentFormat,
    UdfUniversalDiskFormatPartition,
    UuencodedBinaryFile,
    XarArchive,
    AdobeXdpEmbeddedPdf,
    HangulWordProcessorXmlDocument,
    MicrosoftWord2003XmlDocument,
    MicrosoftExcel2003XmlDocument,
    XzArchive,
}

impl TryFrom<&str> for FileType {
    type Error = String;

    fn try_from(cl_type: &str) -> Result<Self, Self::Error> {
        match cl_type {
            "CL_TYPE_ZIP" => Ok(FileType::ZipArchive),
            "CL_TYPE_ZIPSFX" => Ok(FileType::SelfExtractingZipArchive),
            "CL_TYPE_7Z" => Ok(FileType::SevenZipArchive),
            "CL_TYPE_7ZSFX" => Ok(FileType::SelfExtractingSevenZipArchive),
            "CL_TYPE_APM" => Ok(FileType::DiskImageApplePartitionMap),
            "CL_TYPE_ARJ" => Ok(FileType::ArjArchive),
            "CL_TYPE_ARJSFX" => Ok(FileType::SelfExtractingArjArchive),
            "CL_TYPE_AUTOIT" => Ok(FileType::AutoItAutomationExecutable),
            "CL_TYPE_BINARY_DATA" => Ok(FileType::BinaryData),
            "CL_TYPE_BINHEX" => Ok(FileType::BinHexMacintosh),
            "CL_TYPE_BZ" => Ok(FileType::BZipCompressedFile),
            "CL_TYPE_CABSFX" => Ok(FileType::SelfExtractingMicrosoftCabArchive),
            "CL_TYPE_CPIO_CRC" => Ok(FileType::CpioArchiveCrc),
            "CL_TYPE_CPIO_NEWC" => Ok(FileType::CpioArchiveNewc),
            "CL_TYPE_CPIO_ODC" => Ok(FileType::CpioArchiveOdc),
            "CL_TYPE_CPIO_OLD" => Ok(FileType::CpioArchiveOld),
            "CL_TYPE_CRYPTFF" => Ok(FileType::FilesEncryptedByCryptffMalware),
            "CL_TYPE_DMG" => Ok(FileType::AppleDmgArchive),
            "CL_TYPE_EGG" => Ok(FileType::EstSoftEggArchive),
            "CL_TYPE_ELF" => Ok(FileType::ElfExecutable),
            "CL_TYPE_GIF" => Ok(FileType::GifGraphicsFile),
            "CL_TYPE_GPT" => Ok(FileType::DiskImageGuidPartitionTable),
            "CL_TYPE_GRAPHICS" => Ok(FileType::OtherGraphicsFiles),
            "CL_TYPE_GZ" => Ok(FileType::GZipCompressedFile),
            "CL_TYPE_HTML_UTF16" => Ok(FileType::HtmlUtf16),
            "CL_TYPE_HTML" => Ok(FileType::HtmlData),
            "CL_TYPE_HWP3" => Ok(FileType::HangulWordProcessor3X),
            "CL_TYPE_HWPOLE2" => Ok(FileType::HangulWordProcessorEmbeddedOle2),
            "CL_TYPE_INTERNAL" => Ok(FileType::InternalProperties),
            "CL_TYPE_ISHIELD_MSI" => Ok(FileType::WindowsInstallShieldMsiInstaller),
            "CL_TYPE_ISO9660" => Ok(FileType::Iso9660FileSystem),
            "CL_TYPE_JAVA" => Ok(FileType::JavaClassFile),
            "CL_TYPE_JPEG" => Ok(FileType::JpegGraphicsFile),
            "CL_TYPE_LNK" => Ok(FileType::MicrosoftWindowsShortcutFile),
            "CL_TYPE_MACHO_UNIBIN" => Ok(FileType::UniversalBinaryJavaBytecode),
            "CL_TYPE_MACHO" => Ok(FileType::AppleMachOExecutableFile),
            "CL_TYPE_MAIL" => Ok(FileType::EmailFile),
            "CL_TYPE_MBR" => Ok(FileType::DiskImageMasterBootRecord),
            "CL_TYPE_MHTML" => Ok(FileType::MhtmlSavedWebPage),
            "CL_TYPE_MSCAB" => Ok(FileType::MicrosoftCabArchive),
            "CL_TYPE_MSCHM" => Ok(FileType::MicrosoftChmHelpArchive),
            "CL_TYPE_MSEXE" => Ok(FileType::MicrosoftExeDllExecutableFile),
            "CL_TYPE_MSOLE2" => Ok(FileType::MicrosoftOle2ContainerFile),
            "CL_TYPE_MSSZDD" => Ok(FileType::MicrosoftCompressedExe),
            "CL_TYPE_NULSFT" => Ok(FileType::NullSoftScriptedInstallerProgram),
            "CL_TYPE_OLD_TAR" => Ok(FileType::TarArchiveOld),
            "CL_TYPE_ONENOTE" => Ok(FileType::MicrosoftOneNoteDocumentSectionFile),
            "CL_TYPE_OOXML_HWP" => Ok(FileType::HangulOfficeOpenWordProcessor5X),
            "CL_TYPE_OOXML_PPT" => Ok(FileType::MicrosoftOfficeOpenXmlPowerpoint),
            "CL_TYPE_OOXML_WORD" => Ok(FileType::MicrosoftOfficeOpenWord2007Plus),
            "CL_TYPE_OOXML_XL" => Ok(FileType::MicrosoftOfficeOpenExcel2007Plus),
            "CL_TYPE_PART_HFSPLUS" => Ok(FileType::AppleHfsPlusPartition),
            "CL_TYPE_PDF" => Ok(FileType::AdobePdfDocument),
            "CL_TYPE_PNG" => Ok(FileType::PngGraphicsFile),
            "CL_TYPE_POSIX_TAR" => Ok(FileType::PosixTarArchive),
            "CL_TYPE_PS" => Ok(FileType::Postscript),
            "CL_TYPE_PYTHON_COMPILED" => Ok(FileType::PythonByteCompiledExecutable),
            "CL_TYPE_RAR" => Ok(FileType::RarArchive),
            "CL_TYPE_RARSFX" => Ok(FileType::SelfExtractingRarArchive),
            "CL_TYPE_RIFF" => Ok(FileType::ResourceInterchangeFileFormat),
            "CL_TYPE_RTF" => Ok(FileType::RichTextFormatDocument),
            "CL_TYPE_SCRENC" => Ok(FileType::FilesEncryptedByScrencMalware),
            "CL_TYPE_SCRIPT" => Ok(FileType::GenericTypeForScripts),
            "CL_TYPE_SIS" => Ok(FileType::SymbianOsSoftwareInstallationScriptArchive),
            "CL_TYPE_SWF" => Ok(FileType::AdobeFlashFile),
            "CL_TYPE_TEXT_ASCII" => Ok(FileType::AsciiText),
            "CL_TYPE_TEXT_UTF16BE" => Ok(FileType::Utf16BeText),
            "CL_TYPE_TEXT_UTF16LE" => Ok(FileType::Utf16LeText),
            "CL_TYPE_TEXT_UTF8" => Ok(FileType::Utf8Text),
            "CL_TYPE_TIFF" => Ok(FileType::TiffGraphicsFile),
            "CL_TYPE_TNEF" => Ok(FileType::MicrosoftOutlookExchangeEmailAttachmentFormat),
            "CL_TYPE_UDF" => Ok(FileType::UdfUniversalDiskFormatPartition),
            "CL_TYPE_UUENCODED" => Ok(FileType::UuencodedBinaryFile),
            "CL_TYPE_XAR" => Ok(FileType::XarArchive),
            "CL_TYPE_XDP" => Ok(FileType::AdobeXdpEmbeddedPdf),
            "CL_TYPE_XML_HWP" => Ok(FileType::HangulWordProcessorXmlDocument),
            "CL_TYPE_XML_WORD" => Ok(FileType::MicrosoftWord2003XmlDocument),
            "CL_TYPE_XML_XL" => Ok(FileType::MicrosoftExcel2003XmlDocument),
            "CL_TYPE_XZ" => Ok(FileType::XzArchive),
            _ => Err(format!("Unsupported CL_TYPE: {}", cl_type)),
        }
    }
}

// Optional: Implement Display for better error messages
impl Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<'t> TargetDescription<'t> {
    pub fn parse(target_description: &'t str) -> Result<Self> {
        let parts = target_description.split(',').collect::<Vec<&str>>();
        if parts.is_empty() {
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

        let engine = match map.get("Engine") {
            Some(value) => Some(parse_range::<u32>(value)?),
            None => None,
        };
        let target = TargetType::try_from(
            map.get("Target")
                .with_context(|| "Can't find Target Type block")?
                .parse::<u8>()
                .with_context(|| "Can't parse TargetType number")?,
        )
        .with_context(|| "Can't parse TargetType")?;

        let container_raw = map.get("Container").copied();
        let container = container_raw.and_then(|c| FileType::try_from(c).ok());

        Ok({
            TargetDescription {
                engine,
                target,
                file_size: map
                    .get("FileSize")
                    .and_then(|n| parse_range::<usize>(n).ok()),
                entry_point: map
                    .get("EntryPoint")
                    .and_then(|n| parse_range::<usize>(n).ok()),
                number_of_sections: map
                    .get("NumberOfSections")
                    .and_then(|n| parse_range::<usize>(n).ok()),
                container,
                container_raw,
                intermediates: map.get("Intermediates").map(|v| *v),
                icon_group1: map.get("IconGroup1").copied(),
                icon_group2: map.get("IconGroup2").copied(),
            }
        })
    }

    pub fn to_ir(&self) -> crate::ir::TargetDescription {
        crate::ir::TargetDescription {
            raw: compact_whitespace(&self.to_string()),
            engine: range_u32_to_inclusive_u64(self.engine.as_ref()),
            target_type: Some(self.target.to_string()),
            file_size: range_to_inclusive_u64(self.file_size.as_ref()),
            entry_point: range_to_inclusive_u64(self.entry_point.as_ref()),
            number_of_sections: range_to_inclusive_u64(self.number_of_sections.as_ref()),
            container: self.container_raw.map(|v| v.to_string()),
            intermediates: self.intermediates.map(|v| v.to_string()),
            icon_group1: self.icon_group1.map(|v| v.to_string()),
            icon_group2: self.icon_group2.map(|v| v.to_string()),
        }
    }
}

impl<'t> Display for TargetDescription<'t> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        if let Some(engine) = self.engine.as_ref() {
            s.push_str(&format!(
                "
        engine: \"{engine:?}\"
        "
            ));
        }
        s.push_str(&format!(
            "
        target: \"{}\"
        ",
            self.target
        ));

        if let Some(file_size) = self.file_size.as_ref() {
            s.push_str(&format!(
                "
        file_size: \"{file_size:?}\"
            "
            ))
        }
        if let Some(entry_point) = self.entry_point.as_ref() {
            s.push_str(&format!(
                "
        entry_point: \"{entry_point:?}\"
            "
            ))
        }
        if let Some(number_of_sections) = self.number_of_sections.as_ref() {
            s.push_str(&format!(
                "
        number_of_sections: \"{number_of_sections:?}\"
            "
            ))
        }
        if let Some(container) = self.container.as_ref() {
            s.push_str(&format!(
                "
        container: \"{container}\"
            "
            ))
        }
        if let Some(intermediates) = self.intermediates {
            s.push_str(&format!(
                "
        intermediates: \"{intermediates}\"
            "
            ))
        }
        if let Some(icon_group1) = self.icon_group1 {
            s.push_str(&format!(
                "
        icon_group1: \"{icon_group1}\"
            "
            ))
        }
        if let Some(icon_group2) = self.icon_group2 {
            s.push_str(&format!(
                "
        icon_group2: \"{icon_group2}\"
            "
            ))
        }

        write!(f, "{}", s)
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

fn compact_whitespace(input: &str) -> String {
    input
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn range_u32_to_inclusive_u64(range: Option<&Range<u32>>) -> Option<(u64, u64)> {
    let range = range?;
    let start = u64::from(range.start);
    let end_exclusive = u64::from(range.end);
    let end_inclusive = end_exclusive.checked_sub(1)?;
    Some((start, end_inclusive))
}

fn range_to_inclusive_u64(range: Option<&Range<usize>>) -> Option<(u64, u64)> {
    let range = range?;
    let start = u64::try_from(range.start).ok()?;
    let end_exclusive = u64::try_from(range.end).ok()?;
    let end_inclusive = end_exclusive.checked_sub(1)?;
    Some((start, end_inclusive))
}

fn parse_range<T>(s: &str) -> Result<Range<T>>
where
    T: std::str::FromStr + std::ops::Add<Output = T> + Copy + PartialOrd + From<u8>,
{
    let parts: Vec<_> = s.split('-').collect();
    match parts.len() {
        1 => {
            if let Ok(start) = parts[0].parse::<T>() {
                Ok(start..start + T::from(1))
            } else {
                Err(anyhow!("Can't parse range: {}", s))
            }
        }
        2 => {
            if let (Ok(start), Ok(end)) = (parts[0].parse::<T>(), parts[1].parse::<T>()) {
                Ok(start..end + T::from(1))
            } else {
                Err(anyhow!("Can't parse range: {}", s))
            }
        }
        _ => Err(anyhow!("Invalid range: {}", s)),
    }
}
