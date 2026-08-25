use anyhow::{Context, Result, bail};
use goblin::{Object, elf, pe};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryKind {
    Elf,
    Pe,
}

#[derive(Clone, Debug)]
pub struct ExecutableRange {
    pub file_offset: usize,
    pub file_size: usize,
    pub virtual_address: u64,
    pub expansion: Option<ElfExpansion>,
}

#[derive(Clone, Debug)]
pub struct ElfExpansion {
    pub capacity: usize,
    pub memory_size: usize,
    pub file_size_field_offset: usize,
    pub memory_size_field_offset: usize,
}

#[derive(Debug)]
pub struct BinaryInfo {
    pub kind: BinaryKind,
    pub entry: u64,
    pub entry_encoding: EntryEncoding,
    pub executable_ranges: Vec<ExecutableRange>,
}

#[derive(Clone, Copy, Debug)]
pub enum EntryEncoding {
    Elf64 {
        field_offset: usize,
    },
    PeRva32 {
        field_offset: usize,
        image_base: u64,
    },
}

impl BinaryInfo {
    pub fn parse(data: &[u8]) -> Result<Self> {
        match Object::parse(data).context("failed to parse input executable")? {
            Object::Elf(image) => parse_elf(&image, data),
            Object::PE(image) => parse_pe(&image, data),
            _ => bail!("unsupported format: expected a 64-bit ELF or PE executable"),
        }
    }

    pub fn va_to_file_offset(&self, va: u64) -> Option<usize> {
        self.executable_ranges.iter().find_map(|range| {
            let relative = va.checked_sub(range.virtual_address)?;
            (relative < range.file_size as u64).then(|| range.file_offset + relative as usize)
        })
    }

    pub fn write_entry(&self, data: &mut [u8], new_entry: u64) -> Result<()> {
        match self.entry_encoding {
            EntryEncoding::Elf64 { field_offset } => {
                let field = data
                    .get_mut(field_offset..field_offset + 8)
                    .context("ELF entry-point field is truncated")?;
                field.copy_from_slice(&new_entry.to_le_bytes());
            }
            EntryEncoding::PeRva32 {
                field_offset,
                image_base,
            } => {
                let rva = u32::try_from(
                    new_entry
                        .checked_sub(image_base)
                        .context("generated PE entry point is below the image base")?,
                )
                .context("generated PE entry-point RVA is too large")?;
                let field = data
                    .get_mut(field_offset..field_offset + 4)
                    .context("PE entry-point field is truncated")?;
                field.copy_from_slice(&rva.to_le_bytes());
            }
        }
        Ok(())
    }
}

fn parse_elf(image: &elf::Elf<'_>, data: &[u8]) -> Result<BinaryInfo> {
    if !image.is_64 || image.header.e_machine != elf::header::EM_X86_64 {
        bail!("ELF input is not x86-64");
    }

    let mut executable_ranges = Vec::new();
    for (index, ph) in image.program_headers.iter().enumerate() {
        if ph.p_type == elf::program_header::PT_LOAD
            && ph.p_flags & elf::program_header::PF_X != 0
            && ph.p_filesz != 0
        {
            let file_offset =
                usize::try_from(ph.p_offset).context("ELF file offset is too large")?;
            let file_size = usize::try_from(ph.p_filesz).context("ELF segment is too large")?;
            let memory_size = usize::try_from(ph.p_memsz).context("ELF segment is too large")?;
            let mut capacity = data.len().saturating_sub(file_offset);
            for other in &image.program_headers {
                if other.p_type != elf::program_header::PT_LOAD {
                    continue;
                }
                if other.p_offset > ph.p_offset {
                    capacity = capacity.min((other.p_offset - ph.p_offset) as usize);
                }
                if other.p_vaddr > ph.p_vaddr {
                    capacity = capacity.min((other.p_vaddr - ph.p_vaddr) as usize);
                }
            }
            let ph_offset = usize::try_from(image.header.e_phoff)
                .context("ELF program-header offset is too large")?
                + index * image.header.e_phentsize as usize;
            executable_ranges.push(ExecutableRange {
                file_offset,
                file_size,
                virtual_address: ph.p_vaddr,
                expansion: Some(ElfExpansion {
                    capacity,
                    memory_size,
                    file_size_field_offset: ph_offset + 32,
                    memory_size_field_offset: ph_offset + 40,
                }),
            });
        }
    }

    if executable_ranges.is_empty() {
        bail!("ELF contains no file-backed executable PT_LOAD segment");
    }

    Ok(BinaryInfo {
        kind: BinaryKind::Elf,
        entry: image.entry,
        entry_encoding: EntryEncoding::Elf64 { field_offset: 24 },
        executable_ranges,
    })
}

fn parse_pe(image: &pe::PE<'_>, _data: &[u8]) -> Result<BinaryInfo> {
    if !image.is_64 {
        bail!("PE input is not PE32+ (x86-64)");
    }
    let coff = &image.header.coff_header;
    if coff.machine != pe::header::COFF_MACHINE_X86_64 {
        bail!("PE input is not x86-64");
    }

    let image_base = image.image_base;
    let pe_header_offset = image.header.dos_header.pe_pointer as usize;
    let entry_field_offset = pe_header_offset
        .checked_add(4 + pe::header::SIZEOF_COFF_HEADER + 16)
        .context("PE entry-point field offset overflow")?;
    let executable_ranges = image
        .sections
        .iter()
        .filter(|section| {
            section.characteristics & pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
                && section.size_of_raw_data != 0
        })
        .map(|section| ExecutableRange {
            file_offset: section.pointer_to_raw_data as usize,
            file_size: section.size_of_raw_data as usize,
            virtual_address: image_base + section.virtual_address as u64,
            expansion: None,
        })
        .collect::<Vec<_>>();

    if executable_ranges.is_empty() {
        bail!("PE contains no file-backed executable section");
    }

    Ok(BinaryInfo {
        kind: BinaryKind::Pe,
        entry: image_base + image.entry as u64,
        entry_encoding: EntryEncoding::PeRva32 {
            field_offset: entry_field_offset,
            image_base,
        },
        executable_ranges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn va_mapping_is_bounded_by_file_size() {
        let info = BinaryInfo {
            kind: BinaryKind::Elf,
            entry: 0x401000,
            entry_encoding: EntryEncoding::Elf64 { field_offset: 24 },
            executable_ranges: vec![ExecutableRange {
                file_offset: 0x1000,
                file_size: 0x100,
                virtual_address: 0x401000,
                expansion: None,
            }],
        };
        assert_eq!(info.va_to_file_offset(0x401020), Some(0x1020));
        assert_eq!(info.va_to_file_offset(0x401100), None);
    }

    #[test]
    fn writes_elf_entry_field() {
        let mut data = vec![0; 64];
        let info = BinaryInfo {
            kind: BinaryKind::Elf,
            entry: 0x401000,
            entry_encoding: EntryEncoding::Elf64 { field_offset: 24 },
            executable_ranges: vec![],
        };
        info.write_entry(&mut data, 0x402000).unwrap();
        assert_eq!(
            u64::from_le_bytes(data[24..32].try_into().unwrap()),
            0x402000
        );
    }

    #[test]
    fn writes_pe_entry_as_rva() {
        let mut data = vec![0; 64];
        let info = BinaryInfo {
            kind: BinaryKind::Pe,
            entry: 0x140001000,
            entry_encoding: EntryEncoding::PeRva32 {
                field_offset: 16,
                image_base: 0x140000000,
            },
            executable_ranges: vec![],
        };
        info.write_entry(&mut data, 0x140002000).unwrap();
        assert_eq!(u32::from_le_bytes(data[16..20].try_into().unwrap()), 0x2000);
    }
}
