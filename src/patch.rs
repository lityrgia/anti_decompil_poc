use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

use crate::binary::{BinaryInfo, BinaryKind, ExecutableRange};

const INLINE_DISPATCHER_SIZE: usize = 33;
const CAVE_ALIGNMENT: usize = 16;
const ENDBR64: [u8; 4] = [0xF3, 0x0F, 0x1E, 0xFA];

#[derive(Debug)]
pub struct PatchReport {
    pub output: PathBuf,
    pub kind: BinaryKind,
    pub target_va: u64,
    pub dispatcher_va: u64,
}

pub fn patch_executable(input: &Path) -> Result<PatchReport> {
    ensure!(
        input.is_file(),
        "input path is not a regular file: {}",
        input.display()
    );
    let extension = input
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    ensure!(
        extension.eq_ignore_ascii_case("exe") || extension.eq_ignore_ascii_case("elf"),
        "input must have an .exe or .elf extension"
    );

    let mut data =
        fs::read(input).with_context(|| format!("failed to read {}", input.display()))?;
    let info = BinaryInfo::parse(&data)?;
    let target_va = info.entry;
    ensure!(
        info.va_to_file_offset(target_va).is_some(),
        "entry point 0x{target_va:x} is not file-backed executable code"
    );

    let conservative_size = 128usize;
    let cave = find_code_cave(&data, &info.executable_ranges, conservative_size);
    let (cave_offset, cave_va) = match cave {
        Some(location) => location,
        None => expand_elf_segment(&mut data, &info.executable_ranges, conservative_size)
            .context("no suitable executable code cave or expandable ELF segment was found")?,
    };

    let table_va = cave_va + INLINE_DISPATCHER_SIZE as u64;
    let dispatcher = build_inline_dispatcher(cave_va, table_va)?;
    ensure!(
        dispatcher.len() == INLINE_DISPATCHER_SIZE,
        "internal inline dispatcher size mismatch"
    );

    let mut blob = dispatcher;
    let table_offset = blob.len();
    blob.extend_from_slice(&[0; 8]);
    let original_case_va = cave_va + blob.len() as u64;
    blob.extend_from_slice(&ENDBR64);
    let jump_source = cave_va + blob.len() as u64;
    emit_rel32_jump(&mut blob, jump_source, target_va)?;
    let stub_case_va = cave_va + blob.len() as u64;
    blob.extend_from_slice(&ENDBR64);
    blob.extend_from_slice(&[0x31, 0xC0, 0xC3]);

    write_i32(
        &mut blob[table_offset..table_offset + 4],
        relative_i32(table_va, original_case_va)?,
    );
    write_i32(
        &mut blob[table_offset + 4..table_offset + 8],
        relative_i32(table_va, stub_case_va)?,
    );
    ensure!(
        blob.len() <= conservative_size,
        "internal generated-code size estimate was too small"
    );

    data[cave_offset..cave_offset + blob.len()].copy_from_slice(&blob);
    info.write_entry(&mut data, cave_va)?;

    let output = output_path(input);
    fs::write(&output, &data).with_context(|| format!("failed to write {}", output.display()))?;
    preserve_permissions(input, &output)?;

    Ok(PatchReport {
        output,
        kind: info.kind,
        target_va,
        dispatcher_va: cave_va,
    })
}

fn find_code_cave(
    data: &[u8],
    ranges: &[ExecutableRange],
    required: usize,
) -> Option<(usize, u64)> {
    ranges.iter().find_map(|range| {
        let end = range
            .file_offset
            .checked_add(range.file_size)?
            .min(data.len());
        let bytes = data.get(range.file_offset..end)?;
        let mut run_start = 0usize;
        let mut run_len = 0usize;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if byte == 0 || byte == 0xCC {
                if run_len == 0 {
                    run_start = index;
                }
                run_len += 1;
                let aligned = align_up(range.file_offset + run_start, CAVE_ALIGNMENT)?;
                let skipped = aligned - (range.file_offset + run_start);
                if run_len >= required + skipped {
                    let relative = aligned - range.file_offset;
                    return Some((aligned, range.virtual_address + relative as u64));
                }
            } else {
                run_len = 0;
            }
        }
        None
    })
}

fn expand_elf_segment(
    data: &mut [u8],
    ranges: &[ExecutableRange],
    required: usize,
) -> Option<(usize, u64)> {
    for range in ranges {
        let Some(expansion) = range.expansion.as_ref() else {
            continue;
        };
        let used = range.file_size.max(expansion.memory_size);
        let relative = align_up(used, CAVE_ALIGNMENT)?;
        let new_size = relative.checked_add(required)?;
        if new_size > expansion.capacity {
            continue;
        }
        let offset = range.file_offset.checked_add(relative)?;
        let end = range.file_offset.checked_add(new_size)?;
        let padding = data.get(offset..end)?;
        if !padding.iter().all(|byte| *byte == 0 || *byte == 0xCC) {
            continue;
        }
        write_u64_at(data, expansion.file_size_field_offset, new_size as u64)?;
        write_u64_at(data, expansion.memory_size_field_offset, new_size as u64)?;
        return Some((offset, range.virtual_address + relative as u64));
    }
    None
}

fn build_inline_dispatcher(dispatcher_va: u64, table_va: u64) -> Result<Vec<u8>> {
    // RAX is deliberately both the table index and overwritten before the final
    // jump. This is the Hex-Rays-confusing idiom described in the linked report.
    // User-mode x86-64 RSP has bit 63 clear, so the runtime selector remains case 0.
    // RAX/R10/R11 are volatile in both x86-64 ABIs and RSP itself is not modified.
    let mut code = vec![
        0xF3, 0x0F, 0x1E, 0xFA, // endbr64
        0x48, 0x89, 0xE0, // mov rax,rsp
        0x48, 0xC1, 0xE8, 0x3F, // shr rax,3Fh
        0x4C, 0x8D, 0x15, 0, 0, 0, 0, // lea r10,[rip+table]
        0x4D, 0x63, 0x1C, 0x82, // movsxd r11,dword [r10+rax*4]
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (valid second case)
        0x4D, 0x01, 0xD3, // add r11,r10
        0x41, 0xFF, 0xE3, // jmp r11
    ];
    let lea_next_ip = dispatcher_va + 18;
    write_i32(&mut code[14..18], relative_i32(lea_next_ip, table_va)?);
    Ok(code)
}

fn emit_rel32_jump(code: &mut Vec<u8>, source_va: u64, target_va: u64) -> Result<()> {
    code.extend_from_slice(&rel32_jump(source_va, target_va)?);
    Ok(())
}

fn rel32_jump(source_va: u64, target_va: u64) -> Result<[u8; 5]> {
    let displacement = relative_i32(source_va + 5, target_va)?;
    let mut result = [0u8; 5];
    result[0] = 0xE9;
    result[1..].copy_from_slice(&displacement.to_le_bytes());
    Ok(result)
}

fn relative_i32(base: u64, target: u64) -> Result<i32> {
    let displacement = i128::from(target) - i128::from(base);
    i32::try_from(displacement).context("relative address is outside the signed 32-bit range")
}

fn write_i32(destination: &mut [u8], value: i32) {
    destination.copy_from_slice(&value.to_le_bytes());
}

fn write_u64_at(data: &mut [u8], offset: usize, value: u64) -> Option<()> {
    let end = offset.checked_add(8)?;
    data.get_mut(offset..end)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}

fn output_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("patched");
    let extension = input
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    parent.join(format!("{stem}.patch.{extension}"))
}

#[cfg(unix)]
fn preserve_permissions(input: &Path, output: &Path) -> Result<()> {
    let permissions = fs::metadata(input)?.permissions();
    fs::set_permissions(output, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn preserve_permissions(_input: &Path, _output: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::ElfExpansion;

    #[test]
    fn jump_encoding_uses_next_instruction_as_base() {
        assert_eq!(rel32_jump(0x1000, 0x1010).unwrap(), [0xE9, 0x0B, 0, 0, 0]);
    }

    #[test]
    fn output_uses_patch_suffix() {
        assert_eq!(
            output_path(Path::new("sample.exe")),
            PathBuf::from("sample.patch.exe")
        );
        assert_eq!(
            output_path(Path::new("sample.elf")),
            PathBuf::from("sample.patch.elf")
        );
    }

    #[test]
    fn cave_search_aligns_result() {
        let data = vec![0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let range = ExecutableRange {
            file_offset: 0,
            file_size: data.len(),
            virtual_address: 0x1000,
            expansion: None,
        };
        assert_eq!(find_code_cave(&data, &[range], 3), Some((16, 0x1010)));
    }

    #[test]
    fn dispatcher_points_to_external_table() {
        let code = build_inline_dispatcher(0x1000, 0x2000).unwrap();
        let disp = i32::from_le_bytes(code[14..18].try_into().unwrap());
        assert_eq!((0x1000_i64 + 18 + i64::from(disp)) as u64, 0x2000);
    }

    #[test]
    fn dispatcher_contains_required_mov_eax() {
        let code = build_inline_dispatcher(0x1000, 0x2000).unwrap();
        assert_eq!(&code[22..27], &[0xB8, 0x01, 0, 0, 0]);
    }

    #[test]
    fn dispatcher_is_inline_and_has_no_entry_jump() {
        let code = build_inline_dispatcher(0x1000, 0x2000).unwrap();
        assert_eq!(code.len(), INLINE_DISPATCHER_SIZE);
        assert_eq!(&code[..4], &ENDBR64);
        assert_ne!(code[0], 0xE9);
    }

    #[test]
    fn elf_segment_expansion_updates_both_sizes() {
        let mut data = vec![0; 128];
        let range = ExecutableRange {
            file_offset: 32,
            file_size: 16,
            virtual_address: 0x400000,
            expansion: Some(ElfExpansion {
                capacity: 64,
                memory_size: 16,
                file_size_field_offset: 0,
                memory_size_field_offset: 8,
            }),
        };
        assert_eq!(
            expand_elf_segment(&mut data, &[range], 16),
            Some((48, 0x400010))
        );
        assert_eq!(u64::from_le_bytes(data[0..8].try_into().unwrap()), 32);
        assert_eq!(u64::from_le_bytes(data[8..16].try_into().unwrap()), 32);
    }
}
