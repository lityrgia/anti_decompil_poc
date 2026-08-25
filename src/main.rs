use std::{env, path::PathBuf, process::ExitCode};

use anti_decompil_poc::patch_executable;
use anyhow::{Result, ensure};
use spdlog::prelude::*;

fn run() -> Result<()> {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_default();
    let input = arguments.next().map(PathBuf::from);
    ensure!(
        input.is_some() && arguments.next().is_none(),
        "usage: {} <file.exe|file.elf>",
        PathBuf::from(program).display()
    );
    let input = input.expect("checked above");

    info!("parsing {}", input.display());
    let report = patch_executable(&input)?;
    info!(
        "redirected {:?} entry point from 0x{:x} to inline dispatcher at 0x{:x}",
        report.kind, report.target_va, report.dispatcher_va
    );
    info!("wrote {}", report.output.display());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
