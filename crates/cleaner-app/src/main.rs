#![windows_subsystem = "windows"]

mod cli;
mod logging;

use clap::Parser;
use cli::{run_cli_scan, run_cli_scheduled_clean, run_cli_storage_analyze};
use logging::init_logging;

#[derive(Parser, Debug)]
#[command(
    name = "bleachsan",
    version = "0.1.0",
    about = "Lightweight, deterministic Windows storage cleaner & storage analyzer"
)]
struct CliArgs {
    /// Scan all rules and print results to stdout
    #[arg(long)]
    scan: bool,

    /// Run scheduled headless cleanup for Windows Task Scheduler
    #[arg(long)]
    scheduled: bool,

    /// Perform safe cleanup headlessly
    #[arg(long)]
    clean_safe: bool,

    /// Analyze local storage consumers
    #[arg(long)]
    analyze: bool,
}

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let is_headless = args.scan || args.scheduled || args.clean_safe || args.analyze;

    init_logging(is_headless);

    if args.scan {
        run_cli_scan();
        return Ok(());
    }

    if args.scheduled || args.clean_safe {
        run_cli_scheduled_clean();
        return Ok(());
    }

    if args.analyze {
        run_cli_storage_analyze();
        return Ok(());
    }

    // Default: Launch Slint GUI
    tracing::info!("Launching BleachSan Desktop UI");
    if let Err(e) = cleaner_ui::run_ui() {
        tracing::error!("UI Event Loop error: {}", e);
        eprintln!("Failed to launch GUI: {}", e);
    }

    Ok(())
}
