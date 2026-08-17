use cleaner_core::rules::get_embedded_rules;
use cleaner_core::scanner::scan_all_rules;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    println!("=== BleachSan Performance Benchmark Suite ===");

    let rules = get_embedded_rules();
    println!("Loaded {} rules.", rules.len());

    // 1. Benchmark Rule Scan Speed
    let iterations = 5;
    let mut total_duration = 0;

    for i in 1..=iterations {
        let cancel = Arc::new(AtomicBool::new(false));
        let start = Instant::now();
        let plans = scan_all_rules(&rules, None, cancel);
        let elapsed = start.elapsed().as_millis();
        total_duration += elapsed;

        let total_bytes: u64 = plans.iter().map(|p| p.total_bytes).sum();
        println!(
            "Iteration {}: Scanned in {} ms (Reclaimable: {} bytes across {} plans)",
            i,
            elapsed,
            total_bytes,
            plans.len()
        );
    }

    let avg_duration = total_duration as f64 / iterations as f64;
    println!("\nAverage Scan Duration: {:.2} ms", avg_duration);
    println!("=== Benchmark Complete ===");
}
