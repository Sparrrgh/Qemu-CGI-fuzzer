//! A libfuzzer-like fuzzer using qemu for binary-only coverage
#[cfg(target_os = "linux")]
mod fuzzer;

#[cfg(target_os = "linux")]
pub fn main() {
    let args: Vec<_> = std::env::args().collect();
    if std::env::args().any(|a| a == "--repro") {
        let bin_name = args[2].clone();
        let crash_dir = args[3].clone();
        println!("Launched with {bin_name} {crash_dir}");
        let context = fuzzer::grammar::get_cgi_context(50, bin_name);
        fuzzer::grammar::create_concrete_outputs(
            &context,
            std::path::PathBuf::from(crash_dir.clone()),
        );
    } else {
        fuzzer::fuzz();
    }
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
