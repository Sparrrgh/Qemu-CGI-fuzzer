#[cfg(target_os = "linux")]
mod fuzzer;

#[cfg(target_os = "linux")]
use std::path::PathBuf;
pub fn main() {
    let args: Vec<_> = std::env::args().collect();
    // Concretize crashes or fuzz the executable
    // It would be better to build a separate executable
    if std::env::args().any(|a| a == "--to-concrete") {
        let bin_name = args[2].clone();
        let crash_dir = args[3].clone();
        println!(" with {bin_name} {crash_dir}");
        let context = fuzzer::grammar::get_cgi_context(50, bin_name);
        fuzzer::grammar::create_concrete_outputs(&context, PathBuf::from(crash_dir.clone()));
    } else {
        fuzzer::fuzz().expect("Fuzzer crashed");
    }
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
