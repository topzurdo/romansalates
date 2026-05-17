use std::io::{self, Write};

fn main() {
    if let Err(err) = bytecode_decompiler::cli::run() {
        eprintln!("Error: {err:#}");
        pause_before_exit();
        std::process::exit(1);
    }
}

fn pause_before_exit() {
    #[cfg(windows)]
    {
        let _ = writeln!(io::stderr(), "\nPress Enter to exit...");
        let _ = io::stderr().flush();
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
    }
}
