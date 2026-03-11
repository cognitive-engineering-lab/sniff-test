#![feature(rustc_private)]

fn main() {
    sniff_test::env_logger_init(true);
    let args: Vec<String> = std::env::args().collect();
    // If there are enough args that we're trying to call the real rustc,
    // just pass through to calling the real rustc
    if args.len() >= 2 {
        let real_rustc = &args[1];
        let rest = &args[2..];
        let is_passthrough = rest
            .iter()
            .any(|a| a.starts_with("--print") || a == "-vV" || a == "--version" || a == "-V")
            || rest.is_empty();

        if is_passthrough {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new(real_rustc).args(rest).exec();
            panic!("failed to exec rustc: {err}");
        }
    }

    rustc_plugin::driver_main(sniff_test::PrintAllItemsPlugin);
}
