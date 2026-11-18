fn main() {
    // Behave like a normal Unix filter when stdout closes early (`apw list |
    // head`): die on SIGPIPE instead of panicking inside println!.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    std::process::exit(apw::run());
}
