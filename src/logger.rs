use std::sync::OnceLock;

pub fn log_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();

    *ENABLED.get_or_init(|| {
        matches!(
            std::env::var("RAWGREP_LOG").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        )
    })
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::logger::log_enabled() {
            eprintln!($($arg)*);
        }
    };
}
