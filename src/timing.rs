/// Optional pass timings, written to stderr when VELK_TIMING is set.
#[cfg(feature = "timing")]
pub(crate) struct Timer {
    name: &'static str,
    start: Option<std::time::Instant>,
}

#[cfg(feature = "timing")]
impl Timer {
    pub(crate) fn new(name: &'static str) -> Self {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let enabled = *ENABLED.get_or_init(|| std::env::var_os("VELK_TIMING").is_some());
        Self {
            name,
            start: enabled.then(std::time::Instant::now),
        }
    }
}

#[cfg(feature = "timing")]
impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            eprintln!("timing\t{}\t{}", self.name, start.elapsed().as_nanos());
        }
    }
}

macro_rules! scope {
    ($name:expr) => {
        #[cfg(feature = "timing")]
        let _timer = crate::timing::Timer::new($name);
    };
}

pub(crate) use scope;
