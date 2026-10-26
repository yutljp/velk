//! Ordered parallel work in one bounded worker pool.

use std::sync::OnceLock;

use rayon::{ThreadPool, ThreadPoolBuilder};

pub(crate) fn pool() -> Option<&'static ThreadPool> {
    static POOL: OnceLock<Option<ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        crate::timing::scope!("parallel::pool");
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let threads = std::env::var("VELK_THREADS")
            .ok()
            .and_then(|value| value.parse::<std::num::NonZeroUsize>().ok())
            .map_or(cores, |limit| limit.get().min(cores));
        ThreadPoolBuilder::new().num_threads(threads).build().ok()
    })
    .as_ref()
}

pub(crate) fn threads() -> usize {
    pool().map_or(1, ThreadPool::current_num_threads)
}

/// Runs independent work concurrently, retaining the input order.
pub(crate) fn map<T: Sync, R: Send>(items: &[T], work: impl Fn(&T) -> R + Sync + Send) -> Vec<R> {
    use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

    if items.len() <= 1 {
        return items.iter().map(work).collect();
    }
    match pool() {
        Some(pool) if pool.current_num_threads() > 1 => {
            pool.install(|| items.par_iter().with_max_len(1).map(work).collect())
        }
        Some(_) => items.iter().map(work).collect(),
        None => items.iter().map(work).collect(),
    }
}
