//! Every rewrite the passes apply while decompiling the fixtures, checked
//! with z3 as it is applied: run with
//! `cargo test --release --features validate --test validate`.
//! `VELK_VALIDATE_FIXTURES` limits the run to fixtures whose path contains
//! one of its comma-separated parts. `VELK_VALIDATE_APPLICATIONS`, a
//! comma-separated list of application numbers, checks those applications
//! whole and nothing else, for looking into one again.
//!
//! Each rewritten statement is first compared with the original given the
//! statements before it in its block. A pass application with a rewrite that
//! comparison does not prove, or cannot take, is decompiled again and
//! checked as a whole: the function before it against the function after it.
#![cfg(feature = "validate")]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use velk::loader::OpenOptions;
use velk::service::{Binary, CacheLocation};
use velk::validate::product::{self, Application, Verdict};
use velk::validate::{self, Answer, Strategy};

/// Solver work allowed for one query, independent of system load.
const RLIMIT: u64 = 50_000_000;
/// Statement checks taking at least this many seconds are listed.
const SLOW_SECONDS: f64 = 5.0;
/// Statement checks taking at least this many seconds are saved whole.
const SAVED_SECONDS: f64 = 60.0;
/// Solver work allowed for a query word-level reasoning left undecided.
const BIT_LEVEL_RLIMIT: u64 = 1_000_000_000;

#[derive(Default)]
struct Sites {
    /// Statements proved one at a time.
    statements: usize,
    /// Statements left to the whole-function check.
    deferred: usize,
    proved: usize,
    not_proved: usize,
    unknown: usize,
    unchecked: BTreeMap<&'static str, usize>,
}

/// Decompiles every function of `fixture`, without the analysis cache: a
/// cached analysis skips the passes it would check.
fn decompile(fixture: &std::path::Path) {
    let options = OpenOptions {
        cache: Some(CacheLocation::Enabled(false)),
        ..OpenOptions::default()
    };
    if let Ok(mut binary) =
        Binary::open_input(&common::fixtures_dir().join(fixture), None, &options)
    {
        let addresses: Vec<u64> = binary.image().functions.keys().copied().collect();
        for address in addresses {
            let _ = binary.decompile(address, None, None);
        }
    }
}

/// Where an application the check does not prove is saved.
fn saved(directory: &std::path::Path, application: &Application) -> std::path::PathBuf {
    let tag: String = application
        .tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    directory.join(format!("not-proved-{tag}-{}.txt", application.index))
}

/// Checks `applications`, writing a line for each to `profile` as it is
/// checked: where the solver work went, for finding what makes a run slow;
/// and saving one not proved to `directory` once it is checked.
fn check_all(
    applications: &[Application],
    workers: usize,
    profile: &Mutex<std::fs::File>,
    directory: &std::path::Path,
) -> Vec<Verdict> {
    let next = AtomicUsize::new(0);
    let verdicts = Mutex::new(vec![None; applications.len()]);
    std::thread::scope(|scope| {
        for _ in 0..workers.max(1) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(application) = applications.get(index) else {
                        break;
                    };
                    let started = std::time::Instant::now();
                    let (verdict, stats) =
                        product::check_measured(application, RLIMIT, BIT_LEVEL_RLIMIT);
                    let line = format!(
                        "{}\t{}\t{}\t{:.1}\t{}\t{}\t{}\t{:?}\t{:?}\t{:?}\t{}\n",
                        application.tag,
                        application.site,
                        application.index,
                        started.elapsed().as_secs_f64(),
                        stats.blocks,
                        stats.candidates,
                        stats.rounds,
                        stats.queries,
                        stats.undecided,
                        stats.seconds.map(|seconds| seconds.round()),
                        match &verdict {
                            Verdict::Proved => "proved",
                            Verdict::NotProved { .. } => "not proved",
                            Verdict::Unknown { .. } => "undecided",
                            Verdict::Unchecked(_) => "unchecked",
                        }
                    );
                    if let Verdict::NotProved { what, state } = &verdict {
                        std::fs::write(
                            saved(directory, application),
                            format!(
                                "{} in {} (application {})\n{what}\nstate: {state}\n\nbefore:\n{:#?}\n\nafter:\n{:#?}\n",
                                application.site,
                                application.tag,
                                application.index,
                                application.before,
                                application.after
                            ),
                        )
                        .expect("save the application");
                    }
                    let mut file = profile.lock().expect("profile");
                    std::io::Write::write_all(&mut *file, line.as_bytes())
                        .expect("write the profile");
                    verdicts.lock().expect("verdicts")[index] = Some(verdict);
                }
            });
        }
    });
    verdicts
        .into_inner()
        .expect("verdicts")
        .into_iter()
        .map(|verdict| verdict.expect("every application checked"))
        .collect()
}

#[test]
fn every_applied_rewrite_keeps_what_the_function_does() {
    if std::process::Command::new("z3")
        .arg("-version")
        .output()
        .is_err()
    {
        eprintln!("SKIP rewrite validation: z3 unavailable");
        return;
    }
    let filter = std::env::var("VELK_VALIDATE_FIXTURES").ok();
    let only: Option<BTreeSet<usize>> =
        std::env::var("VELK_VALIDATE_APPLICATIONS")
            .ok()
            .map(|list| {
                list.split(',')
                    .map(|number| number.trim().parse().expect("an application number"))
                    .collect()
            });
    let fixtures: Vec<_> = common::fixtures()
        .into_iter()
        .filter(|fixture| {
            filter.as_deref().is_none_or(|filter| {
                filter
                    .split(',')
                    .any(|part| fixture.to_string_lossy().contains(part))
            })
        })
        .collect();
    let workers = std::thread::available_parallelism().map_or(4, |count| count.get());
    let directory = common::root().join("target/validate");
    let _ = std::fs::remove_dir_all(&directory);
    // Where the solver work went, one line per application checked whole.
    let profile = Mutex::new(
        std::fs::File::create(common::root().join("target/validate-profile.tsv"))
            .expect("create the profile"),
    );
    // The statement checks that take long, for the same purpose.
    let slow = Mutex::new(
        std::fs::File::create(common::root().join("target/validate-slow.tsv"))
            .expect("create the slow queries"),
    );
    std::fs::create_dir_all(&directory).expect("create target/validate");
    let start = std::time::Instant::now();
    let mut sites: BTreeMap<&'static str, Sites> = BTreeMap::new();
    let mut skipped: BTreeMap<(&'static str, String), usize> = BTreeMap::new();
    let mut report = String::new();
    for (number, fixture) in fixtures.iter().enumerate() {
        let tag = fixture.to_string_lossy().into_owned();
        validate::begin(&tag);
        decompile(fixture);
        let recorded = validate::take();
        for (key, count) in recorded.skipped {
            *skipped.entry(key).or_default() += count;
        }
        let local = std::time::Instant::now();
        let answers = if only.is_some() {
            Vec::new()
        } else {
            validate::solve(
                &recorded.obligations,
                workers,
                RLIMIT,
                &[Strategy::WordLevel, Strategy::Integer],
                &|index, answer, seconds| {
                    if seconds >= SLOW_SECONDS {
                        let obligation = &recorded.obligations[index];
                        let line = format!(
                            "{tag}\t{}\t{}\t{seconds:.1}\t{}\n",
                            obligation.site,
                            obligation.application,
                            match answer {
                                Answer::Proved => "proved",
                                Answer::Counterexample(_) => "counterexample",
                                Answer::Unknown(_) => "undecided",
                            }
                        );
                        let mut file = slow.lock().expect("slow queries");
                        std::io::Write::write_all(&mut *file, line.as_bytes())
                            .expect("write the slow queries");
                        if seconds >= SAVED_SECONDS {
                            std::fs::write(
                                directory.join(format!("slow-{number}-{index}.smt2")),
                                format!(
                                    "(set-option :rlimit {RLIMIT})\n{}{}",
                                    obligation.query,
                                    Strategy::WordLevel.check()
                                ),
                            )
                            .expect("save the slow query");
                        }
                    }
                },
            )
        };
        let local = local.elapsed().as_secs();
        let mut wanted = recorded.unchecked.clone();
        for (obligation, answer) in recorded.obligations.iter().zip(&answers) {
            let site = sites.entry(obligation.site).or_default();
            if *answer == Answer::Proved {
                site.statements += 1;
            } else {
                site.deferred += 1;
                wanted.insert(obligation.application);
            }
        }
        let wanted: BTreeSet<usize> = only
            .clone()
            .unwrap_or(wanted)
            .into_iter()
            .filter(|application| recorded.fingerprints.contains_key(application))
            .collect();
        if !wanted.is_empty() {
            validate::revisit(&tag, wanted.clone());
            decompile(fixture);
            let again = validate::take();
            let found: BTreeSet<usize> = again
                .applications
                .iter()
                .map(|application| application.index)
                .collect();
            assert_eq!(
                found, wanted,
                "{tag}: decompiling again applied other passes"
            );
            for application in &again.applications {
                assert_eq!(
                    again.fingerprints.get(&application.index),
                    recorded.fingerprints.get(&application.index),
                    "{tag}: application {} changed when decompiled again",
                    application.index
                );
            }
            let verdicts = check_all(&again.applications, workers, &profile, &directory);
            for (application, verdict) in again.applications.iter().zip(verdicts) {
                let site = sites.entry(application.site).or_default();
                match verdict {
                    Verdict::Proved => site.proved += 1,
                    Verdict::Unchecked(reason) => {
                        *site.unchecked.entry(reason).or_default() += 1;
                    }
                    Verdict::Unknown { what, reason } => {
                        site.unknown += 1;
                        eprintln!(
                            "UNDECIDED {} in {tag} (application {}): {what}: {reason}",
                            application.site, application.index
                        );
                    }
                    Verdict::NotProved { what, state } => {
                        site.not_proved += 1;
                        let path = saved(&directory, application);
                        writeln!(
                            report,
                            "{} in {tag}: {what}\n  state: {state}\n  {}",
                            application.site,
                            path.display()
                        )
                        .expect("writing to a String");
                    }
                }
            }
        }
        eprintln!(
            "{}/{} {tag}: {} statement checks in {local}s, {} applications checked whole, {}s",
            number + 1,
            fixtures.len(),
            recorded.obligations.len(),
            wanted.len(),
            start.elapsed().as_secs()
        );
    }
    eprintln!("validation over {} fixtures:", fixtures.len());
    for (site, tally) in &sites {
        eprintln!(
            "  {site}: {} statements proved, {} left to the whole-function check; \
             applications: {} proved, {} not proved, {} undecided",
            tally.statements, tally.deferred, tally.proved, tally.not_proved, tally.unknown
        );
        for (reason, count) in &tally.unchecked {
            eprintln!("    {count} applications not checked: {reason}");
        }
    }
    for ((site, reason), count) in &skipped {
        eprintln!("  {site}: {count} statements not compared one at a time: {reason}");
    }
    assert!(
        report.is_empty(),
        "applications the check does not prove keep what the function does \
         (a changed meaning, or a fact the inferred invariants miss):\n{report}"
    );
}
