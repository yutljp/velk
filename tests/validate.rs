//! Every rewrite the passes apply while decompiling the fixtures, checked
//! with z3 as it is applied: run with
//! `cargo test --release --features validate --test validate`.
//! `VELK_VALIDATE_FIXTURES` limits the run to fixtures whose path contains
//! one of its comma-separated parts. `VELK_VALIDATE_APPLICATIONS`, a
//! comma-separated list of application numbers, checks those applications
//! whole and nothing else, for looking into one again.
//! `VELK_VALIDATE_WORKERS` is how many checks run at once, as many as the
//! machine has processors unless given.
//! `VELK_VALIDATE_SECONDS` is the elapsed time one whole check may take,
//! 60 unless given and unbounded when 0; an application it runs out on is
//! listed undecided, to be checked again alone without the bound.
//!
//! A binary's statements are checked a function at a time and its
//! applications as each is recorded, so that the queries held at once are
//! those of one function and the applications about as many as the workers.
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
/// Solver work allowed for a query with bounds propagation, and for the
/// Horn query.
const BOUNDED_RLIMIT: u64 = 1_000_000_000;
/// Seconds one whole check may take unless `VELK_VALIDATE_SECONDS` says.
const SECONDS: u64 = 60;

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
/// cached analysis skips the passes it would check; and calls `each` after
/// each function.
fn decompile(fixture: &std::path::Path, each: &mut dyn FnMut()) {
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
            each();
        }
    }
}

/// Where an application the check does not prove is saved.
fn saved(directory: &std::path::Path, application: &Application) -> std::path::PathBuf {
    saved_at(directory, &application.tag, application.index)
}

fn saved_at(directory: &std::path::Path, tag: &str, index: usize) -> std::path::PathBuf {
    let tag: String = tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    directory.join(format!("not-proved-{tag}-{index}.txt"))
}

/// What became of one application checked whole.
struct Checked {
    site: &'static str,
    index: usize,
    verdict: Verdict,
}

/// Ends the process when dropped by a panic.
struct EndRunOnPanic;

impl Drop for EndRunOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("a check panicked; the run ends here");
            std::process::exit(1);
        }
    }
}

/// Checks `application` in at most `seconds`, writing a line to `profile`:
/// where the solver work went, for finding what makes a run slow; and
/// saving it to `directory` when it is not proved.
fn check_one(
    application: &Application,
    seconds: Option<u64>,
    profile: &Mutex<std::fs::File>,
    directory: &std::path::Path,
) -> Checked {
    let started = std::time::Instant::now();
    let (verdict, stats) = product::check_measured(application, RLIMIT, BOUNDED_RLIMIT, seconds);
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
    std::io::Write::write_all(&mut *file, line.as_bytes()).expect("write the profile");
    Checked {
        site: application.site,
        index: application.index,
        verdict,
    }
}

#[test]
fn every_applied_rewrite_keeps_what_the_function_does() {
    if std::process::Command::new("z3")
        .arg("-version")
        .output()
        .is_err()
    {
        assert!(
            std::env::var_os("VELK_REQUIRE_SOLVER").is_none(),
            "rewrite validation: VELK_REQUIRE_SOLVER is set and z3 is not on PATH"
        );
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
    let seconds = std::env::var("VELK_VALIDATE_SECONDS")
        .map_or(SECONDS, |seconds| seconds.trim().parse().expect("seconds"));
    let seconds = (seconds != 0).then_some(seconds);
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
    let workers = std::env::var("VELK_VALIDATE_WORKERS").map_or_else(
        |_| std::thread::available_parallelism().map_or(4, |count| count.get()),
        |workers| workers.trim().parse().expect("a number of workers"),
    );
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
        let mut statements = 0;
        let mut local = std::time::Duration::ZERO;
        let mut wanted = BTreeSet::new();
        let mut fingerprints = BTreeMap::new();
        let mut statement_checks = |recorded: validate::Recorded| {
            for (key, count) in recorded.skipped {
                *skipped.entry(key).or_default() += count;
            }
            statements += recorded.obligations.len();
            wanted.extend(recorded.unchecked);
            fingerprints.extend(recorded.fingerprints);
            if only.is_some() {
                return;
            }
            let started = std::time::Instant::now();
            let answers = validate::solve(
                &recorded.obligations,
                workers.min(recorded.obligations.len()),
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
                                directory.join(format!(
                                    "slow-{number}-{}-{index}.smt2",
                                    obligation.application
                                )),
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
            );
            local += started.elapsed();
            for (obligation, answer) in recorded.obligations.iter().zip(&answers) {
                let site = sites.entry(obligation.site).or_default();
                if *answer == Answer::Proved {
                    site.statements += 1;
                } else {
                    site.deferred += 1;
                    wanted.insert(obligation.application);
                }
            }
        };
        validate::begin(&tag);
        decompile(fixture, &mut || statement_checks(validate::collect()));
        statement_checks(validate::take());
        let local = local.as_secs();
        let wanted: BTreeSet<usize> = only
            .clone()
            .unwrap_or(wanted)
            .into_iter()
            .filter(|application| fingerprints.contains_key(application))
            .collect();
        if !wanted.is_empty() {
            // Each application goes to the workers as its pass returns,
            // the decompiling thread waiting while all of them are busy, so
            // those held at once are about as many as the workers.
            let (sender, receiver) = std::sync::mpsc::sync_channel::<Application>(0);
            let receiver = Mutex::new(receiver);
            let checked = Mutex::new(Vec::new());
            let again = std::thread::scope(|scope| {
                for _ in 0..workers.clamp(1, wanted.len()) {
                    scope.spawn(|| {
                        loop {
                            let received = receiver.lock().expect("applications").recv();
                            let Ok(application) = received else {
                                break;
                            };
                            // A check that panics would leave the
                            // decompiling thread waiting for a worker.
                            let ending = EndRunOnPanic;
                            let one = check_one(&application, seconds, &profile, &directory);
                            drop(ending);
                            checked.lock().expect("verdicts").push(one);
                        }
                    });
                }
                validate::revisit(&tag, wanted.clone(), move |application| {
                    sender.send(application).expect("a worker takes it");
                });
                decompile(fixture, &mut || {});
                validate::take()
            });
            let mut checked = checked.into_inner().expect("verdicts");
            checked.sort_by_key(|one| one.index);
            let mut found = BTreeSet::new();
            for Checked {
                site,
                index,
                verdict,
            } in checked
            {
                found.insert(index);
                assert_eq!(
                    again.fingerprints.get(&index),
                    fingerprints.get(&index),
                    "{tag}: application {index} changed when decompiled again"
                );
                let site_name = site;
                let site = sites.entry(site).or_default();
                match verdict {
                    Verdict::Proved => site.proved += 1,
                    Verdict::Unchecked(reason) => {
                        *site.unchecked.entry(reason).or_default() += 1;
                    }
                    Verdict::Unknown { what, reason } => {
                        site.unknown += 1;
                        eprintln!(
                            "UNDECIDED {site_name} in {tag} (application {index}): {what}: {reason}"
                        );
                    }
                    Verdict::NotProved { what, state } => {
                        site.not_proved += 1;
                        writeln!(
                            report,
                            "{site_name} in {tag}: {what}\n  state: {state}\n  {}",
                            saved_at(&directory, &tag, index).display()
                        )
                        .expect("writing to a String");
                    }
                }
            }
            assert_eq!(
                found, wanted,
                "{tag}: decompiling again applied other passes"
            );
        }
        eprintln!(
            "{}/{} {tag}: {statements} statement checks in {local}s, {} applications checked whole, {}s",
            number + 1,
            fixtures.len(),
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
