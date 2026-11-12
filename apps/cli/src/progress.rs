//! Terminal-only push progress. Machine-readable output never contains escapes.
use base64::{Engine, engine::general_purpose::STANDARD};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::{
    io::{IsTerminal, Write},
    sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    time::Duration,
};

pub struct Progress {
    bar: ProgressBar,
    terminal: bool,
    draw: bool,
    json: bool,
    skipped: AtomicU64,
    failed: AtomicU64,
    percent: AtomicU64,
    finished: AtomicBool,
}

impl Progress {
    pub fn new(json: bool, verbose: bool) -> Self {
        let terminal = !json
            && std::io::stderr().is_terminal()
            && std::env::var("TERM").is_ok_and(|term| term != "dumb");
        let draw = terminal && !verbose;
        let bar = ProgressBar::with_draw_target(
            None,
            if draw {
                ProgressDrawTarget::stderr()
            } else {
                ProgressDrawTarget::hidden()
            },
        );
        if draw {
            bar.enable_steady_tick(Duration::from_millis(100));
        }
        Self {
            bar,
            terminal,
            draw,
            json,
            skipped: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            percent: AtomicU64::new(u64::MAX),
            finished: AtomicBool::new(false),
        }
    }

    pub fn phase(&self, message: &str) {
        self.bar
            .set_style(ProgressStyle::with_template("{spinner} {msg}").unwrap());
        self.bar.set_message(message.to_owned());
        if !self.draw {
            self.println(message);
        }
        self.report("working", None, message);
    }

    pub fn println(&self, message: &str) {
        if self.draw {
            self.bar.println(message);
        } else if self.json {
            eprintln!("{message}");
        } else {
            println!("{message}");
        }
    }

    pub fn start(&self, action: &str, total: usize, skipped: usize) {
        self.skipped.store(skipped as u64, Relaxed);
        self.failed.store(0, Relaxed);
        self.bar.set_prefix(action.to_owned());
        self.bar.set_style(
            ProgressStyle::with_template(
                "{prefix} {spinner} [{bar:24.cyan/blue}] {pos}/{len} paths ({percent}%) {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        self.bar.set_length(total as u64);
        self.bar.set_position(skipped as u64);
        self.update();
    }

    pub fn path_finished(&self, failed: bool) {
        if failed {
            self.failed.fetch_add(1, Relaxed);
        }
        self.bar.inc(1);
        self.update();
    }

    fn update(&self) {
        self.bar.set_message(format!(
            "{} skipped, {} failed",
            self.skipped.load(Relaxed),
            self.failed.load(Relaxed)
        ));
        let total = self.bar.length().unwrap_or(0);
        let percent = (self.bar.position() * 100)
            .checked_div(total)
            .unwrap_or(100)
            .min(100);
        if self.percent.swap(percent, Relaxed) != percent {
            self.report(
                "working",
                Some(percent),
                &format!("{} paths", self.bar.prefix()),
            );
        }
    }

    pub fn finish(&self, state: &str, message: &str) {
        self.bar.finish_and_clear();
        self.report(state, None, message);
        self.finished.store(true, Relaxed);
    }

    fn report(&self, state: &str, percent: Option<u64>, message: &str) {
        if !self.terminal {
            return;
        }
        let progress = percent.map_or_else(String::new, |p| format!(":progress={p}"));
        let mut stderr = std::io::stderr().lock();
        let _ = write!(
            stderr,
            "\x1b]7501;state={state}:app=snowstead{progress}:msg={}\x1b\\",
            STANDARD.encode(message)
        );
        let _ = stderr.flush();
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if !self.finished.load(Relaxed) {
            self.finish("error", "Push failed");
        }
    }
}
