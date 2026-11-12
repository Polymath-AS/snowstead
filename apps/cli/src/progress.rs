//! Terminal-only push progress. Machine-readable output never contains escapes.
use base64::{Engine, engine::general_purpose::STANDARD};
use indicatif::{
    HumanBytes, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle,
};
use std::{
    collections::BTreeMap,
    io::{IsTerminal, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};

#[derive(Clone)]
pub struct Progress {
    state: Arc<State>,
}

struct State {
    multi: MultiProgress,
    bar: ProgressBar,
    overflow: ProgressBar,
    paths: Mutex<Vec<(String, PathProgress)>>,
    terminal: bool,
    draw: bool,
    json: bool,
    skipped: AtomicU64,
    failed: AtomicU64,
    percent: AtomicU64,
    finished: AtomicBool,
}

#[derive(Clone)]
pub struct PathProgress {
    path: Arc<str>,
    bar: ProgressBar,
    retries: Arc<Mutex<BTreeMap<u32, (u32, u32)>>>,
}

impl PathProgress {
    pub fn phase(&self, message: &str) {
        let name = self.bar.prefix();
        let uploading = message == "Uploading" || message.starts_with("Retrying");
        let status_style = if message.contains("retry") || message.starts_with("Retrying") {
            ":.yellow"
        } else {
            ""
        };
        self.bar.set_style(
            ProgressStyle::with_template(&format!(
                "  {{spinner}} {{transfer}}  {{wide_msg{status_style}}}"
            ))
            .unwrap()
            .with_key(
                "transfer",
                move |state: &ProgressState, out: &mut dyn std::fmt::Write| {
                    // Recompute on each draw, including while a stalled request
                    // waits, so resizing never leaves a wide row in a narrow terminal.
                    let width = console::Term::stderr().size().1 as usize;
                    let name_width = width.saturating_sub(60).clamp(8, 32);
                    let name = console::truncate_str(&name, name_width, "…");
                    let bytes = match state.len() {
                        Some(total) => {
                            format!("{} / {}", HumanBytes(state.pos()), HumanBytes(total))
                        }
                        None => format!("{} sent", HumanBytes(state.pos())),
                    };
                    let _ = write!(out, "{name:<name_width$} {bytes:<21}");
                    if width >= 120 && uploading {
                        let _ = write!(out, " · {}/s", HumanBytes(state.per_sec() as u64));
                    }
                },
            ),
        );
        self.bar.set_message(message.to_owned());
    }

    pub fn encoded(&self, bytes: u64) {
        self.bar.set_length(bytes);
    }

    pub fn retry_part(&self, number: u32, attempt: u32, attempts: u32) {
        let mut retries = self.retries.lock().unwrap();
        retries.insert(number, (attempt, attempts));
        self.phase(&format!(
            "Retrying part {number} · attempt {attempt}/{attempts}"
        ));
    }

    pub fn part_uploaded(&self, number: u32, bytes: u64) {
        let mut retries = self.retries.lock().unwrap();
        retries.remove(&number);
        self.bar.inc(bytes);
        if let Some((&number, &(attempt, attempts))) = retries.first_key_value() {
            self.phase(&format!(
                "Retrying part {number} · attempt {attempt}/{attempts}"
            ));
        } else {
            self.phase("Uploading");
        }
    }

    pub fn published(&self, inline_bytes: Option<u64>, prepared: bool) {
        if let Some(bytes) = inline_bytes {
            self.bar.set_position(bytes);
        }
        self.phase(if prepared { "Prepared" } else { "Published" });
    }
}

impl Progress {
    pub fn new(json: bool, verbose: bool) -> Self {
        let terminal = !json
            && std::io::stderr().is_terminal()
            && std::env::var("TERM").is_ok_and(|term| term != "dumb");
        let draw = terminal && !verbose;
        let multi = MultiProgress::with_draw_target(if draw {
            ProgressDrawTarget::stderr()
        } else {
            ProgressDrawTarget::hidden()
        });
        let bar = multi.add(ProgressBar::hidden());
        let overflow = multi.add(ProgressBar::hidden());
        overflow.set_style(ProgressStyle::with_template("  {msg}").unwrap());
        if draw {
            bar.enable_steady_tick(Duration::from_millis(100));
        }
        Self {
            state: Arc::new(State {
                multi,
                bar,
                overflow,
                paths: Mutex::new(Vec::new()),
                terminal,
                draw,
                json,
                skipped: AtomicU64::new(0),
                failed: AtomicU64::new(0),
                percent: AtomicU64::new(u64::MAX),
                finished: AtomicBool::new(false),
            }),
        }
    }

    pub fn phase(&self, message: &str) {
        let state = &self.state;
        state
            .bar
            .set_style(ProgressStyle::with_template("{spinner} {msg}").unwrap());
        state.bar.set_message(message.to_owned());
        if !state.draw {
            self.println(message);
        }
        state.report("working", None, message);
    }

    pub fn println(&self, message: &str) {
        let state = &self.state;
        if state.draw {
            let _ = state.multi.println(message);
        } else if state.json {
            eprintln!("{message}");
        } else {
            println!("{message}");
        }
    }

    pub fn start(&self, action: &str, total: usize, skipped: usize) {
        let state = &self.state;
        state.skipped.store(skipped as u64, Relaxed);
        state.failed.store(0, Relaxed);
        state.bar.set_prefix(action.to_owned());
        state.bar.set_style(
            ProgressStyle::with_template(
                "{prefix} {spinner} [{bar:16.cyan/blue}] {pos}/{len} paths ({percent}%)\n{msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        state.bar.set_length(total as u64);
        state.bar.set_position(skipped as u64);
        self.update();
    }

    pub fn add_path(&self, id: &str, path: &str) -> PathProgress {
        let row = PathProgress {
            path: path.into(),
            bar: ProgressBar::hidden(),
            retries: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let base = path.rsplit('/').next().unwrap_or(path);
        row.bar.set_prefix(
            base.split_once('-')
                .map_or(base, |(_, name)| name)
                .to_owned(),
        );
        row.phase("Preparing…");
        if self.state.draw {
            let mut paths = self.state.paths.lock().unwrap();
            if paths.len() < 4 {
                self.state
                    .multi
                    .insert_before(&self.state.overflow, row.bar.clone());
                row.bar.enable_steady_tick(Duration::from_millis(100));
            }
            paths.push((id.to_owned(), row.clone()));
            self.update_overflow(paths.len());
        }
        row
    }

    pub fn path(&self, id: &str) -> Option<PathProgress> {
        self.state
            .paths
            .lock()
            .unwrap()
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, row)| row.clone())
    }

    pub fn finish_path(&self, id: &str, error: Option<&str>) {
        let mut paths = self.state.paths.lock().unwrap();
        if let Some(index) = paths.iter().position(|(key, _)| key == id) {
            let (_, row) = paths.remove(index);
            if let Some(error) = error {
                let line = format!("✗ {}: {error}", row.path);
                let _ = self.state.multi.println(
                    console::Style::new()
                        .for_stderr()
                        .red()
                        .apply_to(line)
                        .to_string(),
                );
            }
            row.bar.finish_and_clear();
            self.state.multi.remove(&row.bar);
            if index < 4
                && let Some((_, row)) = paths.get(3)
            {
                self.state
                    .multi
                    .insert_before(&self.state.overflow, row.bar.clone());
                row.bar.enable_steady_tick(Duration::from_millis(100));
            }
            self.update_overflow(paths.len());
        }
    }

    fn update_overflow(&self, count: usize) {
        self.state.overflow.set_message(if count > 4 {
            format!("+ {} other active paths", count - 4)
        } else {
            String::new()
        });
    }

    pub fn path_finished(&self, failed: bool) {
        let state = &self.state;
        if failed {
            state.failed.fetch_add(1, Relaxed);
        }
        state.bar.inc(1);
        self.update();
    }

    fn update(&self) {
        let state = &self.state;
        let skipped = state.skipped.load(Relaxed);
        let failed = state.failed.load(Relaxed);
        let completed = state.bar.position().saturating_sub(skipped + failed);
        let action = if state.bar.prefix() == "Preparing" {
            "prepared"
        } else {
            "pushed"
        };
        state.bar.set_message(format!(
            "{completed} {action}, {skipped} skipped, {failed} failed"
        ));
        let total = state.bar.length().unwrap_or(0);
        let percent = (state.bar.position() * 100)
            .checked_div(total)
            .unwrap_or(100)
            .min(100);
        if state.percent.swap(percent, Relaxed) != percent {
            state.report(
                "working",
                Some(percent),
                &format!("{} paths", state.bar.prefix()),
            );
        }
    }

    pub fn finish(&self, status: &str, message: &str) {
        self.state.finish(status, message);
    }
}

impl State {
    fn finish(&self, state: &str, message: &str) {
        // Detached batch requests can outlive cancellation. Hide the target so
        // their last acknowledgement cannot redraw rows after the final status.
        self.bar.finish_and_clear();
        for (_, row) in self.paths.lock().unwrap().drain(..) {
            row.bar.finish_and_clear();
            self.multi.remove(&row.bar);
        }
        self.overflow.finish_and_clear();
        let _ = self.multi.clear();
        self.multi.set_draw_target(ProgressDrawTarget::hidden());
        self.report(state, None, message);
        self.finished.store(true, Relaxed);
    }

    fn report(&self, state: &str, percent: Option<u64>, message: &str) {
        if !self.terminal {
            return;
        }
        let progress = percent.map_or_else(String::new, |p| format!(":progress={p}"));
        self.multi.suspend(|| {
            let mut stderr = std::io::stderr().lock();
            let _ = write!(
                stderr,
                "\x1b]7501;state={state}:app=snowstead{progress}:msg={}\x1b\\",
                STANDARD.encode(message)
            );
            let _ = stderr.flush();
        });
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if !self.finished.load(Relaxed) {
            self.finish("error", "Push failed");
        }
    }
}
