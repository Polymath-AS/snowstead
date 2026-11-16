//! How a pool of background workers waits for SQL work without polling for
//! it. A worker that finds nothing sleeps until the first of: a wake from
//! this process, sent after the commit that made work due; the time the
//! worker itself read as the next at which waiting work becomes due; and a
//! slow fallback for what this process never saw (another instance, a crash
//! between a commit and its wake, a manual change).
//!
//! One wake rouses one worker. The worker that claims work passes a wake on
//! before it starts, so a second idle worker looks for the rest while every
//! other one stays asleep. No wake is lost: with no worker waiting, the wake
//! is stored and ends the next wait at once, and a worker only starts waiting
//! after a full scan that found nothing.
use std::time::Duration;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// How long an idle worker sleeps with no wake and no known due time.
pub(crate) const FALLBACK: Duration = Duration::from_secs(30);
/// The former poll interval: how long a worker waits before it looks again
/// after work it found but did not finish.
const MISS: Duration = Duration::from_millis(100);
/// The shortest wait for a due time. One already past means the work became
/// due, or was taken, as the scan ran: look again soon, without spinning.
const SOONEST: Duration = Duration::from_millis(10);

#[derive(Default)]
pub(crate) struct Wake(Notify);

impl Wake {
    /// Call after the commit that makes work due, never before: a worker
    /// that looks first finds nothing and sleeps again.
    pub(crate) fn wake(&self) {
        // A stored permit wakes a worker that is busy or has not started yet.
        self.0.notify_one();
    }
}

#[derive(Debug)]
pub(crate) enum Turn {
    /// Claimed work. Look again at once.
    Worked,
    /// Found due work and did not finish it: another writer held the row, or
    /// the attempt recorded the work's own backoff.
    Missed,
    /// A scan of everything found nothing due. The next due time, if any
    /// waiting work has one, as an interval from now.
    Idle(Option<Duration>),
}

/// The pause after a failed turn: 100 ms, doubling to 5 s. A failure waits
/// neither for the fallback nor for nothing.
pub(crate) struct Backoff(Duration);

impl Default for Backoff {
    fn default() -> Self {
        Self(Self::FIRST)
    }
}

impl Backoff {
    const FIRST: Duration = Duration::from_millis(100);
    const LAST: Duration = Duration::from_secs(5);

    pub(crate) fn next(&mut self) -> Duration {
        let pause = self.0;
        self.0 = (pause * 2).min(Self::LAST);
        pause
    }

    pub(crate) fn reset(&mut self) {
        self.0 = Self::FIRST;
    }
}

/// One worker's waits between its turns. Shutdown interrupts a wait, never
/// a turn.
pub(crate) struct Pace<'a> {
    wake: &'a Wake,
    stopped: &'a CancellationToken,
    fallback: Duration,
    failures: Backoff,
}

impl<'a> Pace<'a> {
    pub(crate) fn new(wake: &'a Wake, stopped: &'a CancellationToken, fallback: Duration) -> Self {
        Self {
            wake,
            stopped,
            fallback,
            failures: Backoff::default(),
        }
    }

    /// Whether to take another turn.
    pub(crate) fn running(&self) -> bool {
        !self.stopped.is_cancelled()
    }

    /// Wait as the turn that just ended asks.
    pub(crate) async fn after<E>(&mut self, turn: Result<Turn, E>) {
        let pause = match turn {
            Ok(Turn::Worked) => {
                self.failures.reset();
                return tokio::task::yield_now().await;
            }
            Ok(Turn::Idle(due)) => {
                self.failures.reset();
                let timer = due.map_or(self.fallback, |due| due.max(SOONEST).min(self.fallback));
                tokio::select! {
                    _ = self.stopped.cancelled() => {}
                    _ = self.wake.0.notified() => {}
                    _ = tokio::time::sleep(timer) => {}
                }
                return;
            }
            Ok(Turn::Missed) => {
                self.failures.reset();
                MISS
            }
            Err(_) => self.failures.next(),
        };
        // A wake during this pause stays stored for the wait that follows.
        tokio::select! {
            _ = self.stopped.cancelled() => {}
            _ = tokio::time::sleep(pause) => {}
        }
    }
}

/// Seconds until a due time read from SQL, as an interval from now. A time
/// already past is due now; one too far for a timer is left to the fallback.
pub(crate) fn until(seconds: Option<f64>) -> Option<Duration> {
    seconds.map(|seconds| Duration::try_from_secs_f64(seconds.max(0.0)).unwrap_or(FALLBACK))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::{Semaphore, mpsc};

    const NEVER: Duration = Duration::from_secs(3600);
    const SOON: Duration = Duration::from_secs(20);

    struct Worker {
        wake: Arc<Wake>,
        stopped: CancellationToken,
        /// One message as each turn starts.
        started: mpsc::UnboundedReceiver<()>,
        /// A turn ends once it is given a permit.
        finish: Arc<Semaphore>,
        task: tokio::task::JoinHandle<()>,
    }

    /// A worker whose every turn reports `outcome`, with fallback `NEVER`.
    fn worker(wake: Arc<Wake>, outcome: fn(usize) -> Result<Turn, ()>) -> Worker {
        let stopped = CancellationToken::new();
        let (start, started) = mpsc::unbounded_channel();
        let finish = Arc::new(Semaphore::new(0));
        let task = tokio::spawn({
            let (wake, stopped, finish) = (wake.clone(), stopped.clone(), finish.clone());
            async move {
                let mut pace = Pace::new(&wake, &stopped, NEVER);
                let mut turns = 0;
                while pace.running() {
                    start.send(()).unwrap();
                    finish.acquire().await.unwrap().forget();
                    pace.after(outcome(turns)).await;
                    turns += 1;
                }
            }
        });
        Worker {
            wake,
            stopped,
            started,
            finish,
            task,
        }
    }

    impl Worker {
        async fn turn_starts(&mut self) {
            tokio::time::timeout(SOON, self.started.recv())
                .await
                .expect("the worker did not look again")
                .unwrap();
        }

        async fn stop(self) {
            self.stopped.cancel();
            self.finish.add_permits(usize::MAX >> 4);
            tokio::time::timeout(SOON, self.task)
                .await
                .expect("the worker did not stop")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn a_wake_during_a_turn_that_finds_nothing_causes_another_look() {
        let mut worker = worker(Arc::default(), |_| Ok(Turn::Idle(None)));
        worker.turn_starts().await;
        // The scan is in flight and will report nothing: its snapshot
        // predates the commit this wake follows.
        worker.wake.wake();
        worker.finish.add_permits(1);
        // Only the stored wake can end a wait that is an hour long.
        worker.turn_starts().await;
        worker.stop().await;
    }

    #[tokio::test]
    async fn a_wake_before_the_worker_starts_or_during_a_failed_turn_is_kept() {
        let wake = Arc::<Wake>::default();
        wake.wake();
        // The second turn fails. Every other one finds nothing.
        let mut worker = worker(wake, |turn| {
            if turn == 1 {
                Err(())
            } else {
                Ok(Turn::Idle(None))
            }
        });
        worker.turn_starts().await;
        worker.finish.add_permits(1);
        // The wake from before the start ended the first wait.
        worker.turn_starts().await;
        worker.wake.wake();
        worker.finish.add_permits(1);
        // The pause after a failure is not the wait, and does not use it up.
        worker.turn_starts().await;
        worker.finish.add_permits(1);
        worker.turn_starts().await;
        worker.stop().await;
    }

    #[tokio::test]
    async fn two_wakes_rouse_two_waiting_workers_and_one_wake_only_one() {
        let wake = Arc::<Wake>::default();
        let mut workers = [
            worker(wake.clone(), |_| Ok(Turn::Idle(None))),
            worker(wake.clone(), |_| Ok(Turn::Idle(None))),
        ];
        for worker in &mut workers {
            worker.turn_starts().await;
            worker.finish.add_permits(1);
        }
        // However these land (on a waiting worker or as the one stored
        // wake), a claim's wake reaches a worker other than the claimant: a
        // turn is in flight when it is sent, so the claimant is not waiting.
        wake.wake();
        let [first, second] = &mut workers;
        let claimant = tokio::select! {
            _ = first.started.recv() => 0,
            _ = second.started.recv() => 1,
        };
        wake.wake();
        workers[1 - claimant].turn_starts().await;
        // Nothing woke the claimant again.
        workers[claimant].finish.add_permits(1);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), workers[claimant].started.recv())
                .await
                .is_err()
        );
        for worker in workers {
            worker.stop().await;
        }
    }

    #[tokio::test]
    async fn a_known_due_time_ends_the_wait_and_a_failure_does_not_wait_for_the_fallback() {
        let mut due = worker(Arc::default(), |_| {
            Ok(Turn::Idle(Some(Duration::from_millis(50))))
        });
        let mut failing = worker(Arc::default(), |_| Err(()));
        for worker in [&mut due, &mut failing] {
            for _ in 0..3 {
                worker.turn_starts().await;
                worker.finish.add_permits(1);
            }
        }
        due.stop().await;
        failing.stop().await;
    }

    #[test]
    fn failures_back_off_to_a_cap_and_reset() {
        let mut backoff = Backoff::default();
        let pauses: Vec<_> = (0..8).map(|_| backoff.next().as_millis()).collect();
        assert_eq!(pauses, [100, 200, 400, 800, 1600, 3200, 5000, 5000]);
        backoff.reset();
        assert_eq!(backoff.next().as_millis(), 100);
    }

    #[test]
    fn due_times_become_bounded_intervals() {
        assert_eq!(until(None), None);
        assert_eq!(until(Some(-3.0)), Some(Duration::ZERO));
        assert_eq!(until(Some(0.25)), Some(Duration::from_millis(250)));
        assert_eq!(until(Some(f64::INFINITY)), Some(FALLBACK));
    }
}
