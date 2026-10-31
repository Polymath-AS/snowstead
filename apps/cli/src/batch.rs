use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
type Reply<R> = oneshot::Sender<Result<R, Arc<str>>>;
pub struct Batcher<T, R> {
    sender: mpsc::Sender<(T, Reply<R>)>,
}
impl<T, R> Clone for Batcher<T, R> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}
impl<T: Send + 'static, R: Send + 'static> Batcher<T, R> {
    pub fn new<F, Fut>(max_size: usize, concurrency: usize, delay: Duration, operation: F) -> Self
    where
        F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<Vec<R>>> + Send + 'static,
    {
        assert!(concurrency > 0);
        let (sender, mut receiver) = mpsc::channel::<(T, Reply<R>)>(max_size);
        let operation = Arc::new(operation);
        tokio::spawn(async move {
            let mut batches = JoinSet::new();
            loop {
                while batches.len() >= concurrency {
                    batches.join_next().await;
                }
                let first = tokio::select! {
                    value = receiver.recv() => value,
                    _ = batches.join_next(), if !batches.is_empty() => continue,
                };
                let Some(first) = first else {
                    break;
                };
                let mut values = vec![first.0];
                let mut replies = vec![first.1];
                let mut deadline = tokio::time::Instant::now() + delay;
                while values.len() < max_size {
                    // Additional lanes only take full batches. A partial batch
                    // waits for active work, then gets the ordinary collection
                    // window. This preserves batching without stranding a tail
                    // whose remaining paths depend on its publication.
                    let next = if batches.is_empty() {
                        tokio::time::timeout_at(deadline, receiver.recv())
                            .await
                            .unwrap_or(None)
                    } else {
                        tokio::select! {
                            value = receiver.recv() => value,
                            _ = batches.join_next() => {
                                if batches.is_empty() {
                                    deadline = tokio::time::Instant::now() + delay;
                                }
                                continue;
                            }
                        }
                    };
                    match next {
                        Some((value, reply)) => {
                            values.push(value);
                            replies.push(reply)
                        }
                        None => break,
                    }
                }
                while values.len() < max_size && !batches.is_empty() {
                    batches.join_next().await;
                }
                let operation = operation.clone();
                batches.spawn(async move {
                    let answer = operation(values).await.and_then(|rows| {
                        if rows.len() != replies.len() {
                            anyhow::bail!("API batch response length differs from request")
                        }
                        Ok(rows)
                    });
                    match answer {
                        Ok(rows) => {
                            for (row, reply) in rows.into_iter().zip(replies) {
                                let _ = reply.send(Ok(row));
                            }
                        }
                        Err(e) => {
                            let error: Arc<str> = format!("{e:#}").into();
                            for reply in replies {
                                let _ = reply.send(Err(error.clone()));
                            }
                        }
                    }
                });
            }
            while batches.join_next().await.is_some() {}
        });
        Self { sender }
    }
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn request(&self, value: T) -> anyhow::Result<R> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((value, tx))
            .await
            .map_err(|_| anyhow::anyhow!("upload batch stopped"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("upload batch stopped"))?
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::join_all;
    use tokio::sync::{Mutex, Semaphore};

    #[tokio::test]
    async fn concurrent_batches_fill_before_flushing_and_partial_tails_survive_errors() {
        let first_gate = Arc::new(Semaphore::new(0));
        let second_gate = Arc::new(Semaphore::new(0));
        let (started, mut starts) = mpsc::unbounded_channel();
        let batch = Batcher::new(2, 2, Duration::from_millis(10), {
            let first_gate = first_gate.clone();
            let second_gate = second_gate.clone();
            move |items: Vec<u32>| {
                let started = started.clone();
                let first_gate = first_gate.clone();
                let second_gate = second_gate.clone();
                async move {
                    started.send(items.clone()).unwrap();
                    if items.contains(&0) {
                        let _permit = first_gate.acquire().await.unwrap();
                        anyhow::bail!("first batch failed");
                    }
                    if items.contains(&2) {
                        let _permit = second_gate.acquire().await.unwrap();
                    }
                    Ok(items.into_iter().map(|id| id * 7).collect())
                }
            }
        });
        let request = |id| {
            let batch = batch.clone();
            tokio::spawn(async move { batch.request(id).await })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            let first = request(0);
            let second = request(1);
            assert_eq!(starts.recv().await, Some(vec![0, 1]));

            let third = request(2);
            assert!(
                tokio::time::timeout(Duration::from_millis(30), starts.recv())
                    .await
                    .is_err(),
                "a free lane must not fragment a partial batch"
            );
            let fourth = request(3);
            assert_eq!(starts.recv().await, Some(vec![2, 3]));

            let tail = request(4);
            first_gate.add_permits(1);
            assert!(
                first
                    .await
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("first batch failed")
            );
            assert!(
                second
                    .await
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("first batch failed")
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(30), starts.recv())
                    .await
                    .is_err(),
                "a partial tail waits until all active batches finish"
            );
            second_gate.add_permits(1);
            assert_eq!(third.await.unwrap().unwrap(), 14);
            assert_eq!(fourth.await.unwrap().unwrap(), 21);
            assert_eq!(starts.recv().await, Some(vec![4]));
            assert_eq!(tail.await.unwrap().unwrap(), 28);
        })
        .await
        .expect("full concurrent batches and dependency-constrained tails must progress");
    }

    #[tokio::test]
    async fn slow_batch_does_not_block_other_batches_or_exceed_concurrency() {
        let gate = Arc::new(Semaphore::new(0));
        let (started, mut starts) = mpsc::unbounded_channel();
        let batch = Batcher::new(1, 2, Duration::ZERO, {
            let gate = gate.clone();
            move |items: Vec<u32>| {
                let gate = gate.clone();
                let started = started.clone();
                async move {
                    started.send(items[0]).unwrap();
                    let _permit = gate.acquire().await.unwrap();
                    if items[0] == 0 {
                        anyhow::bail!("first batch failed");
                    }
                    Ok(items.into_iter().map(|id| id * 7).collect())
                }
            }
        });
        let first = tokio::spawn({
            let batch = batch.clone();
            async move { batch.request(0).await }
        });
        assert_eq!(starts.recv().await, Some(0));
        let second = tokio::spawn({
            let batch = batch.clone();
            async move { batch.request(3).await }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            assert_eq!(starts.recv().await, Some(3));
        })
        .await
        .expect("another batch must start while the first is blocked");
        let third = tokio::spawn(async move { batch.request(5).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(30), starts.recv())
                .await
                .is_err()
        );
        gate.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), async {
            assert_eq!(starts.recv().await, Some(5));
            assert!(first.await.unwrap().is_err());
            assert_eq!(second.await.unwrap().unwrap(), 21);
            assert_eq!(third.await.unwrap().unwrap(), 35);
        })
        .await
        .expect("failed batches must release capacity and preserve other replies");
    }

    #[tokio::test]
    async fn bounds_batches_flushes_the_tail_and_keeps_results_with_their_callers() {
        let sizes = Arc::new(Mutex::new(Vec::new()));
        let observed = sizes.clone();
        let batch = Batcher::new(8, 1, Duration::from_millis(10), move |items: Vec<u32>| {
            let observed = observed.clone();
            async move {
                observed.lock().await.push(items.len());
                Ok(items
                    .into_iter()
                    .map(|id| {
                        if id == 11 {
                            Err("rejected")
                        } else {
                            Ok(id * 7)
                        }
                    })
                    .collect())
            }
        });
        let answers = tokio::time::timeout(
            Duration::from_secs(2),
            join_all((0..19).map(|id| batch.request(id))),
        )
        .await
        .expect("a partial batch must flush without another request");
        for (id, answer) in answers.into_iter().enumerate() {
            assert_eq!(
                answer.unwrap(),
                if id == 11 {
                    Err("rejected")
                } else {
                    Ok(id as u32 * 7)
                }
            );
        }
        assert_eq!(*sizes.lock().await, [8, 8, 3]);

        // With one upload worker there is nothing to collect: a full batch
        // must flush immediately, even with a long collection window.
        let single = Batcher::new(1, 1, Duration::from_secs(60), |items: Vec<u32>| async {
            Ok(items)
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), single.request(43))
                .await
                .expect("a full batch must not wait for its deadline")
                .unwrap(),
            43
        );
    }
}
