use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
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
    pub fn new<F, Fut>(max_size: usize, delay: Duration, operation: F) -> Self
    where
        F: Fn(Vec<T>) -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<Vec<R>>> + Send,
    {
        let (sender, mut receiver) = mpsc::channel::<(T, Reply<R>)>(max_size);
        tokio::spawn(async move {
            while let Some(first) = receiver.recv().await {
                let mut values = vec![first.0];
                let mut replies = vec![first.1];
                let deadline = tokio::time::Instant::now() + delay;
                while values.len() < max_size {
                    match tokio::time::timeout_at(deadline, receiver.recv()).await {
                        Ok(Some((value, reply))) => {
                            values.push(value);
                            replies.push(reply)
                        }
                        _ => break,
                    }
                }
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
            }
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
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn bounds_batches_flushes_the_tail_and_keeps_results_with_their_callers() {
        let sizes = Arc::new(Mutex::new(Vec::new()));
        let observed = sizes.clone();
        let batch = Batcher::new(8, Duration::from_millis(10), move |items: Vec<u32>| {
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
        let single = Batcher::new(1, Duration::from_secs(60), |items: Vec<u32>| async {
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
