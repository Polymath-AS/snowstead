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
    pub fn new<F, Fut>(operation: F) -> Self
    where
        F: Fn(Vec<T>) -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<Vec<R>>> + Send,
    {
        let (sender, mut receiver) = mpsc::channel::<(T, Reply<R>)>(100);
        tokio::spawn(async move {
            while let Some(first) = receiver.recv().await {
                let mut values = vec![first.0];
                let mut replies = vec![first.1];
                let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
                while values.len() < 100 {
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
