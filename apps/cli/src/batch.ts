/**
 * Gathers single calls into batched ones: each call waits until maxSize
 * items are queued or delayMs passes, then one run() answers all of them,
 * in order. A failed run fails every call in it.
 */
export function batcher<T, R>(
  maxSize: number,
  delayMs: number,
  run: (items: T[]) => Promise<R[]>,
): (item: T) => Promise<R> {
  let queue: { item: T; resolve: (r: R) => void; reject: (e: unknown) => void }[] = [];
  let timer: ReturnType<typeof setTimeout> | undefined;

  const flush = () => {
    clearTimeout(timer);
    timer = undefined;
    const batch = queue;
    queue = [];
    run(batch.map((q) => q.item)).then(
      (results) => batch.forEach((q, i) => q.resolve(results[i])),
      (err: unknown) => batch.forEach((q) => q.reject(err)),
    );
  };

  return (item) =>
    new Promise<R>((resolve, reject) => {
      queue.push({ item, resolve, reject });
      if (queue.length >= maxSize) flush();
      else timer ??= setTimeout(flush, delayMs);
    });
}

/** Runs at most `limit` of the functions it is given at once. */
export function limiter(limit: number): <R>(fn: () => Promise<R>) => Promise<R> {
  let active = 0;
  const waiting: (() => void)[] = [];
  return async (fn) => {
    if (active >= limit) await new Promise<void>((resolve) => waiting.push(resolve));
    active++;
    try {
      return await fn();
    } finally {
      active--;
      waiting.shift()?.();
    }
  };
}
