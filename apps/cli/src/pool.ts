/**
 * Run fn over items with bounded concurrency. Items are claimed in order;
 * the returned promise settles after every item has been processed.
 * Rejections propagate to the caller.
 */
export async function runPool<T>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<void>,
): Promise<void> {
  let next = 0;

  async function worker(): Promise<void> {
    while (next < items.length) {
      const idx = next;
      next++;
      await fn(items[idx], idx);
    }
  }

  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(concurrency, items.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);
}
