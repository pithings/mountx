/**
 * A single writer / many readers lock over a session's path map.
 *
 * Both transports need exactly this and for exactly the same reason: `RENAME`
 * is the only operation that rewrites paths it did not resolve itself, so it
 * must not run while another request is between resolving a path and using it.
 * A `LOOKUP` that resolved `/a/b` before a rename must not bind that path
 * after it. Everything else runs concurrently, which is the whole point of not
 * having a queue.
 *
 * It lives here rather than in either session because it is character-identical
 * in both and depends on nothing — sharing it costs neither transport a byte of
 * the other's bundle.
 *
 * **Liveness, stated honestly.** A writer blocks new readers *before* waiting
 * for the outstanding ones, so a driver call that never settles inside a reader
 * stalls every rename behind it, and every path-resolving request behind that.
 * Two things keep the blast radius small: only `RENAME` is a writer, and the
 * requests a driver can realistically hang on for an unbounded time — reads and
 * writes — are deliberately dispatched *outside* the lock, because they resolve
 * nothing in the path map. What remains exposed is a hung lookup, readdir or
 * getattr. A finer-grained scheme (per-subtree locks, or making a reader's bind
 * fail closed against a map epoch instead of blocking) is a benchmark-milestone
 * concern, not a v1 one.
 */
export class PathLock {
  #tail: Promise<unknown> = Promise.resolve();
  #gate: Promise<void> | undefined;
  readonly #active = new Set<Promise<unknown>>();

  /** Run `fn` as a reader: concurrent with every other reader. */
  async read<T>(fn: () => Promise<T>): Promise<T> {
    while (this.#gate !== undefined) {
      await this.#gate;
    }
    const running = fn();
    this.#active.add(running);
    try {
      return await running;
    } finally {
      this.#active.delete(running);
    }
  }

  /** Run `fn` as the writer: after every outstanding reader, before every new one. */
  write<T>(fn: () => Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      let open!: () => void;
      this.#gate = new Promise<void>((resolve) => {
        open = resolve;
      });
      try {
        await Promise.allSettled(this.#active);
        return await fn();
      } finally {
        this.#gate = undefined;
        open();
      }
    };
    // Writers are serialized against each other by the chain; both callbacks
    // are `run` so a failed rename does not wedge the next one.
    const result = this.#tail.then(run, run);
    this.#tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}
