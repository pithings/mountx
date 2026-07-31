/**
 * A driver that takes a real turn of the event loop to answer.
 *
 * The bundled memory driver answers every call inside one microtask, and that
 * hides a whole class of ordering bug: two requests that arrive together run
 * through it in lockstep, so a session's bookkeeping is always in place before
 * the second request looks at it, however late the session writes it. No real
 * driver behaves that way — `node:fs` is a threadpool round trip per call — and
 * the difference is exactly the window a *retransmission* arrives in.
 *
 * So every method here, and every method of the handles `open` returns, is
 * pushed to the next macrotask before it runs. Nothing else changes: the
 * results, the errors and the order the driver itself sees the calls in are the
 * driver's own. This is what makes "the duplicate reached the table before the
 * original wrote to it" reproducible without a temp directory and a real
 * filesystem.
 *
 * Not a `*.test.ts` file: it is imported by several.
 */

import type { FileHandleLike, FsDriver } from "../src/types.ts";

/** The next macrotask, which is one full turn later than a microtask. */
const turn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

/** Delay every call of `value`'s methods by one turn, `apply`ing on the target. */
function delayed<T extends object>(value: T, onOpen?: (handle: unknown) => unknown): T {
  return new Proxy(value, {
    get(target, property, receiver) {
      const member = Reflect.get(target, property, receiver) as unknown;
      if (typeof member !== "function") {
        return member;
      }
      return async (...args: unknown[]): Promise<unknown> => {
        await turn();
        const result = await (member as (...rest: unknown[]) => unknown).apply(target, args);
        return property === "open" && onOpen !== undefined ? onOpen(result) : result;
      };
    },
  });
}

/** The same driver, one event-loop turn slower on every call it answers. */
export function withLatency<T extends FsDriver>(driver: T): FsDriver {
  return delayed(driver, (handle) => delayed(handle as FileHandleLike));
}
