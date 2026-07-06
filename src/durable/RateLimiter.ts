import { DurableObject } from 'cloudflare:workers';

// ---------------------------------------------------------------------------
// RateLimiter – a fixed-window counter with atomic increments.
//
// Each instance (addressed via idFromName) owns one counter, so reads and
// writes are serialized by the Durable Object's single-threaded execution —
// unlike the previous KV read-then-write, concurrent failed logins cannot race
// past the threshold. Used for three independent dimensions per login attempt:
// (ip + username), ip alone, and username alone.
// ---------------------------------------------------------------------------

interface WindowState {
  count: number;
  resetAt: number; // epoch ms
}

const KEY = 'state';

export class RateLimiter extends DurableObject {
  /** Current attempt count in the active window (0 if the window has expired). */
  async count(): Promise<number> {
    const state = await this.ctx.storage.get<WindowState>(KEY);
    if (!state || state.resetAt <= Date.now()) return 0;
    return state.count;
  }

  /** Increment the counter, starting a new window if the previous one expired. */
  async increment(windowSeconds: number): Promise<number> {
    const now = Date.now();
    const state = await this.ctx.storage.get<WindowState>(KEY);

    const next: WindowState =
      !state || state.resetAt <= now
        ? { count: 1, resetAt: now + windowSeconds * 1000 }
        : { count: state.count + 1, resetAt: state.resetAt };

    await this.ctx.storage.put(KEY, next);
    // Self-clean when the window closes so storage does not accumulate.
    await this.ctx.storage.setAlarm(next.resetAt);
    return next.count;
  }

  /** Clear the counter (e.g. after a successful login). */
  async reset(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }

  async alarm(): Promise<void> {
    const state = await this.ctx.storage.get<WindowState>(KEY);
    if (!state || state.resetAt <= Date.now()) {
      await this.ctx.storage.deleteAll();
    }
  }
}
