import { DurableObject } from 'cloudflare:workers';

// ---------------------------------------------------------------------------
// RateLimiter – a fixed-window counter with atomic increments.
//
// Each instance owns a transactional attempt budget. Login uses independent
// (IP + username), IP, and username budgets. Registration uses an IP budget;
// consent uses a one-use budget alongside its session binding and expiry.
// ---------------------------------------------------------------------------

interface WindowState {
  count: number;
  resetAt: number; // epoch ms
}

const KEY = 'state';

export class RateLimiter extends DurableObject {
  /** Reserve capacity before expensive work; checking then counting failures races. */
  async consume(windowSeconds: number, limit: number): Promise<boolean> {
    return this.ctx.storage.transaction(async (txn) => {
      const now = Date.now();
      const state = await txn.get<WindowState>(KEY);
      const next = !state || state.resetAt <= now
        ? { count: 0, resetAt: now + windowSeconds * 1000 }
        : state;
      if (next.count >= limit) return false;
      next.count++;
      await txn.put(KEY, next);
      await txn.setAlarm(next.resetAt);
      return true;
    });
  }
  async alarm(): Promise<void> {
    const state = await this.ctx.storage.get<WindowState>(KEY);
    if (!state || state.resetAt <= Date.now()) {
      await this.ctx.storage.deleteAll();
    }
  }
}
