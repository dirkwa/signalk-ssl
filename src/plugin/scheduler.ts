import type { SslService } from './service.js'

const ONE_DAY_MS = 24 * 60 * 60 * 1000

export interface SchedulerHandle {
  readonly stop: () => void
}

export const startRenewalScheduler = (
  service: SslService,
  logError: (e: unknown) => void,
  intervalMs: number = ONE_DAY_MS
): SchedulerHandle => {
  const timer = setInterval(() => {
    service.issueIfNeeded().catch(logError)
  }, intervalMs)
  // Don't keep the process alive just for this timer.
  timer.unref()
  return {
    stop: () => {
      clearInterval(timer)
    }
  }
}
