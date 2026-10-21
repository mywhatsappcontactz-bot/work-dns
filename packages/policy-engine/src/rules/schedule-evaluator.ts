import { DaySchedule } from '@work-dns/shared-types';

export interface LocalTimeComponents {
  dayOfWeek: 0 | 1 | 2 | 3 | 4 | 5 | 6;
  minuteOfDay: number; // 0 to 1439
}

/**
 * Calculates the local day of week and minute of the day for a given UTC epoch timestamp
 * in a target IANA timezone (e.g., "Africa/Lagos").
 */
export function getLocalTimeComponents(utcEpochMs: number, timezone: string): LocalTimeComponents {
  const date = new Date(utcEpochMs);

  // Format parts according to target timezone
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    weekday: 'short',
    hour: 'numeric',
    minute: 'numeric',
    hour12: false,
  });

  const parts = formatter.formatToParts(date);
  let weekdayStr = '';
  let hour = 0;
  let minute = 0;

  for (const part of parts) {
    if (part.type === 'weekday') weekdayStr = part.value;
    else if (part.type === 'hour') hour = parseInt(part.value, 10);
    else if (part.type === 'minute') minute = parseInt(part.value, 10);
  }

  // Map 24-hour wrap (e.g. 24 -> 0 in some locales)
  if (hour === 24) hour = 0;

  const weekdayMap: Record<string, 0 | 1 | 2 | 3 | 4 | 5 | 6> = {
    Sun: 0,
    Mon: 1,
    Tue: 2,
    Wed: 3,
    Thu: 4,
    Fri: 5,
    Sat: 6,
  };

  const dayOfWeek = weekdayMap[weekdayStr] ?? 0;
  const minuteOfDay = hour * 60 + minute;

  return { dayOfWeek, minuteOfDay };
}

/**
 * Checks if the current local time falls within any configured enforced schedule window.
 */
export function isWithinScheduleWindows(
  utcEpochMs: number,
  timezone: string,
  windows: DaySchedule[]
): boolean {
  if (windows.length === 0) {
    return false;
  }

  const { dayOfWeek, minuteOfDay } = getLocalTimeComponents(utcEpochMs, timezone);

  for (const window of windows) {
    if (window.dayOfWeek === dayOfWeek) {
      if (minuteOfDay >= window.startMinuteOfDay && minuteOfDay < window.endMinuteOfDay) {
        return true;
      }
    }
  }

  return false;
}
