import type { LeaveType } from "./types";

export const STATS_EVENT_TYPES: LeaveType[] = [
  "ANNUAL_LEAVE",
  "SICK_LEAVE",
  "HOME_OFFICE",
  "UNPAID_LEAVE",
  "OTHER",
];

export function parseCsvList(value?: string): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

export function isValidLeaveType(value: string): value is LeaveType {
  return STATS_EVENT_TYPES.includes(value as LeaveType);
}

export function buildStatsDateRange({
  year,
  month,
  quarter,
}: {
  year: number;
  month?: number;
  quarter?: number;
}): { startDate: string; endDate: string; months: number[] } {
  if (!Number.isFinite(year)) {
    throw new Error("Invalid year");
  }

  if (month !== undefined) {
    if (month < 1 || month > 12) {
      throw new Error("Invalid month");
    }
    const start = new Date(Date.UTC(year, month - 1, 1));
    const end = new Date(Date.UTC(year, month, 0));
    return {
      startDate: start.toISOString().slice(0, 10),
      endDate: end.toISOString().slice(0, 10),
      months: [month],
    };
  }

  if (quarter !== undefined) {
    if (quarter < 1 || quarter > 4) {
      throw new Error("Invalid quarter");
    }
    const startMonth = (quarter - 1) * 3 + 1;
    const endMonth = startMonth + 2;
    const start = new Date(Date.UTC(year, startMonth - 1, 1));
    const end = new Date(Date.UTC(year, endMonth, 0));
    return {
      startDate: start.toISOString().slice(0, 10),
      endDate: end.toISOString().slice(0, 10),
      months: [startMonth, startMonth + 1, endMonth],
    };
  }

  const start = new Date(Date.UTC(year, 0, 1));
  const end = new Date(Date.UTC(year, 12, 0));
  return {
    startDate: start.toISOString().slice(0, 10),
    endDate: end.toISOString().slice(0, 10),
    months: Array.from({ length: 12 }, (_, index) => index + 1),
  };
}
