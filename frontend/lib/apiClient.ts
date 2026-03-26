import { apiBaseUrl } from "@/lib/auth";
import type {
  LeaveStatus,
  LeaveType,
  VacationPolicy,
  StatsDashboardResponse,
  StatsTableResponse,
  StatsCalendarResponse,
  StatsExportJob,
  StatsExportFormat,
  StatsReportType,
} from "~backend/shared/types";

interface RequestOptions {
  method?: string;
  body?: unknown;
  token?: string | null;
}

async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }

  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.message || "API request failed");
  }

  return (await response.json()) as T;
}

function toQuery(params: Record<string, string | number | boolean | undefined>) {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== "") {
      searchParams.set(key, String(value));
    }
  });
  const query = searchParams.toString();
  return query ? `?${query}` : "";
}

export function createApiClient(token: string | null) {
  return {
    auth: {
      changePassword: (data: { currentPassword: string; newPassword: string }) =>
        apiRequest<{ ok: true }>("/auth/change-password", { method: "POST", body: data, token }),
    },
    audit: {
      list: (params: { entityType?: string; entityId?: string; limit?: number }) =>
        apiRequest<{ logs: any[] }>(`/audit${toQuery(params)}`, { token }),
    },
    calendar: {
      get: (params: { startDate: string; endDate: string; teamId?: number }) =>
        apiRequest<{ events: any[] }>(`/calendar${toQuery(params)}`, { token }),
    },
    namedays: {
      today: (params: { teamId?: number } = {}) =>
        apiRequest<{ date: string; names: string[]; users: Array<{ id: string; name: string }> }>(
          `/namedays/today${toQuery(params)}`,
          { token }
        ),
    },
    holidays: {
      list: (params: { year?: number; includeInactive?: boolean }) =>
        apiRequest<{ holidays: any[] }>(`/holidays${toQuery(params)}`, { token }),
      create: (data: { date: string; name: string; isCompanyHoliday?: boolean; isActive?: boolean }) =>
        apiRequest<any>("/holidays", { method: "POST", body: data, token }),
      update: (data: { id: number } & Record<string, unknown>) =>
        apiRequest<any>(`/holidays/${data.id}`, { method: "PATCH", body: data, token }),
      remove: (data: { id: number }) =>
        apiRequest<any>(`/holidays/${data.id}`, { method: "DELETE", token }),
    },
    teams: {
      list: () => apiRequest<{ teams: any[] }>("/teams", { token }),
      create: (data: { name: string; maxConcurrentLeaves?: number | null }) =>
        apiRequest<any>("/teams", { method: "POST", body: data, token }),
      update: (data: { id: number } & Record<string, unknown>) =>
        apiRequest<any>(`/teams/${data.id}`, { method: "PATCH", body: data, token }),
      remove: (data: { id: number }) =>
        apiRequest<any>(`/teams/${data.id}`, { method: "DELETE", token }),
    },
    users: {
      list: () => apiRequest<{ users: any[] }>("/users", { token }),
      me: () => apiRequest<any>("/users/me", { token }),
      create: (data: {
        email: string;
        name: string;
        role?: string;
        teamId?: number | null;
        birthDate?: string | null;
        hasChild?: boolean;
        employmentStartDate?: string | null;
        manualLeaveAllowanceHours?: number | null;
      }) =>
        apiRequest<any>("/users", { method: "POST", body: data, token }),
      update: (data: { id: string } & Record<string, unknown>) =>
        apiRequest<any>(`/users/${data.id}`, { method: "PATCH", body: data, token }),
      resetPassword: (data: { id: string }) =>
        apiRequest<{ ok: true }>(`/users/${data.id}/reset-password`, { method: "POST", token }),
      remove: (data: { id: string }) =>
        apiRequest<any>(`/users/${data.id}`, { method: "DELETE", token }),
    },
    leave_requests: {
      list: (params: {
        userId?: string;
        status?: LeaveStatus;
        type?: LeaveType;
        startDate?: string;
        endDate?: string;
        teamId?: number;
      }) => apiRequest<{ requests: any[] }>(`/leave-requests${toQuery(params)}`, { token }),
      create: (data: any) => apiRequest<any>("/leave-requests", { method: "POST", body: data, token }),
      update: (data: { id: number } & Record<string, unknown>) =>
        apiRequest<any>(`/leave-requests/${data.id}`, { method: "PATCH", body: data, token }),
      submit: (data: { id: number }) =>
        apiRequest<any>(`/leave-requests/${data.id}/submit`, { method: "POST", token }),
      approve: (data: { id: number; comment?: string; bulk?: boolean }) =>
        apiRequest<any>(`/leave-requests/${data.id}/approve`, { method: "POST", body: data, token }),
      reject: (data: { id: number; comment: string; bulk?: boolean }) =>
        apiRequest<any>(`/leave-requests/${data.id}/reject`, { method: "POST", body: data, token }),
      cancel: (data: { id: number }) =>
        apiRequest<any>(`/leave-requests/${data.id}/cancel`, { method: "POST", token }),
      remove: (data: { id: number }) =>
        apiRequest<any>(`/leave-requests/${data.id}`, { method: "DELETE", token }),
    },
    leave_balances: {
      me: () =>
        apiRequest<{ year: number; allowanceHours: number; usedHours: number; remainingHours: number }>(
          "/leave-balances/me",
          { token }
        ),
    },
    notifications: {
      list: () => apiRequest<{ notifications: any[] }>("/notifications", { token }),
      read: (data: { id: number }) =>
        apiRequest<{ ok: true }>(`/notifications/${data.id}/read`, { method: "POST", token }),
      readAll: () => apiRequest<{ ok: true }>("/notifications/read-all", { method: "POST", token }),
    },
    database: {
      export: () => apiRequest<any>("/admin/database/export", { token }),
      import: (payload: { backup: any; confirm: string }) =>
        apiRequest<any>("/admin/database/import", { method: "POST", body: payload, token }),
    },
    vacation_policy: {
      get: () => apiRequest<{ policy: VacationPolicy }>("/admin/vacation-policy", { token }),
      update: (data: Partial<VacationPolicy>) =>
        apiRequest<{ policy: VacationPolicy }>("/admin/vacation-policy", { method: "PATCH", body: data, token }),
    },
    stats: {
      dashboard: (params: {
        year?: number;
        month?: number;
        quarter?: number;
        teamId?: number;
        memberIds?: string[];
        eventTypes?: LeaveType[];
      }) =>
        apiRequest<StatsDashboardResponse>(
          `/stats/dashboard${toQuery({
            year: params.year,
            month: params.month,
            quarter: params.quarter,
            teamId: params.teamId,
            memberIds: params.memberIds?.join(","),
            eventTypes: params.eventTypes?.join(","),
          })}`,
          { token }
        ),
      table: (params: {
        year?: number;
        month?: number;
        quarter?: number;
        teamId?: number;
        memberIds?: string[];
        eventTypes?: LeaveType[];
        search?: string;
        sortBy?: string;
        sortDir?: string;
        page?: number;
        pageSize?: number;
      }) =>
        apiRequest<StatsTableResponse>(
          `/stats/table${toQuery({
            year: params.year,
            month: params.month,
            quarter: params.quarter,
            teamId: params.teamId,
            memberIds: params.memberIds?.join(","),
            eventTypes: params.eventTypes?.join(","),
            search: params.search,
            sortBy: params.sortBy,
            sortDir: params.sortDir,
            page: params.page,
            pageSize: params.pageSize,
          })}`,
          { token }
        ),
      calendar: (params: { year?: number; teamId?: number; memberIds?: string[]; eventTypes?: LeaveType[] }) =>
        apiRequest<StatsCalendarResponse>(
          `/stats/calendar${toQuery({
            year: params.year,
            teamId: params.teamId,
            memberIds: params.memberIds?.join(","),
            eventTypes: params.eventTypes?.join(","),
          })}`,
          { token }
        ),
      exports: {
        create: (data: {
          reportType: StatsReportType;
          format: StatsExportFormat;
          filters: {
            year?: number;
            month?: number;
            quarter?: number;
            teamId?: number;
            memberIds?: string[];
            eventTypes?: LeaveType[];
          };
        }) => apiRequest<StatsExportJob>("/stats/exports", { method: "POST", body: data, token }),
        list: () => apiRequest<{ exports: StatsExportJob[] }>("/stats/exports", { token }),
        detail: (id: string) => apiRequest<StatsExportJob>(`/stats/exports/${id}`, { token }),
      },
    },
  };
}
