import { api, APIError, Query } from "encore.dev/api";
import { getAuthData } from "~encore/auth";
import db from "../db";
import { isAdmin, isManager } from "../shared/rbac";
import type { LeaveRequest } from "../shared/types";

interface GetCalendarParams {
  startDate: Query<string>;
  endDate: Query<string>;
  teamId?: Query<number>;
}

interface CalendarEvent extends LeaveRequest {
  userName: string;
  userEmail: string;
  teamId: number | null;
}

interface GetCalendarResponse {
  events: CalendarEvent[];
}

async function getManagedTeamIds(userId: string): Promise<number[]> {
  const rows: Array<{ teamId: number }> = [];
  try {
    for await (const row of db.query<{
      teamId: number;
    }>`
      SELECT team_id as "teamId"
      FROM manager_teams
      WHERE manager_user_id = ${userId}
    `) {
      rows.push(row);
    }
  } catch {
    return [];
  }

  return Array.from(new Set(rows.map((row) => Number(row.teamId)).filter((id) => Number.isFinite(id))));
}

function mergeVisibleTeamIds(ownTeamId: number | null, managedTeamIds: number[]): number[] {
  return Array.from(
    new Set(
      [ownTeamId, ...managedTeamIds].filter((value): value is number => Number.isFinite(value) && value !== null)
    )
  );
}

// Gets calendar view with all leave requests in date range
export const get = api(
  { auth: true, expose: true, method: "GET", path: "/calendar" },
  async (params: GetCalendarParams): Promise<GetCalendarResponse> => {
    const auth = getAuthData()!;
    const isAdminUser = isAdmin(auth.role);
    const isManagerUser = isManager(auth.role);
    const viewerId = auth.userID;
    let viewerTeamId: number | null = null;
    let visibleTeamIds: number[] = [];
    let showTeamCalendarForEmployees = false;
    try {
      const settings = await db.queryRow<{ showTeamCalendarForEmployees: boolean }>`
        SELECT show_team_calendar_for_employees as "showTeamCalendarForEmployees"
        FROM settings
        LIMIT 1
      `;
      showTeamCalendarForEmployees = settings?.showTeamCalendarForEmployees ?? false;
    } catch {
      showTeamCalendarForEmployees = false;
    }

    if (!isAdminUser) {
      const viewer = await db.queryRow<{ teamId: number | null }>`
        SELECT team_id as "teamId"
        FROM users
        WHERE id = ${viewerId}
      `;

      if (!viewer) {
        throw APIError.notFound("User not found");
      }

      viewerTeamId = viewer.teamId;
    }

    if (isManagerUser && !isAdminUser) {
      const managedTeamIds = await getManagedTeamIds(viewerId);
      visibleTeamIds = mergeVisibleTeamIds(viewerTeamId, managedTeamIds);
    } else if (!isAdminUser && viewerTeamId !== null) {
      visibleTeamIds = [viewerTeamId];
    }

    const conditions: string[] = [
      "lr.start_date <= $2",
      "lr.end_date >= $1",
      "lr.status != 'DRAFT'",
      "lr.status != 'REJECTED'",
    ];
    const values: any[] = [params.startDate, params.endDate];

    if ((isManagerUser || isAdminUser) && params.teamId) {
      if (isManagerUser && !isAdminUser && !visibleTeamIds.includes(params.teamId)) {
        throw APIError.permissionDenied("Cannot access another team's calendar");
      }
      conditions.push(`u.team_id = $${values.length + 1}`);
      values.push(params.teamId);
    }

    if (isManagerUser && !isAdminUser && !params.teamId) {
      if (visibleTeamIds.length > 0) {
        conditions.push(`u.team_id = ANY($${values.length + 1}::bigint[])`);
        values.push(visibleTeamIds);
      } else {
        conditions.push(`lr.user_id = $${values.length + 1}`);
        values.push(viewerId);
      }
    }

    if (!isManagerUser && !isAdminUser) {
      if (params.teamId && params.teamId !== viewerTeamId) {
        throw APIError.permissionDenied("Cannot access another team's calendar");
      }
      if (showTeamCalendarForEmployees && viewerTeamId) {
        conditions.push(`u.team_id = $${values.length + 1}`);
        values.push(viewerTeamId);
      } else {
        conditions.push(`lr.user_id = $${values.length + 1}`);
        values.push(viewerId);
      }
    }
    
    const query = `
      SELECT 
        lr.id, lr.user_id as "userId", lr.type,
        lr.start_date::date::text as "startDate",
        lr.end_date::date::text as "endDate",
        lr.start_time::text as "startTime",
        lr.end_time::text as "endTime",
        
        
        lr.status, lr.reason, lr.manager_comment as "managerComment",
        lr.approved_by as "approvedBy",
        lr.approved_at as "approvedAt",
        lr.computed_hours as "computedHours",
        lr.attachment_url as "attachmentUrl",
        lr.created_at as "createdAt",
        lr.updated_at as "updatedAt",
        u.name as "userName",
        u.email as "userEmail",
        u.team_id as "teamId"
      FROM leave_requests lr
      JOIN users u ON lr.user_id = u.id
      WHERE ${conditions.join(" AND ")}
      ORDER BY lr.start_date ASC
    `;
    
    const events: CalendarEvent[] = [];
    for await (const row of db.rawQuery<CalendarEvent>(query, ...values)) {
      if (!isAdminUser && row.userId !== viewerId) {
        const isSameTeam = isManagerUser
          ? visibleTeamIds.includes(Number(row.teamId))
          : viewerTeamId !== null && viewerTeamId === row.teamId;
        if (!isManagerUser || !isSameTeam) {
          row.reason = null;
          row.managerComment = null;
        }
      }
      events.push(row);
    }
    
    return { events };
  }
);


