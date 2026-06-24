import { api, APIError } from "encore.dev/api";
import { getAuthData } from "~encore/auth";
import db from "../db";
import { createAuditLog, createNotification } from "../shared/audit";
import { ensureAnnualLeaveBalance } from "../shared/leave-balance";
import { isAdmin, isManager, requireManager } from "../shared/rbac";
import type { LeaveRequest } from "../shared/types";

interface ApproveLeaveRequestParams {
  id: number;
  comment?: string;
  bulk?: boolean;
}

export const approve = api<ApproveLeaveRequestParams, LeaveRequest>(
  { auth: true, expose: true, method: "POST", path: "/leave-requests/:id/approve" },
  async (req): Promise<LeaveRequest> => {
    const { id, comment, bulk } = req;
    const auth = getAuthData()!;
    const isAdminUser = isAdmin(auth.role);
    const isManagerUser = isManager(auth.role);
    requireManager(auth.role);
    const request = await db.queryRow<LeaveRequest & { teamId: number | null; userName: string | null }>`
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
        u.team_id as "teamId",
        u.name as "userName"
      FROM leave_requests lr
      JOIN users u ON lr.user_id = u.id
      WHERE lr.id = ${id}
    `;
    
    if (!request) {
      throw APIError.notFound("Leave request not found");
    }

    if (isManagerUser && !isAdminUser) {
      const viewer = await db.queryRow<{ teamId: number | null }>`
        SELECT team_id as "teamId"
        FROM users
        WHERE id = ${auth.userID}
      `;
      if (!viewer || viewer.teamId === null || viewer.teamId !== request.teamId) {
        throw APIError.permissionDenied("Cannot approve another team's request");
      }
    }
    
    if (request.status !== "PENDING") {
      throw APIError.failedPrecondition("Can only approve requests in PENDING status");
    }
    
    // Check team concurrent leave limit
    if (request.teamId) {
      const team = await db.queryRow<{ maxConcurrentLeaves: number | null }>`
        SELECT max_concurrent_leaves as "maxConcurrentLeaves"
        FROM teams
        WHERE id = ${request.teamId}
      `;
      
      if (team?.maxConcurrentLeaves) {
        // Count approved leaves that overlap with this request
        const count = await db.queryRow<{ count: number }>`
          SELECT COUNT(*) as count
          FROM leave_requests lr
          JOIN users u ON lr.user_id = u.id
          WHERE u.team_id = ${request.teamId}
            AND lr.status = 'APPROVED'
            AND lr.start_date <= ${request.endDate}
            AND lr.end_date >= ${request.startDate}
        `;
        
        if (count && count.count >= team.maxConcurrentLeaves) {
          throw APIError.failedPrecondition(
            `Team concurrent leave limit (${team.maxConcurrentLeaves}) would be exceeded`
          );
        }
      }
    }

    if (request.type === "ANNUAL_LEAVE") {
      await ensureAnnualLeaveBalance({
        userId: request.userId,
        startDate: request.startDate,
        requestedHours: request.computedHours,
        requestId: request.id,
      });
    }
    
    const approverId = auth.userID;
    
    await db.exec`
      UPDATE leave_requests
      SET status = 'APPROVED',
          approved_by = ${approverId},
          approved_at = NOW(),
          manager_comment = ${comment || null}
      WHERE id = ${id}
    `;
    
    const updated = await db.queryRow<LeaveRequest>`
      SELECT 
        id, user_id as "userId", type,
        start_date::date::text as "startDate",
        end_date::date::text as "endDate",
        start_time::text as "startTime",
        end_time::text as "endTime",
        
        
        status, reason, manager_comment as "managerComment",
        approved_by as "approvedBy",
        approved_at as "approvedAt",
        computed_hours as "computedHours",
        attachment_url as "attachmentUrl",
        created_at as "createdAt",
        updated_at as "updatedAt"
      FROM leave_requests
      WHERE id = ${id}
    `;
    
    await createAuditLog(
      approverId,
      "leave_request",
      id,
      bulk ? "BULK_APPROVE" : "APPROVE",
      request,
      updated
    );
    
    const notificationPayload = {
      requestId: id,
      userId: request.userId,
      userName: request.userName,
      type: updated?.type,
      startDate: updated?.startDate,
      endDate: updated?.endDate,
      startTime: updated?.startTime,
      endTime: updated?.endTime,
      status: updated?.status,
      computedHours: updated?.computedHours,
      managerComment: updated?.managerComment,
      approvedBy: approverId,
      approverName: auth.name,
      approverEmail: auth.email,
    };

    const notificationJobs: Promise<unknown>[] = [];
    notificationJobs.push(
      createNotification(
        request.userId,
        "REQUEST_APPROVED",
        notificationPayload,
        `leave_request:${id}:approved:requester`
      )
    );

    const managers = request.teamId
      ? await db.queryAll<{ id: string }>`
          SELECT id
          FROM users
          WHERE role = 'MANAGER'
            AND is_active = true
            AND team_id = ${request.teamId}
        `
      : await db.queryAll<{ id: string }>`
          SELECT id
          FROM users
          WHERE role = 'MANAGER'
            AND is_active = true
        `;

    for (const manager of managers) {
      notificationJobs.push(
        createNotification(
          manager.id,
          "REQUEST_APPROVED_FOR_REVIEWERS",
          notificationPayload,
          `leave_request:${id}:approved:${manager.id}`
        )
      );
    }

    const admins = await db.queryAll<{ id: string }>`
      SELECT id
      FROM users
      WHERE role = 'ADMIN'
        AND is_active = true
    `;

    for (const admin of admins) {
      notificationJobs.push(
        createNotification(
          admin.id,
          "REQUEST_APPROVED_FOR_REVIEWERS",
          notificationPayload,
          `leave_request:${id}:approved:${admin.id}`
        )
      );
    }

    void Promise.allSettled(notificationJobs).then((results) => {
      const failedCount = results.filter((result) => result.status === "rejected").length;
      if (failedCount > 0) {
        console.warn(`Leave request ${id}: ${failedCount} approval notification(s) failed`);
      }
    });
    
    return updated!;
  }
);


