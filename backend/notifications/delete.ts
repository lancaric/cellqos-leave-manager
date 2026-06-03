import { api } from "encore.dev/api";
import { getAuthData } from "~encore/auth";
import db from "../db";
import { isAdmin } from "../shared/rbac";

interface DeleteNotificationParams {
  id: number;
}

export const remove = api(
  { auth: true, expose: true, method: "DELETE", path: "/notifications/:id" },
  async ({ id }: DeleteNotificationParams): Promise<{ ok: true }> => {
    const auth = getAuthData()!;
    const isAdminUser = isAdmin(auth.role);

    if (isAdminUser) {
      await db.exec`
        DELETE FROM notifications
        WHERE id = ${id}
      `;
    } else {
      await db.exec`
        DELETE FROM notifications
        WHERE id = ${id}
          AND user_id = ${auth.userID}
      `;
    }

    return { ok: true };
  }
);
