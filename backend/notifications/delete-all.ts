import { api } from "encore.dev/api";
import { getAuthData } from "~encore/auth";
import db from "../db";
import { isAdmin } from "../shared/rbac";

export const removeAll = api(
  { auth: true, expose: true, method: "DELETE", path: "/notifications" },
  async (): Promise<{ ok: true }> => {
    const auth = getAuthData()!;

    if (isAdmin(auth.role)) {
      await db.exec`
        DELETE FROM notifications
      `;
    } else {
      await db.exec`
        DELETE FROM notifications
        WHERE user_id = ${auth.userID}
      `;
    }

    return { ok: true };
  }
);
