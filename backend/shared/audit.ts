import db from "../db";
import { sendNotificationEmail } from "./email";
import { buildNotificationEmail } from "./notification-email";

let notificationsDedupeKeySupported: boolean | null = null;
let userEmailNotificationsSupported: boolean | null = null;

async function hasNotificationsDedupeKey(): Promise<boolean> {
  if (notificationsDedupeKeySupported !== null) {
    return notificationsDedupeKeySupported;
  }
  const row = await db.queryRow<{ exists: boolean }>`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'notifications'
        AND column_name = 'dedupe_key'
    ) as "exists"
  `;
  notificationsDedupeKeySupported = row?.exists ?? false;
  return notificationsDedupeKeySupported;
}

async function hasUserEmailNotificationsEnabled(): Promise<boolean> {
  if (userEmailNotificationsSupported !== null) {
    return userEmailNotificationsSupported;
  }
  const row = await db.queryRow<{ exists: boolean }>`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'users'
        AND column_name = 'email_notifications_enabled'
    ) as "exists"
  `;
  userEmailNotificationsSupported = row?.exists ?? false;
  return userEmailNotificationsSupported;
}

export async function createAuditLog(
  actorUserId: string,
  entityType: string,
  entityId: string | number,
  action: string,
  beforeData: any = null,
  afterData: any = null
): Promise<void> {
  await db.exec`
    INSERT INTO audit_logs (
      actor_user_id, entity_type, entity_id, action, before_json, after_json
    ) VALUES (
      ${actorUserId},
      ${entityType},
      ${String(entityId)},
      ${action},
      ${beforeData ? JSON.stringify(beforeData) : null},
      ${afterData ? JSON.stringify(afterData) : null}
    )
  `;
}

export async function createNotification(
  userId: string,
  type: string,
  payload: any,
  dedupeKey?: string | null
): Promise<void> {
  const supportsDedupeKey = await hasNotificationsDedupeKey();
  let notificationId: number | null = null;
  if (supportsDedupeKey) {
    const inserted = await db.queryRow<{ id: number }>`
      INSERT INTO notifications (user_id, type, payload_json, dedupe_key)
      VALUES (${userId}, ${type}, ${JSON.stringify(payload)}, ${dedupeKey ?? null})
      ON CONFLICT (dedupe_key) DO NOTHING
      RETURNING id
    `;
    notificationId = inserted?.id ?? null;
  } else {
    const inserted = await db.queryRow<{ id: number }>`
      INSERT INTO notifications (user_id, type, payload_json)
      VALUES (${userId}, ${type}, ${JSON.stringify(payload)})
      RETURNING id
    `;
    notificationId = inserted?.id ?? null;
  }

  if (!notificationId) {
    return;
  }

  const supportsEmailNotifications = await hasUserEmailNotificationsEnabled();
  const user = await db.queryRow<{ email: string; emailNotificationsEnabled: boolean }>`
    SELECT email,
      ${supportsEmailNotifications ? "email_notifications_enabled" : "TRUE"} as "emailNotificationsEnabled"
    FROM users
    WHERE id = ${userId}
  `;

  if (!user?.email || user.emailNotificationsEnabled === false) {
    return;
  }

  const { subject, text } = buildNotificationEmail(type, payload);
  const sent = await sendNotificationEmail({
    to: user.email,
    subject,
    text,
  });

  if (sent) {
    await db.exec`
      UPDATE notifications
      SET sent_at = NOW()
      WHERE id = ${notificationId}
    `;
  }
}
