export interface NotificationEmailContent {
  subject: string;
  text: string;
}

const leaveTypeLabels: Record<string, string> = {
  ANNUAL_LEAVE: "Dovolenka",
  SICK_LEAVE: "PN",
  HOME_OFFICE: "Home office",
  UNPAID_LEAVE: "Neplatené voľno",
  OTHER: "Iné",
};

const leaveStatusLabels: Record<string, string> = {
  DRAFT: "Návrh",
  PENDING: "Čaká",
  APPROVED: "Schválené",
  REJECTED: "Zamietnuté",
  CANCELLED: "Zrušené",
};

function formatDateTime(date?: string, time?: string): string {
  if (!date) {
    return "?";
  }
  if (!time) {
    return date;
  }
  return `${date} ${time}`;
}

function formatTimeRange(startTime?: string | null, endTime?: string | null): string | null {
  if (!startTime && !endTime) {
    return null;
  }
  return `${startTime ?? "?"} – ${endTime ?? "?"}`;
}

function buildLeaveRequestDetails(payload: any): string[] {
  const startDateTime = formatDateTime(payload.startDate, payload.startTime);
  const endDateTime = formatDateTime(payload.endDate, payload.endTime);
  const timeRange = formatTimeRange(payload.startTime, payload.endTime);
  const typeLabel = payload.type ? leaveTypeLabels[payload.type] ?? payload.type : null;
  const statusLabel = payload.status ? leaveStatusLabels[payload.status] ?? payload.status : null;

  const lines = [
    payload.requestKind === "CANCELLATION" ? "Typ požiadavky: Zrušenie schválenej dovolenky" : null,
    payload.requestKind === "CHANGE" ? "Typ požiadavky: Úprava schválenej dovolenky" : null,
    `Typ: ${typeLabel ?? "?"}`,
    `Stav: ${statusLabel ?? "?"}`,
    `Začiatok: ${startDateTime}`,
    `Koniec: ${endDateTime}`,
  ].filter((line): line is string => Boolean(line));

  if (timeRange) {
    lines.push(`Čas: ${timeRange}`);
  }

  if (payload.computedHours !== undefined && payload.computedHours !== null) {
    lines.push(`Trvanie: ${payload.computedHours} hodín`);
  }

  if (payload.managerComment) {
    lines.push(`Komentár manažéra: ${payload.managerComment}`);
  }

  if (payload.userName || payload.userId) {
    lines.push(`Žiadateľ: ${payload.userName ?? payload.userId}`);
  }

  if (payload.approverName || payload.approverEmail || payload.approvedBy) {
    const approverLabel = payload.approverName ?? payload.approvedBy ?? "?";
    const approverEmailSuffix = payload.approverEmail ? ` (${payload.approverEmail})` : "";
    lines.push(`Rozhodol: ${approverLabel}${approverEmailSuffix}`);
  }

  return lines;
}

export function buildNotificationEmail(type: string, payload: any): NotificationEmailContent {
  const safePayload = payload ?? {};

  switch (type) {
    case "REQUEST_SUBMITTED":
      return {
        subject: "Ziadost bola odoslana",
        text: [
          "Vasa ziadost o dovolenku bola odoslana na schvalenie.",
          ...buildLeaveRequestDetails(safePayload),
        ].join("\n"),
      };
    case "NEW_PENDING_REQUEST":
      return {
        subject: "Nová žiadosť na schválenie",
        text: [
          safePayload.requestKind === "CANCELLATION"
            ? "Bola vytvorená nová žiadosť o zrušenie schválenej dovolenky."
            : safePayload.requestKind === "CHANGE"
              ? "Bola vytvorená nová žiadosť o úpravu schválenej dovolenky."
              : "Bola vytvorená nová žiadosť na schválenie.",
          ...buildLeaveRequestDetails(safePayload),
        ].join("\n"),
      };
    case "REQUEST_APPROVED":
      return {
        subject: "Žiadosť schválená",
        text: [
          safePayload.requestKind === "CANCELLATION"
            ? "Vaša žiadosť o zrušenie schválenej dovolenky bola schválená."
            : safePayload.requestKind === "CHANGE"
              ? "Vaša žiadosť o úpravu schválenej dovolenky bola schválená."
              : "Vaša žiadosť bola schválená.",
          ...buildLeaveRequestDetails(safePayload),
        ].join("\n"),
      };
    case "REQUEST_REJECTED":
      return {
        subject: "Žiadosť zamietnutá",
        text: [
          safePayload.requestKind === "CANCELLATION"
            ? "Vaša žiadosť o zrušenie schválenej dovolenky bola zamietnutá."
            : safePayload.requestKind === "CHANGE"
              ? "Vaša žiadosť o úpravu schválenej dovolenky bola zamietnutá."
              : "Vaša žiadosť bola zamietnutá.",
          ...buildLeaveRequestDetails(safePayload),
        ].join("\n"),
      };
    case "REQUEST_APPROVED_FOR_REVIEWERS":
      return {
        subject: "Ziadost bola schvalena",
        text: [
          "Jedna ziadost bola schvalena.",
          ...buildLeaveRequestDetails(safePayload),
        ].join("\n"),
      };
    case "REQUEST_REJECTED_FOR_REVIEWERS":
      return {
        subject: "Ziadost bola zamietnuta",
        text: [
          "Jedna ziadost bola zamietnuta.",
          ...buildLeaveRequestDetails(safePayload),
        ].join("\n"),
      };
    case "REQUEST_UPDATED_BY_MANAGER":
      return {
        subject: "Žiadosť upravená manažérom",
        text: [
          "Vaša žiadosť bola upravená manažérom.",
          ...buildLeaveRequestDetails(safePayload),
        ].join("\n"),
      };
    case "REQUEST_CANCELLED":
      return {
        subject: "Žiadosť zrušená",
        text: [
          "Žiadosť bola zrušená.",
          ...buildLeaveRequestDetails(safePayload),
        ].join("\n"),
      };
    case "PASSWORD_RESET":
      return {
        subject: "Heslo bolo resetované",
        text: `Reset vykonal ${safePayload.adminName ?? "admin"}${
          safePayload.adminEmail ? ` (${safePayload.adminEmail})` : ""
        }.`,
      };
    default:
      return {
        subject: "Notifikácia",
        text: `Máte nové upozornenie.\n\nDetaily:\n${JSON.stringify(safePayload, null, 2)}`,
      };
  }
}
