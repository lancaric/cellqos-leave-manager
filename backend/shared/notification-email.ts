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

const requestKindLabels: Record<string, string> = {
  STANDARD: "Nová žiadosť",
  CHANGE: "Úprava schválenej dovolenky",
  CANCELLATION: "Zrušenie schválenej dovolenky",
};

function formatDateTime(date?: string | null, time?: string | null): string {
  if (!date) {
    return "?";
  }
  if (!time) {
    return date;
  }
  return `${date} ${time}`;
}

function buildRangeLabel(payload: {
  startDate?: string | null;
  endDate?: string | null;
  startTime?: string | null;
  endTime?: string | null;
}): string {
  return `${formatDateTime(payload.startDate, payload.startTime)} -> ${formatDateTime(payload.endDate, payload.endTime)}`;
}

function buildRequestKindLine(payload: any): string {
  const requestKind = payload.requestKind ?? "STANDARD";
  return `Typ požiadavky: ${requestKindLabels[requestKind] ?? requestKind}`;
}

function buildChangeLine(payload: any): string | null {
  if (payload.requestKind !== "CHANGE" || !payload.sourceStartDate || !payload.sourceEndDate) {
    return null;
  }

  const sourceRange = buildRangeLabel({
    startDate: payload.sourceStartDate,
    endDate: payload.sourceEndDate,
    startTime: payload.sourceStartTime,
    endTime: payload.sourceEndTime,
  });
  const targetRange = buildRangeLabel({
    startDate: payload.startDate,
    endDate: payload.endDate,
    startTime: payload.startTime,
    endTime: payload.endTime,
  });

  return `Mení sa z: ${sourceRange} na: ${targetRange}`;
}

function buildLeaveRequestDetails(payload: any): string[] {
  const startDateTime = formatDateTime(payload.startDate, payload.startTime);
  const endDateTime = formatDateTime(payload.endDate, payload.endTime);
  const typeLabel = payload.type ? leaveTypeLabels[payload.type] ?? payload.type : null;
  const statusLabel = payload.status ? leaveStatusLabels[payload.status] ?? payload.status : null;

  const lines = [
    buildRequestKindLine(payload),
    buildChangeLine(payload),
    `Typ voľna: ${typeLabel ?? "?"}`,
    `Stav: ${statusLabel ?? "?"}`,
    `Začiatok: ${startDateTime}`,
    `Koniec: ${endDateTime}`,
  ].filter((line): line is string => Boolean(line));

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

function buildActionText(type: string, payload: any): string {
  const requestKind = payload.requestKind ?? "STANDARD";

  if (type === "REQUEST_APPROVED") {
    if (requestKind === "CHANGE") return "Vaša žiadosť o úpravu schválenej dovolenky bola schválená.";
    if (requestKind === "CANCELLATION") return "Vaša žiadosť o zrušenie schválenej dovolenky bola schválená.";
    return "Vaša žiadosť bola schválená.";
  }

  if (type === "REQUEST_REJECTED") {
    if (requestKind === "CHANGE") return "Vaša žiadosť o úpravu schválenej dovolenky bola zamietnutá.";
    if (requestKind === "CANCELLATION") return "Vaša žiadosť o zrušenie schválenej dovolenky bola zamietnutá.";
    return "Vaša žiadosť bola zamietnutá.";
  }

  if (type === "REQUEST_APPROVED_FOR_REVIEWERS") {
    return "Jedna žiadosť bola schválená.";
  }

  if (type === "REQUEST_REJECTED_FOR_REVIEWERS") {
    return "Jedna žiadosť bola zamietnutá.";
  }

  return "Máte nové upozornenie.";
}

function buildGenericNotificationDetails(payload: any): string[] {
  const lines: string[] = [];

  if (payload.userName || payload.userId) {
    lines.push(`Používateľ: ${payload.userName ?? payload.userId}`);
  }

  if (payload.requestKind) {
    lines.push(buildRequestKindLine(payload));
  }

  if (payload.type) {
    lines.push(`Typ voľna: ${leaveTypeLabels[payload.type] ?? payload.type}`);
  }

  if (payload.status) {
    lines.push(`Stav: ${leaveStatusLabels[payload.status] ?? payload.status}`);
  }

  if (payload.startDate || payload.endDate) {
    lines.push(`Termín: ${buildRangeLabel(payload)}`);
  }

  if (payload.computedHours !== undefined && payload.computedHours !== null) {
    lines.push(`Trvanie: ${payload.computedHours} hodín`);
  }

  if (payload.managerComment) {
    lines.push(`Komentár manažéra: ${payload.managerComment}`);
  }

  return lines;
}

export function buildNotificationEmail(type: string, payload: any): NotificationEmailContent {
  const safePayload = payload ?? {};

  switch (type) {
    case "REQUEST_SUBMITTED":
      return {
        subject: "Žiadosť bola odoslaná",
        text: [
          "Vaša žiadosť o dovolenku bola odoslaná na schválenie.",
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
        text: [buildActionText(type, safePayload), ...buildLeaveRequestDetails(safePayload)].join("\n"),
      };
    case "REQUEST_REJECTED":
      return {
        subject: "Žiadosť zamietnutá",
        text: [buildActionText(type, safePayload), ...buildLeaveRequestDetails(safePayload)].join("\n"),
      };
    case "REQUEST_APPROVED_FOR_REVIEWERS":
      return {
        subject: "Žiadosť bola schválená",
        text: [buildActionText(type, safePayload), ...buildLeaveRequestDetails(safePayload)].join("\n"),
      };
    case "REQUEST_REJECTED_FOR_REVIEWERS":
      return {
        subject: "Žiadosť bola zamietnutá",
        text: [buildActionText(type, safePayload), ...buildLeaveRequestDetails(safePayload)].join("\n"),
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
        text: ["Žiadosť bola zrušená.", ...buildLeaveRequestDetails(safePayload)].join("\n"),
      };
    case "PASSWORD_RESET":
      return {
        subject: "Heslo bolo resetované",
        text: `Reset vykonal ${safePayload.adminName ?? "admin"}${
          safePayload.adminEmail ? ` (${safePayload.adminEmail})` : ""
        }.`,
      };
    default: {
      const details = buildGenericNotificationDetails(safePayload);
      return {
        subject: "Notifikácia",
        text: ["Máte nové upozornenie.", ...details].join("\n"),
      };
    }
  }
}

