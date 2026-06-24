import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useBackend } from "@/lib/backend";
import { useAuth } from "@/lib/auth";
import { formatLeaveHours } from "@/lib/leaveFormat";
import { formatRequestDateTime } from "@/lib/requestDateTime";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/components/ui/use-toast";
import { Calendar, Clock } from "lucide-react";
import RequestFormDialog from "./RequestFormDialog";

type AuditLogEntry = {
  id: number;
  actorUserId: string;
  actorName?: string | null;
  action: string;
  beforeJson: any;
  afterJson: any;
  createdAt: string;
};

interface RequestDetailDialogProps {
  request: any;
  open: boolean;
  onClose: () => void;
}

export default function RequestDetailDialog({ request, open, onClose }: RequestDetailDialogProps) {
  const backend = useBackend();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isManager = user?.role === "MANAGER" || user?.role === "ADMIN";
  const { toast } = useToast();
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [approvalComment, setApprovalComment] = useState("");
  const startDateLabel = formatRequestDateTime(request.startDate, request.startTime);
  const endDateLabel = formatRequestDateTime(request.endDate, request.endTime);
  const sourceStartDateLabel = formatRequestDateTime(request.sourceStartDate, request.sourceStartTime);
  const sourceEndDateLabel = formatRequestDateTime(request.sourceEndDate, request.sourceEndTime);
  const startTimeLabel = request.startTime ? request.startTime.slice(0, 5) : null;
  const endTimeLabel = request.endTime ? request.endTime.slice(0, 5) : null;
  const timeRangeLabel =
    startTimeLabel && endTimeLabel ? `${startTimeLabel} - ${endTimeLabel}` : startTimeLabel || endTimeLabel;
  const sourceStartTimeLabel = request.sourceStartTime ? request.sourceStartTime.slice(0, 5) : null;
  const sourceEndTimeLabel = request.sourceEndTime ? request.sourceEndTime.slice(0, 5) : null;
  const sourceTimeRangeLabel =
    sourceStartTimeLabel && sourceEndTimeLabel
      ? `${sourceStartTimeLabel} - ${sourceEndTimeLabel}`
      : sourceStartTimeLabel || sourceEndTimeLabel;

  const meQuery = useQuery({
    queryKey: ["me"],
    enabled: open && Boolean(user),
    queryFn: async () => backend.users.me(),
  });

  const managedTeamIds = ((meQuery.data?.managedTeamIds as number[] | undefined) ?? []).map((value) => Number(value));
  const requestTeamId = request.teamId !== undefined && request.teamId !== null ? Number(request.teamId) : null;
  const isOwnRequest = request.userId === user?.id;
  const canManageOtherUsersRequest =
    user?.role === "ADMIN"
      || (user?.role === "MANAGER" && requestTeamId !== null && managedTeamIds.includes(requestTeamId));
  const canManageRequest = Boolean(
    user?.role === "ADMIN"
      || (user?.role === "EMPLOYEE" && isOwnRequest)
      || (user?.role === "MANAGER" && !isOwnRequest && canManageOtherUsersRequest)
  );
  const canApproveRequest = Boolean(
    request.status === "PENDING" && !isOwnRequest && canManageOtherUsersRequest
  );
  const requestKind = request.requestKind ?? "STANDARD";
  const isApprovedOwnRequest = isOwnRequest && request.status === "APPROVED";
  const isPendingDerivedRequest = request.status === "PENDING" && Boolean(request.sourceRequestId);
  const canRequestApprovedLeaveChange = Boolean(!isManager && isApprovedOwnRequest);
  const canRequestApprovedLeaveCancellation = Boolean(!isManager && isApprovedOwnRequest);

  const invalidateData = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["my-requests"] }),
      queryClient.invalidateQueries({ queryKey: ["team-requests"] }),
      queryClient.invalidateQueries({ queryKey: ["pending-requests"] }),
      queryClient.invalidateQueries({ queryKey: ["calendar"] }),
      queryClient.invalidateQueries({ queryKey: ["notifications"] }),
      queryClient.invalidateQueries({ queryKey: ["leave-balance"] }),
    ]);
  };

  const submitMutation = useMutation({
    mutationFn: async () => backend.leave_requests.submit({ id: request.id }),
    onSuccess: async () => {
      await invalidateData();
      toast({ title: "Ziadost bola odoslana na schvalenie" });
      onClose();
    },
    onError: (error: any) => {
      console.error("Failed to submit request:", error);
      toast({ title: "Odoslanie ziadosti zlyhalo", description: error.message, variant: "destructive" });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: async () => backend.leave_requests.cancel({ id: request.id }),
    onSuccess: async () => {
      await invalidateData();
      toast({
        title: isApprovedOwnRequest ? "Žiadosť o zrušenie bola odoslaná na schválenie" : "Žiadosť bola zrušená",
      });
      onClose();
    },
    onError: (error: any) => {
      console.error("Failed to cancel request:", error);
      toast({ title: "Zrusenie ziadosti zlyhalo", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async () => backend.leave_requests.remove({ id: request.id }),
    onSuccess: async () => {
      await invalidateData();
      toast({ title: "Ziadost bola odstranena" });
      onClose();
    },
    onError: (error: any) => {
      console.error("Failed to delete request:", error);
      toast({ title: "Odstranenie ziadosti zlyhalo", description: error.message, variant: "destructive" });
    },
  });

  const approveMutation = useMutation({
    mutationFn: async () => backend.leave_requests.approve({ id: request.id, comment: approvalComment || undefined }),
    onSuccess: async () => {
      await invalidateData();
      toast({ title: "Ziadost bola schvalena" });
      setApprovalComment("");
      onClose();
    },
    onError: (error: any) => {
      console.error("Failed to approve request:", error);
      toast({ title: "Schvalenie ziadosti zlyhalo", description: error.message, variant: "destructive" });
    },
  });

  const rejectMutation = useMutation({
    mutationFn: async () => {
      if (!approvalComment.trim()) {
        throw new Error("Komentar je povinny pri zamietnuti");
      }
      return backend.leave_requests.reject({ id: request.id, comment: approvalComment.trim() });
    },
    onSuccess: async () => {
      await invalidateData();
      toast({ title: "Ziadost bola zamietnuta" });
      setApprovalComment("");
      onClose();
    },
    onError: (error: any) => {
      console.error("Failed to reject request:", error);
      toast({ title: "Zamietnutie ziadosti zlyhalo", description: error.message, variant: "destructive" });
    },
  });

  const statusColors = {
    DRAFT: "bg-gray-500",
    PENDING: "bg-red-500",
    APPROVED: "bg-green-500",
    REJECTED: "bg-red-500",
    CANCELLED: "bg-gray-400",
  };

  const statusLabels = {
    DRAFT: "Navrh",
    PENDING: "Caka",
    APPROVED: "Schvalene",
    REJECTED: "Zamietnute",
    CANCELLED: "Zrusene",
  };

  const actionLabels: Record<string, string> = {
    CREATE: "Vytvorena",
    UPDATE: "Upravena",
    SUBMIT: "Odoslana",
    APPROVE: "Schvalena",
    REJECT: "Zamietnuta",
    CANCEL: "Zrusena",
    DELETE: "Odstranena",
    BULK_APPROVE: "Hromadne schvalenie",
    BULK_REJECT: "Hromadne zamietnutie",
    CHANGE_REQUEST_CREATE: "Požiadavka na úpravu",
    CANCELLATION_REQUEST_CREATE: "Požiadavka na zrušenie",
    CANCELLATION_REQUEST_APPROVED: "Zrušenie schválené",
  };

  const canViewHistory = Boolean(user?.role === "MANAGER" || user?.role === "ADMIN" || request.userId === user?.id);

  const historyQuery = useQuery({
    queryKey: ["audit", request.id],
    enabled: open && canViewHistory,
    queryFn: async () => {
      const response = await backend.audit.list({
        entityType: "leave_request",
        entityId: String(request.id),
      });
      return response.logs as AuditLogEntry[];
    },
  });

  const sortedHistory = useMemo(() => {
    if (!historyQuery.data) return [];
    return [...historyQuery.data].sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
  }, [historyQuery.data]);

  const formatHistoryEntry = (entry: AuditLogEntry) => {
    const before = entry.beforeJson ?? {};
    const after = entry.afterJson ?? {};
    const startDate = formatRequestDateTime(after.startDate ?? before.startDate, after.startTime ?? before.startTime);
    const endDate = formatRequestDateTime(after.endDate ?? before.endDate, after.endTime ?? before.endTime);
    const beforeStatus = before.status;
    const afterStatus = after.status;
    const statusChange =
      beforeStatus && afterStatus && beforeStatus !== afterStatus
        ? `${statusLabels[beforeStatus as keyof typeof statusLabels] ?? beforeStatus} -> ${statusLabels[afterStatus as keyof typeof statusLabels] ?? afterStatus}`
        : afterStatus
          ? statusLabels[afterStatus as keyof typeof statusLabels] ?? afterStatus
          : null;

    const pieces = [
      statusChange ? `Stav: ${statusChange}` : null,
      startDate && endDate ? `Obdobie: ${startDate} - ${endDate}` : null,
    ].filter(Boolean);

    return pieces.length > 0 ? pieces.join(" | ") : "Bez detailu zmeny";
  };

  const typeLabels = {
    ANNUAL_LEAVE: "Dovolenka",
    SICK_LEAVE: "PN",
    HOME_OFFICE: "Home office",
    UNPAID_LEAVE: "Neplatene volno",
    OTHER: "Ine",
  };

  const requestKindLabels = {
    CHANGE: "Úprava schválenej dovolenky",
    CANCELLATION: "Zrušenie schválenej dovolenky",
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Detail ziadosti o volno</DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-sm text-muted-foreground">Typ</div>
              <div className="flex flex-wrap items-center gap-2 font-medium">
                <span>{typeLabels[request.type as keyof typeof typeLabels]}</span>
                {requestKind !== "STANDARD" && (
                  <Badge variant="outline">
                    {requestKindLabels[requestKind as keyof typeof requestKindLabels] ?? requestKind}
                  </Badge>
                )}
              </div>
            </div>
            <Badge className={`${statusColors[request.status as keyof typeof statusColors]} px-3 py-1 text-xs shrink-0`}>
              {statusLabels[request.status as keyof typeof statusLabels] ?? request.status}
            </Badge>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <div className="text-sm text-muted-foreground mb-1">Zaciatok</div>
              <div className="flex flex-wrap items-center gap-2">
                <Calendar className="h-4 w-4 text-muted-foreground" />
                <span className="break-all">{startDateLabel}</span>
              </div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground mb-1">Koniec</div>
              <div className="flex flex-wrap items-center gap-2">
                <Calendar className="h-4 w-4 text-muted-foreground" />
                <span className="break-all">{endDateLabel}</span>
              </div>
            </div>
          </div>

          {timeRangeLabel && (
            <div>
              <div className="text-sm text-muted-foreground mb-1">Cas</div>
              <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                <Clock className="h-4 w-4" />
                <span>{timeRangeLabel}</span>
              </div>
            </div>
          )}

          <div>
            <div className="text-sm text-muted-foreground mb-1">Trvanie</div>
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <span>{formatLeaveHours(request.computedHours)}</span>
            </div>
          </div>

          {requestKind === "CHANGE" && request.sourceRequestId && request.sourceStartDate && (
            <div className="grid gap-4 rounded-md border p-4 sm:grid-cols-2">
              <div className="space-y-2">
                <div className="text-sm font-medium">Povodna schvalena dovolenka</div>
                <div className="text-sm text-muted-foreground">
                  {sourceStartDateLabel} - {sourceEndDateLabel}
                </div>
                {sourceTimeRangeLabel && (
                  <div className="text-sm text-muted-foreground">Cas: {sourceTimeRangeLabel}</div>
                )}
                {request.sourceComputedHours !== null && request.sourceComputedHours !== undefined && (
                  <div className="text-sm text-muted-foreground">
                    Trvanie: {formatLeaveHours(request.sourceComputedHours)}
                  </div>
                )}
              </div>
              <div className="space-y-2">
                <div className="text-sm font-medium">Nova poziadavka na schvalenie</div>
                <div className="text-sm text-muted-foreground">
                  {startDateLabel} - {endDateLabel}
                </div>
                {timeRangeLabel && (
                  <div className="text-sm text-muted-foreground">Cas: {timeRangeLabel}</div>
                )}
                <div className="text-sm text-muted-foreground">
                  Trvanie: {formatLeaveHours(request.computedHours)}
                </div>
              </div>
            </div>
          )}

          {requestKind === "CANCELLATION" && request.sourceRequestId && request.sourceStartDate && (
            <div className="rounded-md border p-4">
              <div className="text-sm font-medium">Dovolenka urcena na zrusenie</div>
              <div className="mt-2 text-sm text-muted-foreground">
                {sourceStartDateLabel} - {sourceEndDateLabel}
              </div>
              {sourceTimeRangeLabel && (
                <div className="mt-1 text-sm text-muted-foreground">Cas: {sourceTimeRangeLabel}</div>
              )}
              {request.sourceComputedHours !== null && request.sourceComputedHours !== undefined && (
                <div className="mt-1 text-sm text-muted-foreground">
                  Trvanie: {formatLeaveHours(request.sourceComputedHours)}
                </div>
              )}
            </div>
          )}

          {request.reason && (
            <div>
              <div className="text-sm text-muted-foreground mb-1">Dovod</div>
              <div className="p-3 bg-muted rounded-md">{request.reason}</div>
            </div>
          )}

          {request.managerComment && (
            <div>
              <div className="text-sm text-muted-foreground mb-1">Komentar manazera</div>
              <div className="p-3 bg-muted rounded-md">{request.managerComment}</div>
            </div>
          )}

          {(requestKind === "CHANGE" || requestKind === "CANCELLATION") && (
            <div className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
              {requestKind === "CHANGE"
                ? "Toto je požiadavka na úpravu už schválenej dovolenky. Po schválení nahradí pôvodnú dovolenku."
                : "Toto je požiadavka na zrušenie už schválenej dovolenky. Po schválení sa pôvodná dovolenka zruší."}
            </div>
          )}

          {canApproveRequest && (
            <div className="space-y-3 rounded-md border p-4">
              <div className="text-sm font-medium">Schvalenie ziadosti</div>
              <Textarea
                placeholder="Komentar pre schvalenie alebo zamietnutie (povinny pri zamietnuti)"
                value={approvalComment}
                onChange={(event) => setApprovalComment(event.target.value)}
                rows={3}
              />
              <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
                <Button
                  size="sm"
                  className="bg-green-600 hover:bg-green-700"
                  onClick={() => approveMutation.mutate()}
                  disabled={approveMutation.isPending || rejectMutation.isPending}
                >
                  Schvalit
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => rejectMutation.mutate()}
                  disabled={approveMutation.isPending || rejectMutation.isPending || !approvalComment.trim()}
                >
                  Zamietnut
                </Button>
              </div>
            </div>
          )}

          {isManager && !canManageRequest && (
            <div className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
              Tuto ziadost vidite, ale nemate pravo ju menit ani schvalovat. Na spravu mate len timy, ktore realne riadite.
            </div>
          )}

          {canViewHistory && (
            <div>
              <div className="text-sm text-muted-foreground mb-2">History</div>
              {historyQuery.isLoading && <div className="text-sm text-muted-foreground">Nacitavam historiu...</div>}
              {historyQuery.isError && <div className="text-sm text-destructive">Historiu sa nepodarilo nacitat.</div>}
              {!historyQuery.isLoading && !historyQuery.isError && sortedHistory.length === 0 && (
                <div className="text-sm text-muted-foreground">Ziadna historia.</div>
              )}
              {!historyQuery.isLoading && !historyQuery.isError && sortedHistory.length > 0 && (
                <ul className="space-y-3">
                  {sortedHistory.map((entry) => (
                    <li key={entry.id} className="flex flex-wrap items-start gap-3">
                      <Badge variant="outline">{actionLabels[entry.action] ?? entry.action}</Badge>
                      <div className="space-y-1 min-w-0">
                        <div className="text-sm">
                          {new Date(entry.createdAt).toLocaleString("sk-SK")} | {entry.actorName ?? entry.actorUserId}
                        </div>
                        <div className="text-sm text-muted-foreground">{formatHistoryEntry(entry)}</div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          <div className="flex flex-wrap justify-end gap-2">
            {(isManager || canRequestApprovedLeaveChange) && (
              <>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setShowEditDialog(true)}
                  disabled={isManager ? !canManageRequest : false}
                >
                  {canRequestApprovedLeaveChange ? "Požiadať o úpravu" : "Upraviť"}
                </Button>
              </>
            )}
            {isManager && (
              <Button
                size="sm"
                variant="destructive"
                onClick={() => {
                  if (window.confirm("Naozaj chcete odstranit tuto ziadost?")) {
                    deleteMutation.mutate();
                  }
                }}
                disabled={deleteMutation.isPending || !canManageRequest}
              >
                Odstranit
              </Button>
            )}
            {request.status === "DRAFT" && (
              <Button size="sm" className="font-semibold" onClick={() => submitMutation.mutate()}>
                Odoslat na schvalenie
              </Button>
            )}
            {(request.status === "DRAFT" || request.status === "PENDING") && (
              <Button size="sm" variant="destructive" onClick={() => cancelMutation.mutate()}>
                {isPendingDerivedRequest ? "Stiahnuť požiadavku" : "Zrusit ziadost"}
              </Button>
            )}
            {canRequestApprovedLeaveCancellation && (
              <Button size="sm" variant="destructive" onClick={() => cancelMutation.mutate()}>
                Požiadať o zrušenie
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
      {showEditDialog && (
        <RequestFormDialog
          open={showEditDialog}
          request={request}
          onClose={() => {
            setShowEditDialog(false);
            if (canRequestApprovedLeaveChange || isPendingDerivedRequest) {
              onClose();
            }
          }}
        />
      )}
    </Dialog>
  );
}
