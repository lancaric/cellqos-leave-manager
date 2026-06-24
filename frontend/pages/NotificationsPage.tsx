import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useBackend } from "@/lib/backend";
import { useToast } from "@/components/ui/use-toast";
import { formatRequestRange } from "@/lib/requestDateTime";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { Notification } from "~backend/shared/types";

type NotificationWithDates = Notification & {
  createdAt: string;
  readAt: string | null;
  payloadJson: any;
};

function getRequestKindLabel(payload: any): string {
  if (payload.requestKind === "CHANGE") return "Úprava schválenej dovolenky";
  if (payload.requestKind === "CANCELLATION") return "Zrušenie schválenej dovolenky";
  return "Nová žiadosť";
}

function getSourceRange(payload: any): string | null {
  if (!payload.sourceStartDate || !payload.sourceEndDate) {
    return null;
  }

  return formatRequestRange({
    startDate: payload.sourceStartDate,
    endDate: payload.sourceEndDate,
    startTime: payload.sourceStartTime,
    endTime: payload.sourceEndTime,
  });
}

function buildNotificationText(payload: any): string {
  const range = formatRequestRange(payload) || "?";
  const kindLabel = getRequestKindLabel(payload);
  const sourceRange = getSourceRange(payload);

  if (payload.requestKind === "CHANGE" && sourceRange) {
    return `${kindLabel} • z ${sourceRange} na ${range}`;
  }

  return `${kindLabel} • ${range}`;
}

function getNotificationContent(notification: NotificationWithDates) {
  const payload = notification.payloadJson ?? {};
  const actor = payload.userName ?? payload.userId ?? "Neznámy používateľ";
  const detailedText = buildNotificationText(payload);

  switch (notification.type) {
    case "NEW_PENDING_REQUEST":
      return {
        title:
          payload.requestKind === "CANCELLATION"
            ? "Nová žiadosť o zrušenie"
            : payload.requestKind === "CHANGE"
              ? "Nová žiadosť o úpravu"
              : "Nová žiadosť na schválenie",
        text: `${actor} • ${detailedText}`,
      };
    case "REQUEST_APPROVED":
      return {
        title: "Žiadosť schválená",
        text: detailedText,
      };
    case "REQUEST_APPROVED_FOR_REVIEWERS":
      return {
        title: "Žiadosť bola schválená",
        text: `${actor} • ${detailedText}`,
      };
    case "REQUEST_REJECTED":
      return {
        title: "Žiadosť zamietnutá",
        text: detailedText,
      };
    case "REQUEST_REJECTED_FOR_REVIEWERS":
      return {
        title: "Žiadosť bola zamietnutá",
        text: `${actor} • ${detailedText}`,
      };
    case "REQUEST_UPDATED_BY_MANAGER":
      return {
        title: "Žiadosť upravená manažérom",
        text: `Stav: ${payload.status ?? "nezmenený"} • ${detailedText}`,
      };
    case "REQUEST_CANCELLED":
      return {
        title: "Žiadosť zrušená",
        text: `${actor} • ${detailedText}`,
      };
    case "PASSWORD_RESET":
      return {
        title: "Heslo bolo resetované",
        text: `Reset vykonal ${payload.adminName ?? "admin"}${
          payload.adminEmail ? ` (${payload.adminEmail})` : ""
        }`,
      };
    default:
      return { title: "Notifikácia", text: JSON.stringify(payload) };
  }
}

export default function NotificationsPage() {
  const backend = useBackend();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const notificationsQuery = useQuery({
    queryKey: ["notifications"],
    queryFn: async () => {
      const response = await backend.notifications.list();
      return response.notifications as NotificationWithDates[];
    },
  });

  const readMutation = useMutation({
    mutationFn: async (id: number) => backend.notifications.read({ id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
    onError: (error: any) => {
      toast({
        title: "Označenie notifikácie zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const readAllMutation = useMutation({
    mutationFn: async () => backend.notifications.readAll(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
      toast({ title: "Všetky notifikácie boli označené ako prečítané." });
    },
    onError: (error: any) => {
      toast({
        title: "Označenie všetkých notifikácií zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => backend.notifications.remove({ id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
      toast({ title: "Notifikácia bola vymazaná." });
    },
    onError: (error: any) => {
      toast({
        title: "Vymazanie notifikácie zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const deleteAllMutation = useMutation({
    mutationFn: async () => backend.notifications.removeAll(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
      toast({ title: "Notifikácie boli vymazané." });
    },
    onError: (error: any) => {
      toast({
        title: "Vymazanie notifikácií zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const unreadCount = useMemo(() => {
    return (notificationsQuery.data ?? []).filter((item) => !item.readAt).length;
  }, [notificationsQuery.data]);

  if (notificationsQuery.isLoading) {
    return <div className="py-12 text-center">Načítavam notifikácie...</div>;
  }

  if (notificationsQuery.isError) {
    return <div className="py-12 text-center text-destructive">Notifikácie sa nepodarilo načítať.</div>;
  }

  const notifications = notificationsQuery.data ?? [];

  const handleDelete = (id: number) => {
    const confirmed = window.confirm("Naozaj chcete vymazať túto notifikáciu?");
    if (confirmed) {
      deleteMutation.mutate(id);
    }
  };

  const handleDeleteAll = () => {
    const confirmed = window.confirm("Naozaj chcete vymazať všetky notifikácie?");
    if (confirmed) {
      deleteAllMutation.mutate();
    }
  };

  if (notifications.length === 0) {
    return (
      <Card className="p-8 text-center">
        <p className="text-muted-foreground">Žiadne notifikácie.</p>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold">Notifikácie</h2>
          {unreadCount > 0 && <Badge variant="secondary">{unreadCount} neprečítané</Badge>}
        </div>
        <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
          <Button
            variant="outline"
            size="sm"
            className="w-full sm:w-auto"
            onClick={() => readAllMutation.mutate()}
            disabled={readAllMutation.isPending || unreadCount === 0}
          >
            Označiť všetko ako prečítané
          </Button>
          <Button
            variant="destructive"
            size="sm"
            className="w-full sm:w-auto"
            onClick={handleDeleteAll}
            disabled={deleteAllMutation.isPending || notifications.length === 0}
          >
            Vymazať všetko
          </Button>
        </div>
      </div>

      {notifications.map((notification) => {
        const content = getNotificationContent(notification);

        return (
          <Card
            key={notification.id}
            className="flex flex-col gap-4 p-4 sm:flex-row sm:items-start sm:justify-between"
          >
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{content.title}</span>
                {!notification.readAt && <Badge variant="secondary">Nové</Badge>}
              </div>
              <div className="text-sm text-muted-foreground">{content.text}</div>
              <div className="text-xs text-muted-foreground">
                {new Date(notification.createdAt).toLocaleString("sk-SK")}
              </div>
            </div>

            <div className="flex w-full flex-col gap-2 sm:w-auto">
              {!notification.readAt && (
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full sm:w-auto"
                  onClick={() => readMutation.mutate(notification.id)}
                  disabled={readMutation.isPending}
                >
                  Označiť ako prečítané
                </Button>
              )}
              <Button
                size="sm"
                variant="destructive"
                className="w-full sm:w-auto"
                onClick={() => handleDelete(notification.id)}
                disabled={deleteMutation.isPending}
              >
                Vymazať
              </Button>
            </div>
          </Card>
        );
      })}
    </div>
  );
}
