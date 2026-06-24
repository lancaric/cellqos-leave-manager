import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatLeaveHours } from "@/lib/leaveFormat";
import { formatRequestRange } from "@/lib/requestDateTime";
import { Eye } from "lucide-react";
import RequestDetailDialog from "./RequestDetailDialog";

interface RequestsListProps {
  requests: any[];
  isLoading: boolean;
  onUpdate: () => void;
  showUser?: boolean;
}

export default function RequestsList({ requests, isLoading, onUpdate, showUser }: RequestsListProps) {
  const [selectedRequest, setSelectedRequest] = useState<any>(null);

  const statusColors = {
    DRAFT: "bg-gray-500",
    PENDING: "bg-red-500",
    APPROVED: "bg-green-500",
    REJECTED: "bg-red-500",
    CANCELLED: "bg-gray-400",
  };

  const requestKindLabels = {
    CHANGE: "Úprava schválenej dovolenky",
    CANCELLATION: "Zrušenie schválenej dovolenky",
  };

  const statusLabels = {
    DRAFT: "Návrh",
    PENDING: "Čaká",
    APPROVED: "Schválené",
    REJECTED: "Zamietnuté",
    CANCELLED: "Zrušené",
  };

  const typeLabels = {
    ANNUAL_LEAVE: "Dovolenka",
    SICK_LEAVE: "PN",
    HOME_OFFICE: "Home office",
    UNPAID_LEAVE: "Neplatené voľno",
    OTHER: "Iné",
  };

  if (isLoading) {
    return <div className="py-12 text-center">Načítava sa...</div>;
  }

  if (requests.length === 0) {
    return (
      <Card className="p-12 text-center">
        <p className="text-muted-foreground">Nenašli sa žiadne žiadosti</p>
      </Card>
    );
  }

  return (
    <>
      <div className="space-y-4">
        {requests.map((request) => (
          <Card key={request.id} className="p-4 sm:p-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex-1 space-y-2">
                <div className="flex flex-wrap items-center gap-3">
                  <h3 className="font-semibold">
                    {typeLabels[request.type as keyof typeof typeLabels]}
                  </h3>
                  {request.requestKind && request.requestKind !== "STANDARD" && (
                    <Badge variant="outline">
                      {requestKindLabels[request.requestKind as keyof typeof requestKindLabels] ?? request.requestKind}
                    </Badge>
                  )}
                  <Badge className={statusColors[request.status as keyof typeof statusColors]}>
                    {statusLabels[request.status as keyof typeof statusLabels] ?? request.status}
                  </Badge>
                  {showUser && request.userName && (
                    <span className="text-sm text-muted-foreground">{request.userName}</span>
                  )}
                </div>

                <div className="text-sm text-muted-foreground">
                  {formatRequestRange(request)} ({formatLeaveHours(request.computedHours)})
                </div>

                {request.reason && (
                  <div className="text-sm italic text-muted-foreground">{request.reason}</div>
                )}
              </div>

              <Button
                variant="outline"
                size="sm"
                className="w-full sm:w-auto"
                onClick={() => setSelectedRequest(request)}
              >
                <Eye className="mr-2 h-4 w-4" />
                Detail
              </Button>
            </div>
          </Card>
        ))}
      </div>

      {selectedRequest && (
        <RequestDetailDialog
          request={selectedRequest}
          open={!!selectedRequest}
          onClose={() => {
            setSelectedRequest(null);
            onUpdate();
          }}
        />
      )}
    </>
  );
}
