import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useBackend } from "@/lib/backend";
import { formatLeaveHours } from "@/lib/leaveFormat";
import { formatRequestRange } from "@/lib/requestDateTime";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/components/ui/use-toast";
import { Check, X } from "lucide-react";

interface ApprovalInboxProps {
  requests: any[];
  isLoading: boolean;
  onUpdate: () => void;
}

export default function ApprovalInbox({ requests, isLoading, onUpdate }: ApprovalInboxProps) {
  const backend = useBackend();
  const { toast } = useToast();
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [comment, setComment] = useState("");
  const [bulkComment, setBulkComment] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const selectedCount = selectedIds.size;
  const allSelected = useMemo(
    () => requests.length > 0 && selectedIds.size === requests.length,
    [requests.length, selectedIds]
  );

  const approveMutation = useMutation({
    mutationFn: async (id: number) => backend.leave_requests.approve({ id, comment }),
    onSuccess: () => {
      toast({ title: "Ziadost bola schvalena" });
      setComment("");
      setExpandedId(null);
      onUpdate();
    },
    onError: (error: any) => {
      console.error("Failed to approve request:", error);
      toast({
        title: "Schvalenie ziadosti zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const rejectMutation = useMutation({
    mutationFn: async (id: number) => {
      if (!comment) {
        throw new Error("Komentar je povinny pri zamietnuti");
      }
      return backend.leave_requests.reject({ id, comment });
    },
    onSuccess: () => {
      toast({ title: "Ziadost bola zamietnuta" });
      setComment("");
      setExpandedId(null);
      onUpdate();
    },
    onError: (error: any) => {
      console.error("Failed to reject request:", error);
      toast({
        title: "Zamietnutie ziadosti zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const bulkApproveMutation = useMutation({
    mutationFn: async (ids: number[]) => {
      await Promise.all(
        ids.map((id) => backend.leave_requests.approve({ id, comment: bulkComment, bulk: true }))
      );
    },
    onSuccess: () => {
      toast({ title: "Vybrane ziadosti boli schvalene" });
      setBulkComment("");
      setSelectedIds(new Set());
      onUpdate();
    },
    onError: (error: any) => {
      console.error("Failed to bulk approve requests:", error);
      toast({
        title: "Hromadne schvalenie zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const bulkRejectMutation = useMutation({
    mutationFn: async (ids: number[]) => {
      if (!bulkComment) {
        throw new Error("Komentar je povinny pri zamietnuti");
      }
      await Promise.all(
        ids.map((id) => backend.leave_requests.reject({ id, comment: bulkComment, bulk: true }))
      );
    },
    onSuccess: () => {
      toast({ title: "Vybrane ziadosti boli zamietnute" });
      setBulkComment("");
      setSelectedIds(new Set());
      onUpdate();
    },
    onError: (error: any) => {
      console.error("Failed to bulk reject requests:", error);
      toast({
        title: "Hromadne zamietnutie zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const typeLabels = {
    ANNUAL_LEAVE: "Dovolenka",
    SICK_LEAVE: "PN",
    HOME_OFFICE: "Home office",
    UNPAID_LEAVE: "Neplatene volno",
    OTHER: "Ine",
  };

  const requestKindLabels = {
    CHANGE: "Uprava schvalenej dovolenky",
    CANCELLATION: "Zrusenie schvalenej dovolenky",
  };

  const formatSourceRange = (request: any) => {
    if (!request.sourceStartDate || !request.sourceEndDate) {
      return null;
    }

    return formatRequestRange({
      startDate: request.sourceStartDate,
      endDate: request.sourceEndDate,
      startTime: request.sourceStartTime,
      endTime: request.sourceEndTime,
    });
  };

  if (isLoading) {
    return <div className="py-12 text-center">Nacitava sa...</div>;
  }

  if (requests.length === 0) {
    return (
      <Card className="p-12 text-center">
        <p className="text-muted-foreground">Ziadne cakajuce ziadosti</p>
      </Card>
    );
  }

  const handleToggleAll = () => {
    if (allSelected) {
      setSelectedIds(new Set());
      return;
    }
    setSelectedIds(new Set(requests.map((request) => request.id)));
  };

  const handleToggleOne = (id: number, checked: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      <Card className="space-y-4 p-4 sm:p-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <Checkbox checked={allSelected} onCheckedChange={handleToggleAll} />
            <span className="text-sm text-muted-foreground">
              Oznacene: {selectedCount} / {requests.length}
            </span>
          </div>
          <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
            <Button
              size="sm"
              className="w-full bg-green-600 hover:bg-green-700 sm:w-auto"
              onClick={() => bulkApproveMutation.mutate(Array.from(selectedIds))}
              disabled={selectedCount === 0 || bulkApproveMutation.isPending}
            >
              Schvalit oznacene
            </Button>
            <Button
              size="sm"
              variant="destructive"
              className="w-full sm:w-auto"
              onClick={() => bulkRejectMutation.mutate(Array.from(selectedIds))}
              disabled={selectedCount === 0 || bulkRejectMutation.isPending || !bulkComment}
            >
              Zamietnut oznacene
            </Button>
          </div>
        </div>
        <Textarea
          placeholder="Komentar pre hromadne schvalenie alebo zamietnutie (povinny pri zamietnuti)"
          value={bulkComment}
          onChange={(e) => setBulkComment(e.target.value)}
          rows={3}
        />
      </Card>

      {requests.map((request) => {
        const sourceRange = formatSourceRange(request);

        return (
          <Card key={request.id} className="p-4 sm:p-6">
            <div className="space-y-4">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="flex-1 space-y-2">
                  <div className="flex flex-wrap items-center gap-3">
                    <Checkbox
                      checked={selectedIds.has(request.id)}
                      onCheckedChange={(checked) => handleToggleOne(request.id, Boolean(checked))}
                    />
                    <h3 className="font-semibold">
                      {typeLabels[request.type as keyof typeof typeLabels]}
                    </h3>
                    {request.requestKind && request.requestKind !== "STANDARD" && (
                      <Badge variant="outline">
                        {requestKindLabels[request.requestKind as keyof typeof requestKindLabels] ?? request.requestKind}
                      </Badge>
                    )}
                    <Badge className="bg-red-500">CAKA</Badge>
                  </div>

                  <div className="space-y-1 text-sm text-muted-foreground">
                    <div>
                      {formatRequestRange(request)} ({formatLeaveHours(request.computedHours)})
                    </div>
                    {request.requestKind === "CHANGE" && sourceRange && (
                      <div>
                        Povodne: {sourceRange}
                        {request.sourceComputedHours !== null && request.sourceComputedHours !== undefined
                          ? ` (${formatLeaveHours(request.sourceComputedHours)})`
                          : ""}
                      </div>
                    )}
                    {request.requestKind === "CANCELLATION" && sourceRange && (
                      <div>
                        Rusi sa: {sourceRange}
                        {request.sourceComputedHours !== null && request.sourceComputedHours !== undefined
                          ? ` (${formatLeaveHours(request.sourceComputedHours)})`
                          : ""}
                      </div>
                    )}
                    {request.userName && <div>Ziadatel: {request.userName}</div>}
                    {request.currentBalanceHours !== null && request.currentBalanceHours !== undefined && (
                      <div>
                        Pred schvalenim: {formatLeaveHours(request.currentBalanceHours)} • Po schvaleni:{" "}
                        {formatLeaveHours(request.balanceAfterApprovalHours)}
                      </div>
                    )}
                  </div>

                  {request.reason && (
                    <div className="text-sm italic text-muted-foreground">Dovod: {request.reason}</div>
                  )}
                </div>

                <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
                  <Button
                    size="sm"
                    variant="outline"
                    className="w-full border-green-600 text-green-600 hover:bg-green-50 sm:w-auto"
                    onClick={() => setExpandedId(expandedId === request.id ? null : request.id)}
                  >
                    <Check className="mr-2 h-4 w-4" />
                    Schvalit
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="w-full border-red-600 text-red-600 hover:bg-red-50 sm:w-auto"
                    onClick={() => setExpandedId(expandedId === request.id ? null : request.id)}
                  >
                    <X className="mr-2 h-4 w-4" />
                    Zamietnut
                  </Button>
                </div>
              </div>

              {expandedId === request.id && (
                <div className="space-y-3 border-t pt-4">
                  <Textarea
                    placeholder="Pridajte komentar (nepovinny pri schvaleni, povinny pri zamietnuti)"
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    rows={3}
                  />
                  <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setExpandedId(null);
                        setComment("");
                      }}
                    >
                      Zrusit
                    </Button>
                    <Button
                      size="sm"
                      className="bg-green-600 hover:bg-green-700"
                      onClick={() => approveMutation.mutate(request.id)}
                      disabled={approveMutation.isPending}
                    >
                      Potvrdit schvalenie
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => rejectMutation.mutate(request.id)}
                      disabled={rejectMutation.isPending || !comment}
                    >
                      Potvrdit zamietnutie
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </Card>
        );
      })}
    </div>
  );
}
