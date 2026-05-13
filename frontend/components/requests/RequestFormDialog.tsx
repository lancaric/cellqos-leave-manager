import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import moment from "moment";
import { useBackend } from "@/lib/backend";
import { useAuth } from "@/lib/auth";
import type { LeaveType } from "~backend/shared/types";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/components/ui/use-toast";

interface RequestFormDialogProps {
  open: boolean;
  onClose: () => void;
  request?: any;
  initialStartDate?: string;
  initialEndDate?: string;
}

const formatDateValue = (value?: string) => {
  if (!value) {
    return "";
  }

  const parsed = moment(value, ["YYYY-MM-DD", "YYYY-MM-DD HH:mm:ss", moment.ISO_8601], true);
  if (parsed.isValid()) {
    return parsed.format("YYYY-MM-DD");
  }

  return value.split(" ")[0] || value;
};

const DEFAULT_START_TIME = "08:00";

function getEndTimeFromWorkingHours(startTime = DEFAULT_START_TIME, workingHoursPerDay?: number | null) {
  const hours = Number(workingHoursPerDay ?? 8);
  const normalizedHours = Number.isFinite(hours) && hours > 0 ? hours : 8;
  return moment(startTime, "HH:mm")
    .add(normalizedHours, "hours")
    .format("HH:mm");
}

export default function RequestFormDialog({
  open,
  onClose,
  request,
  initialStartDate,
  initialEndDate,
}: RequestFormDialogProps) {
  const backend = useBackend();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canManageUsers = user?.role === "MANAGER" || user?.role === "ADMIN";
  const { toast } = useToast();
  const { data: usersData } = useQuery({
    queryKey: ["users"],
    queryFn: async () => backend.users.list(),
    enabled: canManageUsers,
  });
  const { data: meData } = useQuery({
    queryKey: ["me"],
    queryFn: async () => backend.users.me(),
    enabled: !canManageUsers,
  });

  const users = usersData?.users || [];
  const requestUserWorkingHoursPerDay = request
    ? canManageUsers
      ? users.find((entry: any) => entry.id === request.userId)?.workingHoursPerDay
      : meData?.workingHoursPerDay
    : undefined;
  const defaultStartTime = request ? request.startTime || DEFAULT_START_TIME : DEFAULT_START_TIME;
  const defaultWorkingHoursPerDay = request
    ? requestUserWorkingHoursPerDay
    : canManageUsers
      ? users.find((entry: any) => entry.id === (user?.id ?? ""))?.workingHoursPerDay
      : meData?.workingHoursPerDay;
  const defaultEndTime = request
    ? request.endTime || getEndTimeFromWorkingHours(defaultStartTime, defaultWorkingHoursPerDay)
    : getEndTimeFromWorkingHours(defaultStartTime, defaultWorkingHoursPerDay);
  const { register, handleSubmit, setValue, watch, reset } = useForm({
    defaultValues: {
      userId: user?.id ?? "",
      type: request?.type || "ANNUAL_LEAVE",
      startDate: formatDateValue(request?.startDate || initialStartDate),
      endDate: formatDateValue(request?.endDate || initialEndDate),
      startTime: defaultStartTime,
      endTime: defaultEndTime,
      reason: request?.reason || "",
    },
  });

  const selectedUserId = watch("userId");

  useEffect(() => {
    reset({
      userId: request?.userId || user?.id || "",
      type: request?.type || "ANNUAL_LEAVE",
      startDate: formatDateValue(request?.startDate || initialStartDate),
      endDate: formatDateValue(request?.endDate || initialEndDate),
      startTime: defaultStartTime,
      endTime: defaultEndTime,
      reason: request?.reason || "",
    });
  }, [defaultEndTime, defaultStartTime, initialEndDate, initialStartDate, request, reset, user?.id]);

  useEffect(() => {
    if (request) {
      return;
    }

    const selectedUser = canManageUsers
      ? users.find((entry: any) => entry.id === selectedUserId)
      : meData;
    const endTime = getEndTimeFromWorkingHours(DEFAULT_START_TIME, selectedUser?.workingHoursPerDay);
    setValue("startTime", DEFAULT_START_TIME);
    setValue("endTime", endTime);
  }, [canManageUsers, meData, request, selectedUserId, setValue, users]);
  
  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      return backend.leave_requests.create(data);
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["my-requests"] }),
        queryClient.invalidateQueries({ queryKey: ["team-requests"] }),
        queryClient.invalidateQueries({ queryKey: ["pending-requests"] }),
        queryClient.invalidateQueries({ queryKey: ["calendar"] }),
        queryClient.invalidateQueries({ queryKey: ["notifications"] }),
        queryClient.invalidateQueries({ queryKey: ["leave-balance"] }),
      ]);
      toast({ title: "Žiadosť bola úspešne vytvorená" });
      onClose();
    },
    onError: (error: any) => {
      console.error("Failed to create request:", error);
      toast({
        title: "Vytvorenie žiadosti zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (data: any) => {
      return backend.leave_requests.update(data);
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["my-requests"] }),
        queryClient.invalidateQueries({ queryKey: ["team-requests"] }),
        queryClient.invalidateQueries({ queryKey: ["pending-requests"] }),
        queryClient.invalidateQueries({ queryKey: ["calendar"] }),
        queryClient.invalidateQueries({ queryKey: ["notifications"] }),
        queryClient.invalidateQueries({ queryKey: ["leave-balance"] }),
      ]);
      toast({ title: "Žiadosť bola úspešne upravená" });
      onClose();
    },
    onError: (error: any) => {
      console.error("Failed to update request:", error);
      toast({
        title: "Úprava žiadosti zlyhala",
        description: error.message,
        variant: "destructive",
      });
    },
  });
  
  const onSubmit = (data: any) => {
    const payload = {
      ...data,
      userId: canManageUsers ? data.userId : undefined,
    };

    if (request) {
      const { userId: _userId, ...rest } = payload;
      updateMutation.mutate({ id: request.id, ...rest });
      return;
    }

    createMutation.mutate(payload);
  };

  const startDate = watch("startDate");
  const endDate = watch("endDate");
  const isSameDay = Boolean(startDate && endDate && startDate === endDate);

  const { data: holidayRange } = useQuery({
    queryKey: ["holiday-range", startDate, endDate],
    queryFn: async () => {
      if (!startDate || !endDate) {
        return { holidays: [] };
      }

      const startMoment = moment(startDate, "YYYY-MM-DD", true);
      const endMoment = moment(endDate, "YYYY-MM-DD", true);
      if (!startMoment.isValid() || !endMoment.isValid()) {
        return { holidays: [] };
      }

      const rangeStart = moment.min(startMoment, endMoment);
      const rangeEnd = moment.max(startMoment, endMoment);
      const years = Array.from(
        { length: rangeEnd.year() - rangeStart.year() + 1 },
        (_, index) => rangeStart.year() + index
      );
      const holidayResponses = await Promise.all(
        years.map((year) => backend.holidays.list({ year }))
      );
      const holidays = holidayResponses.flatMap((response) => response.holidays || []);
      const inRange = holidays.filter((holiday) => {
        const holidayMoment = moment(holiday.date, "YYYY-MM-DD", true);
        return holidayMoment.isValid() && holidayMoment.isBetween(rangeStart, rangeEnd, "day", "[]");
      });

      return { holidays: inRange };
    },
    enabled: Boolean(startDate && endDate),
  });
  const holidaysInRange = holidayRange?.holidays || [];
  
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {request ? "Upraviť žiadosť o voľno" : "Nová žiadosť o voľno"}
          </DialogTitle>
          <DialogDescription>
            {request
              ? "Upravte detaily žiadosti podľa potreby."
              : "Vyplňte detaily žiadosti a odošlite ju na schválenie."}
          </DialogDescription>
        </DialogHeader>
        
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {canManageUsers && !request && (
            <div>
              <Label>Žiadateľ</Label>
              <Select
                value={watch("userId")}
                onValueChange={(value) => setValue("userId", value)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Vyberte používateľa" />
                </SelectTrigger>
                <SelectContent>
                  {users.map((entry: any) => (
                    <SelectItem key={entry.id} value={entry.id}>
                      {entry.name} ({entry.email})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          <div>
            <Label>Typ</Label>
            <Select
              value={watch("type")}
              onValueChange={(value) => setValue("type", value as LeaveType)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ANNUAL_LEAVE">Dovolenka</SelectItem>
                <SelectItem value="SICK_LEAVE">PN</SelectItem>
                <SelectItem value="HOME_OFFICE">Home office</SelectItem>
                <SelectItem value="UNPAID_LEAVE">Neplatené voľno</SelectItem>
                <SelectItem value="OTHER">Iné</SelectItem>
              </SelectContent>
            </Select>
          </div>
          
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <Label>Začiatok</Label>
              <Input className="h-10" type="date" {...register("startDate")} required />
            </div>
            <div>
              <Label>Koniec</Label>
              <Input className="h-10" type="date" {...register("endDate")} required />
            </div>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label className={isSameDay ? "text-foreground" : undefined}>Príchod</Label>
              <Input
                className={`h-10 ${isSameDay ? "border-primary/60 bg-primary/5" : ""}`}
                type="time"
                {...register("startTime")}
              />
            </div>
            <div className="space-y-2">
              <Label className={isSameDay ? "text-foreground" : undefined}>Odchod</Label>
              <Input
                className={`h-10 ${isSameDay ? "border-primary/60 bg-primary/5" : ""}`}
                type="time"
                {...register("endTime")}
              />
            </div>
          </div>
          {holidaysInRange.length > 0 && (
            <p className="text-sm text-muted-foreground">
              V rozsahu sú sviatky:{" "}
              {holidaysInRange
                .map((holiday: any) => `${holiday.date} – ${holiday.name}`)
                .join(", ")}{" "}
              (nepočítajú sa do dovolenky).
            </p>
          )}
          
          <div>
            <Label>Dôvod (nepovinné)</Label>
            <Textarea {...register("reason")} rows={3} />
          </div>
          
          <div className="flex flex-wrap justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose} className="min-w-[120px]">
              Zrušiť
            </Button>
            <Button
              type="submit"
              disabled={createMutation.isPending || updateMutation.isPending}
              className="min-w-[160px]"
            >
              {createMutation.isPending || updateMutation.isPending ? "Ukladá sa..." : "Uložiť ako návrh"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
