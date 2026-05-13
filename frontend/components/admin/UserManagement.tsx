import { useState } from "react";
import { useForm } from "react-hook-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useBackend } from "@/lib/backend";
import { useToast } from "@/components/ui/use-toast";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { formatLeaveHours } from "@/lib/leaveFormat";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

type UnitType = "HOURS" | "DAYS";

type UserFormValues = {
  name: string;
  email: string;
  role: "EMPLOYEE" | "MANAGER" | "ADMIN";
  teamId: string;
  managedTeamIds: string[];
  workingHoursPerDay: string;
  employmentStartDate: string;
  birthDate: string;
  hasChild: boolean;
  manualLeaveAllowanceHours: string;
  manualLeaveAllowanceUnit: UnitType;
  manualCarryOverHours: string;
  manualCarryOverUnit: UnitType;
  emailNotificationsEnabled: boolean;
};

function getDefaultValues(): UserFormValues {
  return {
    name: "",
    email: "",
    role: "EMPLOYEE",
    teamId: "none",
    managedTeamIds: [],
    workingHoursPerDay: "8",
    employmentStartDate: "",
    birthDate: "",
    hasChild: false,
    manualLeaveAllowanceHours: "",
    manualLeaveAllowanceUnit: "HOURS",
    manualCarryOverHours: "",
    manualCarryOverUnit: "HOURS",
    emailNotificationsEnabled: true,
  };
}

function parsePositiveNumber(value: string) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function formatUnitValue(value: number) {
  return Number.isInteger(value) ? String(value) : String(Number(value.toFixed(2)));
}

function convertValueBetweenUnits(value: string, from: UnitType, to: UnitType, workingHoursPerDay: number) {
  const parsedValue = parsePositiveNumber(value);
  if (parsedValue === null || from === to) {
    return value;
  }

  const convertedValue = to === "DAYS" ? parsedValue / workingHoursPerDay : parsedValue * workingHoursPerDay;
  return formatUnitValue(convertedValue);
}

function formatHoursWithDays(hours: number | null | undefined, workingHoursPerDay?: number | null) {
  const resolvedWorkingHoursPerDay =
    Number.isFinite(Number(workingHoursPerDay)) && Number(workingHoursPerDay) > 0
      ? Number(workingHoursPerDay)
      : 8;
  const resolvedHours = Number(hours ?? 0);
  const days = resolvedHours / resolvedWorkingHoursPerDay;

  return `${formatLeaveHours(resolvedHours)} (${formatUnitValue(days)} d)`;
}

export default function UserManagement() {
  const backend = useBackend();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<any | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["users"],
    queryFn: async () => backend.users.list(),
  });

  const { data: teamsData } = useQuery({
    queryKey: ["teams"],
    queryFn: async () => backend.teams.list(),
  });

  const { register, handleSubmit, setValue, watch, reset } = useForm<UserFormValues>({
    defaultValues: getDefaultValues(),
  });

  const createMutation = useMutation({
    mutationFn: async (payload: {
      email: string;
      name: string;
      role: string;
      teamId?: number | null;
      managedTeamIds?: number[];
      workingHoursPerDay?: number;
      birthDate?: string | null;
      hasChild?: boolean;
      employmentStartDate?: string | null;
      manualLeaveAllowanceHours?: number | null;
      manualCarryOverHours?: number | null;
      emailNotificationsEnabled?: boolean;
    }) => backend.users.create(payload),
    onSuccess: () => {
      toast({ title: "Používateľ bol vytvorený." });
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setDialogOpen(false);
    },
    onError: (error: any) => {
      toast({
        title: "Vytvorenie používateľa zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (payload: { id: string } & Record<string, unknown>) =>
      backend.users.update(payload),
    onSuccess: () => {
      toast({ title: "Používateľ bol upravený." });
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setDialogOpen(false);
    },
    onError: (error: any) => {
      toast({
        title: "Úprava používateľa zlyhala",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (payload: { id: string }) => backend.users.remove(payload),
    onSuccess: () => {
      toast({ title: "Používateľ bol odstránený." });
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (error: any) => {
      toast({
        title: "Odstránenie používateľa zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const resetPasswordMutation = useMutation({
    mutationFn: async (payload: { id: string }) => backend.users.resetPassword(payload),
    onSuccess: () => {
      toast({ title: "Heslo bolo resetované na predvolené." });
    },
    onError: (error: any) => {
      toast({
        title: "Reset hesla zlyhal",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  if (isLoading) {
    return <div className="py-12 text-center">Načítava sa...</div>;
  }

  const users = data?.users || [];
  const teams = teamsData?.teams || [];
  const roleLabels = {
    MANAGER: "Manažér",
    EMPLOYEE: "Zamestnanec",
    ADMIN: "Admin",
  };

  const openCreate = () => {
    setEditingUser(null);
    reset(getDefaultValues());
    setDialogOpen(true);
  };

  const openEdit = (user: any) => {
    setEditingUser(user);
    const initialManagedTeamIds = Array.isArray(user.managedTeamIds)
      ? user.managedTeamIds.map((id: number) => String(id))
      : [];

    reset({
      name: user.name ?? "",
      email: user.email ?? "",
      role: user.role ?? "EMPLOYEE",
      teamId: user.teamId ? String(user.teamId) : "none",
      managedTeamIds: initialManagedTeamIds,
      workingHoursPerDay:
        user.workingHoursPerDay !== null && user.workingHoursPerDay !== undefined
          ? String(user.workingHoursPerDay)
          : "8",
      employmentStartDate: user.employmentStartDate ? String(user.employmentStartDate).slice(0, 10) : "",
      birthDate: user.birthDate ? String(user.birthDate).slice(0, 10) : "",
      hasChild: Boolean(user.hasChild),
      manualLeaveAllowanceHours:
        user.manualLeaveAllowanceHours !== null && user.manualLeaveAllowanceHours !== undefined
          ? String(user.manualLeaveAllowanceHours)
          : "",
      manualLeaveAllowanceUnit: "HOURS",
      manualCarryOverHours:
        user.manualCarryOverHours !== null && user.manualCarryOverHours !== undefined
          ? String(user.manualCarryOverHours)
          : "",
      manualCarryOverUnit: "HOURS",
      emailNotificationsEnabled:
        user.emailNotificationsEnabled !== null && user.emailNotificationsEnabled !== undefined
          ? Boolean(user.emailNotificationsEnabled)
          : true,
    });
    setDialogOpen(true);
  };

  const handleDelete = (user: any) => {
    const confirmed = window.confirm(`Naozaj chcete odstrániť používateľa ${user.name}?`);
    if (confirmed) {
      deleteMutation.mutate({ id: user.id });
    }
  };

  const handleResetPassword = (user: any) => {
    const confirmed = window.confirm(`Naozaj chcete resetovať heslo používateľa ${user.name}?`);
    if (confirmed) {
      resetPasswordMutation.mutate({ id: user.id });
    }
  };

  const toggleManagedTeam = (teamId: string, checked: boolean) => {
    const current = watch("managedTeamIds") || [];
    if (checked) {
      if (!current.includes(teamId)) {
        setValue("managedTeamIds", [...current, teamId]);
      }
      return;
    }

    setValue(
      "managedTeamIds",
      current.filter((id) => id !== teamId)
    );
  };

  const onSubmit = (values: UserFormValues) => {
    const parsedManagedTeamIds = (values.managedTeamIds || [])
      .map((id) => Number(id))
      .filter((id) => Number.isFinite(id));

    const resolvedTeamId =
      values.role === "ADMIN"
        ? null
        : values.teamId !== "none"
          ? Number(values.teamId)
          : null;

    const parsedWorkingHoursPerDay = Number(values.workingHoursPerDay);
    if (!Number.isFinite(parsedWorkingHoursPerDay) || parsedWorkingHoursPerDay <= 0) {
      toast({
        title: "Neplatná pracovná doba",
        description: "Zadajte počet hodín za deň väčší ako 0.",
        variant: "destructive",
      });
      return;
    }

    const parsedManualLeaveAllowanceValue =
      values.manualLeaveAllowanceHours !== ""
        ? parsePositiveNumber(values.manualLeaveAllowanceHours)
        : null;
    if (values.manualLeaveAllowanceHours !== "" && parsedManualLeaveAllowanceValue === null) {
      toast({
        title: "Neplatný nárok dovolenky",
        description: "Zadajte platnú hodnotu nároku dovolenky.",
        variant: "destructive",
      });
      return;
    }

    const parsedManualCarryOverValue =
      values.manualCarryOverHours !== ""
        ? parsePositiveNumber(values.manualCarryOverHours)
        : null;
    if (values.manualCarryOverHours !== "" && parsedManualCarryOverValue === null) {
      toast({
        title: "Neplatná prenesená dovolenka",
        description: "Zadajte platnú hodnotu prenesenej dovolenky.",
        variant: "destructive",
      });
      return;
    }

    const payload = {
      email: values.email.trim(),
      name: values.name.trim(),
      role: values.role,
      teamId: resolvedTeamId,
      managedTeamIds: values.role === "MANAGER" ? parsedManagedTeamIds : [],
      workingHoursPerDay: parsedWorkingHoursPerDay,
      employmentStartDate: values.employmentStartDate ? values.employmentStartDate : null,
      birthDate: values.birthDate ? values.birthDate : null,
      hasChild: values.hasChild,
      manualLeaveAllowanceHours:
        parsedManualLeaveAllowanceValue !== null
          ? values.manualLeaveAllowanceUnit === "DAYS"
            ? parsedManualLeaveAllowanceValue * parsedWorkingHoursPerDay
            : parsedManualLeaveAllowanceValue
          : null,
      manualCarryOverHours:
        parsedManualCarryOverValue !== null
          ? values.manualCarryOverUnit === "DAYS"
            ? parsedManualCarryOverValue * parsedWorkingHoursPerDay
            : parsedManualCarryOverValue
          : null,
      emailNotificationsEnabled:
        values.role === "ADMIN" ? Boolean(values.emailNotificationsEnabled) : true,
    };

    if (editingUser) {
      updateMutation.mutate({ id: editingUser.id, ...payload });
    } else {
      createMutation.mutate(payload);
    }
  };

  return (
    <Card className="space-y-4 p-4 sm:p-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold">Používatelia</h2>
          <p className="text-sm text-muted-foreground">
            Spravujte používateľov, priraďte im roly a tímy.
          </p>
        </div>
        <Button onClick={openCreate}>Pridať používateľa</Button>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Meno</TableHead>
            <TableHead>Email</TableHead>
            <TableHead>Rola</TableHead>
            <TableHead>Tím</TableHead>
            <TableHead>Nástup</TableHead>
            <TableHead>Pracovná doba</TableHead>
            <TableHead>Narodenie</TableHead>
            <TableHead>Dieťa</TableHead>
            <TableHead>Nárok dovolenky (hodiny)</TableHead>
            <TableHead>Prenesené z minulého roka (hodiny)</TableHead>
            <TableHead>Zostatok dovolenky (hodiny)</TableHead>
            <TableHead>Stav</TableHead>
            <TableHead className="text-right">Akcie</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {users.map((user) => {
            const managedTeamNames = Array.isArray(user.managedTeamIds)
              ? teams
                  .filter((team: any) =>
                    user.managedTeamIds.some((managedId: number | string) => String(managedId) === String(team.id))
                  )
                  .map((team: any) => team.name)
              : [];
            const teamName = teams.find((team: any) => team.id === user.teamId)?.name;
            const teamLabel =
              user.role === "MANAGER"
                ? managedTeamNames.length > 0
                  ? [
                      `Člen: ${teamName || "Bez tímu"}`,
                      `Riadi: ${managedTeamNames.join(", ")}`,
                    ].join(" | ")
                  : `Člen: ${teamName || "Bez tímu"}`
                : (teamName || "Bez tímu");

            return (
              <TableRow key={user.id}>
                <TableCell className="font-medium">{user.name}</TableCell>
                <TableCell>{user.email}</TableCell>
                <TableCell>
                  <Badge variant={user.role === "ADMIN" ? "default" : user.role === "MANAGER" ? "secondary" : "outline"}>
                    {roleLabels[user.role as keyof typeof roleLabels] ?? user.role}
                  </Badge>
                </TableCell>
                <TableCell>{teamLabel}</TableCell>
                <TableCell>
                  {user.employmentStartDate ? new Date(user.employmentStartDate).toLocaleDateString() : "—"}
                </TableCell>
                <TableCell>{user.workingHoursPerDay ?? 8} h</TableCell>
                <TableCell>
                  {user.birthDate ? new Date(user.birthDate).toLocaleDateString() : "—"}
                </TableCell>
                <TableCell>{user.hasChild ? "Áno" : "Nie"}</TableCell>
                <TableCell>{formatHoursWithDays(user.annualLeaveAllowanceHours, user.workingHoursPerDay)}</TableCell>
                <TableCell>{formatHoursWithDays(user.carryOverHours, user.workingHoursPerDay)}</TableCell>
                <TableCell>{formatHoursWithDays(user.remainingLeaveHours, user.workingHoursPerDay)}</TableCell>
                <TableCell>
                  <Badge variant={user.isActive ? "default" : "destructive"}>
                    {user.isActive ? "Aktívny" : "Neaktívny"}
                  </Badge>
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2">
                    <Button variant="outline" size="sm" onClick={() => openEdit(user)}>
                      Upraviť
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => handleResetPassword(user)}
                      disabled={resetPasswordMutation.isPending}
                    >
                      Reset hesla
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleDelete(user)}
                      disabled={deleteMutation.isPending}
                    >
                      Odstrániť
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>{editingUser ? "Upraviť používateľa" : "Pridať používateľa"}</DialogTitle>
            <DialogDescription>
              Vyplňte základné informácie o používateľovi a priraďte mu rolu alebo tím.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="user-name">Meno</Label>
                <Input id="user-name" {...register("name", { required: true })} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="user-email">Email</Label>
                <Input id="user-email" type="email" {...register("email", { required: true })} />
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-1">
                <Label>Rola</Label>
                <Select
                  value={watch("role")}
                  onValueChange={(value) => {
                    setValue("role", value as UserFormValues["role"]);
                    if (value === "ADMIN") {
                      setValue("teamId", "none");
                      setValue("managedTeamIds", []);
                    }
                    if (value === "EMPLOYEE") {
                      setValue("managedTeamIds", []);
                    }
                  }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="EMPLOYEE">Zamestnanec</SelectItem>
                    <SelectItem value="MANAGER">Manažér</SelectItem>
                    <SelectItem value="ADMIN">Admin</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1">
                <Label>{watch("role") === "MANAGER" ? "Tím (ako zamestnanec)" : "Tím"}</Label>
                <Select
                  value={watch("teamId")}
                  onValueChange={(value) => setValue("teamId", value)}
                  disabled={watch("role") === "ADMIN"}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Bez tímu" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">Bez tímu</SelectItem>
                    {teams.map((team: any) => (
                      <SelectItem key={team.id} value={String(team.id)}>
                        {team.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {watch("role") === "MANAGER" && (
              <div className="space-y-2">
                <Label>Tímy manažéra</Label>
                <div className="grid gap-2 md:grid-cols-2">
                  {teams.map((team: any) => {
                    const teamId = String(team.id);
                    const isChecked = (watch("managedTeamIds") || []).includes(teamId);
                    return (
                      <label key={team.id} className="flex items-center gap-2 rounded-md border p-2">
                        <Checkbox
                          checked={isChecked}
                          onCheckedChange={(checked) => toggleManagedTeam(teamId, Boolean(checked))}
                        />
                        <span className="text-sm">{team.name}</span>
                      </label>
                    );
                  })}
                </div>
                <p className="text-xs text-muted-foreground">
                  Manažér bude mať prístup k žiadostiam a kalendáru vo vybraných tímoch.
                </p>
              </div>
            )}

            {watch("role") === "ADMIN" && (
              <div className="flex items-center gap-2">
                <Checkbox
                  id="user-email-notifications-enabled"
                  checked={watch("emailNotificationsEnabled")}
                  onCheckedChange={(value) => setValue("emailNotificationsEnabled", Boolean(value))}
                />
                <Label htmlFor="user-email-notifications-enabled">
                  Odosielať notifikácie na email
                </Label>
              </div>
            )}

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="user-birth-date">Dátum narodenia</Label>
                <Input id="user-birth-date" type="date" {...register("birthDate")} />
              </div>
              <div className="flex items-center gap-2 pt-6">
                <Checkbox
                  id="user-has-child"
                  checked={watch("hasChild")}
                  onCheckedChange={(value) => setValue("hasChild", Boolean(value))}
                />
                <Label htmlFor="user-has-child">Má dieťa</Label>
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="user-working-hours">Pracovná doba za deň (hodiny)</Label>
                <Input
                  id="user-working-hours"
                  type="number"
                  min={0.5}
                  step="0.5"
                  placeholder="Napr. 7.5"
                  {...register("workingHoursPerDay", { required: true })}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="user-start-date">Dátum nástupu</Label>
                <Input id="user-start-date" type="date" {...register("employmentStartDate")} />
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="user-manual-allowance">Nárok dovolenky na začiatku roka</Label>
                <p className="text-xs text-muted-foreground">
                  Aktuálny formát zadania: {watch("manualLeaveAllowanceUnit") === "DAYS" ? "dni" : "hodiny"}
                </p>
                <div className="grid grid-cols-[1fr_auto] gap-2">
                  <Input
                    id="user-manual-allowance"
                    type="number"
                    min={0}
                    step="0.5"
                    placeholder={watch("manualLeaveAllowanceUnit") === "DAYS" ? "Napr. 20" : "Napr. 160"}
                    {...register("manualLeaveAllowanceHours")}
                  />
                  <Select
                    value={watch("manualLeaveAllowanceUnit")}
                    onValueChange={(value) => {
                      const nextUnit = value as UserFormValues["manualLeaveAllowanceUnit"];
                      const currentUnit = watch("manualLeaveAllowanceUnit");
                      const workingHoursPerDay = Number(watch("workingHoursPerDay")) || 8;
                      setValue(
                        "manualLeaveAllowanceHours",
                        convertValueBetweenUnits(
                          watch("manualLeaveAllowanceHours"),
                          currentUnit,
                          nextUnit,
                          workingHoursPerDay
                        )
                      );
                      setValue("manualLeaveAllowanceUnit", nextUnit);
                    }}
                  >
                    <SelectTrigger className="w-[110px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="HOURS">Hodiny</SelectItem>
                      <SelectItem value="DAYS">Dni</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <p className="text-xs text-muted-foreground">
                  Ak pole necháte prázdne, systém vypočíta nárok automaticky.
                </p>
              </div>

              <div className="space-y-1">
                <Label htmlFor="user-manual-carry-over"> dovolenka z minulého roka</Label>
                <p className="text-xs text-muted-foreground">
                  Aktuálny formát zadania: {watch("manualCarryOverUnit") === "DAYS" ? "dni" : "hodiny"}
                </p>
                <div className="grid grid-cols-[1fr_auto] gap-2">
                  <Input
                    id="user-manual-carry-over"
                    type="number"
                    min={0}
                    step="0.5"
                    placeholder={watch("manualCarryOverUnit") === "DAYS" ? "Napr. 3" : "Napr. 24"}
                    {...register("manualCarryOverHours")}
                  />
                  <Select
                    value={watch("manualCarryOverUnit")}
                    onValueChange={(value) => {
                      const nextUnit = value as UserFormValues["manualCarryOverUnit"];
                      const currentUnit = watch("manualCarryOverUnit");
                      const workingHoursPerDay = Number(watch("workingHoursPerDay")) || 8;
                      setValue(
                        "manualCarryOverHours",
                        convertValueBetweenUnits(
                          watch("manualCarryOverHours"),
                          currentUnit,
                          nextUnit,
                          workingHoursPerDay
                        )
                      );
                      setValue("manualCarryOverUnit", nextUnit);
                    }}
                  >
                    <SelectTrigger className="w-[110px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="HOURS">Hodiny</SelectItem>
                      <SelectItem value="DAYS">Dni</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <p className="text-xs text-muted-foreground">
                  Ručne nastaví počet hodín prenesených do aktuálneho roka.
                </p>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                Zrušiť
              </Button>
              <Button type="submit" disabled={createMutation.isPending || updateMutation.isPending}>
                {createMutation.isPending || updateMutation.isPending ? "Ukladá sa..." : "Uložiť"}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
