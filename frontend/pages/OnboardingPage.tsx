import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/components/ui/use-toast";
import { useAuth } from "@/lib/auth";
import { useBackend } from "@/lib/backend";
import { formatLeaveHours } from "@/lib/leaveFormat";

interface OnboardingFormValues {
  birthDate: string;
  hasChild: boolean;
  teamId: string;
  employmentStartDate: string;
  unknownStartDate: boolean;
}

export default function OnboardingPage() {
  const navigate = useNavigate();
  const backend = useBackend();
  const { session, setSession } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const userQuery = useQuery({
    queryKey: ["me"],
    enabled: Boolean(session?.token),
    queryFn: () => backend.users.me(),
  });

  const teamsQuery = useQuery({
    queryKey: ["teams"],
    enabled: Boolean(session?.token),
    queryFn: () => backend.teams.list(),
  });

  const { register, handleSubmit, reset, setValue, watch } = useForm<OnboardingFormValues>({
    defaultValues: {
      birthDate: "",
      hasChild: false,
      teamId: "none",
      employmentStartDate: "",
      unknownStartDate: false,
    },
  });

  useEffect(() => {
    if (!userQuery.data) {
      return;
    }

    reset({
      birthDate: userQuery.data.birthDate ? String(userQuery.data.birthDate).slice(0, 10) : "",
      hasChild: Boolean(userQuery.data.hasChild),
      teamId: userQuery.data.teamId ? String(userQuery.data.teamId) : "none",
      employmentStartDate: userQuery.data.employmentStartDate ? String(userQuery.data.employmentStartDate).slice(0, 10) : "",
      unknownStartDate: !userQuery.data.employmentStartDate,
    });
  }, [reset, userQuery.data]);

  const onboardingMutation = useMutation({
    mutationFn: (payload: {
      birthDate: string;
      hasChild: boolean;
      employmentStartDate?: string | null;
      teamId?: number | null;
    }) => backend.users.completeOnboarding(payload),
    onSuccess: (result) => {
      if (session) {
        setSession({
          ...session,
          user: {
            ...session.user,
            ...result.user,
            profileCompleted: true,
            onboardingCompleted: true,
          },
        });
      }

      // Invalidate the /users/me cache so the guard fetches fresh data
      queryClient.invalidateQueries({ queryKey: ["me"] });

      toast({
        title: "Profil bol uložený",
        description: `Váš aktuálny nárok je ${formatLeaveHours(result.allowanceHours)}.`,
      });
      navigate("/calendar", { replace: true });
    },
    onError: (error: any) => {
      toast({
        title: "Uloženie profilu zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  if (!session) {
    return null;
  }

  const unknownStartDate = watch("unknownStartDate");
  const teams = teamsQuery.data?.teams ?? [];

  const onSubmit = (values: OnboardingFormValues) => {
    if (teams.length > 0 && values.teamId === "none") {
      toast({
        title: "Vyberte tím",
        description: "Pre pokračovanie je potrebné priradiť používateľa do tímu.",
        variant: "destructive",
      });
      return;
    }

    onboardingMutation.mutate({
      birthDate: values.birthDate,
      hasChild: values.hasChild,
      employmentStartDate: values.unknownStartDate ? null : values.employmentStartDate || null,
      teamId: values.teamId !== "none" ? Number(values.teamId) : null,
    });
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Dokončenie profilu</h1>
        <p className="max-w-2xl text-sm text-muted-foreground">
          Pred prvým použitím doplňte základné údaje. Na ich základe systém nastaví správny nárok na dovolenku.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.25fr_0.75fr]">
        <Card className="p-6">
          <form className="space-y-5" onSubmit={handleSubmit(onSubmit)}>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="birthDate">Dátum narodenia</Label>
                <Input id="birthDate" type="date" {...register("birthDate", { required: true })} />
              </div>
              <div className="flex items-center gap-2 pt-8">
                <Checkbox
                  id="hasChild"
                  checked={watch("hasChild")}
                  onCheckedChange={(value) => setValue("hasChild", Boolean(value))}
                />
                <Label htmlFor="hasChild">Mám dieťa</Label>
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Priradený tím</Label>
                <Select value={watch("teamId")} onValueChange={(value) => setValue("teamId", value)}>
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
              <div className="space-y-2">
                <Label htmlFor="employmentStartDate">Dátum nástupu</Label>
                <Input
                  id="employmentStartDate"
                  type="date"
                  disabled={unknownStartDate}
                  {...register("employmentStartDate")}
                />
                <div className="flex items-center gap-2 pt-1">
                  <Checkbox
                    id="unknownStartDate"
                    checked={unknownStartDate}
                    onCheckedChange={(value) => {
                      const checked = Boolean(value);
                      setValue("unknownStartDate", checked);
                      if (checked) {
                        setValue("employmentStartDate", "");
                      }
                    }}
                  />
                  <Label htmlFor="unknownStartDate">Neviem dátum nástupu</Label>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3">
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setSession(null);
                  navigate("/login", { replace: true });
                }}
              >
                Odhlásiť sa
              </Button>
              <Button type="submit" disabled={onboardingMutation.isPending}>
                {onboardingMutation.isPending ? "Ukladá sa..." : "Pokračovať"}
              </Button>
            </div>
          </form>
        </Card>

        <Card className="p-6 space-y-4">
          <div>
            <h2 className="text-xl font-semibold">Prečo to potrebujeme</h2>
            <p className="text-sm text-muted-foreground">
              Tieto údaje používame na výpočet 160 alebo 200 hodinového nároku a na správne priradenie do tímu.
            </p>
          </div>
          <div className="space-y-3 text-sm text-muted-foreground">
            <p>Zostatok z minulého roka sa pri prvom dokončení profilu neprenáša.</p>
            <p>Váš nárok na dovolenku sa vypočítá na základe osobných údajov a dátumu narodenia.</p>
            <p>Údaje môžete po uložení skontrolovať v profile.</p>
          </div>
          {userQuery.data?.profileCompleted === false ? (
            <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
              Údaje ešte nie sú dokončené. Po odoslaní budete presmerovaný do aplikácie.
            </div>
          ) : null}
        </Card>
      </div>
    </div>
  );
}
