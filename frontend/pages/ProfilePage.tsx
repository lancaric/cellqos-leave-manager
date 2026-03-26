import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/lib/auth";
import { useBackend } from "@/lib/backend";
import { formatLeaveHours } from "@/lib/leaveFormat";
import { Card } from "@/components/ui/card";
import ChangePasswordForm from "@/components/auth/ChangePasswordForm";

function ProfileRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium sm:text-right">{value}</span>
    </div>
  );
}

export default function ProfilePage() {
  const { user } = useAuth();
  const backend = useBackend();

  const userQuery = useQuery({
    queryKey: ["me"],
    enabled: Boolean(user),
    queryFn: () => backend.users.me(),
  });

  const balanceQuery = useQuery({
    queryKey: ["leave-balance", user?.id],
    enabled: Boolean(user),
    queryFn: () => backend.leave_balances.me(),
  });

  if (!user) {
    return null;
  }

  const displayedUser = userQuery.data ?? user;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">Profil</h1>
        <p className="text-sm text-muted-foreground">
          Základné informácie o vašom účte a zostatku dovolenky.
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="space-y-4 p-6">
          <div>
            <h2 className="text-xl font-semibold">Osobné údaje</h2>
            <p className="text-sm text-muted-foreground">Údaje prihláseného používateľa.</p>
          </div>
          <div className="space-y-3 text-sm">
            <ProfileRow label="Meno" value={displayedUser?.name} />
            <ProfileRow label="Email" value={displayedUser?.email} />
            <ProfileRow
              label="Rola"
              value={
                displayedUser?.role === "ADMIN"
                  ? "Admin"
                  : displayedUser?.role === "MANAGER"
                    ? "Manažér"
                    : "Zamestnanec"
              }
            />
            <ProfileRow
              label="Dátum narodenia"
              value={displayedUser?.birthDate ? new Date(displayedUser.birthDate).toLocaleDateString() : "—"}
            />
            <ProfileRow label="Dieťa" value={displayedUser?.hasChild ? "Áno" : "Nie"} />
          </div>
        </Card>

        <Card className="space-y-4 p-6">
          <div>
            <h2 className="text-xl font-semibold">Dovolenka</h2>
            <p className="text-sm text-muted-foreground">Prehľad dostupného času.</p>
          </div>
          {balanceQuery.isLoading ? (
            <div className="text-sm text-muted-foreground">Načítava sa zostatok...</div>
          ) : balanceQuery.isError ? (
            <div className="text-sm text-destructive">Nepodarilo sa načítať zostatok.</div>
          ) : (
            <div className="space-y-3 text-sm">
              <ProfileRow label="Rok" value={balanceQuery.data?.year} />
              <ProfileRow
                label="Nárok"
                value={formatLeaveHours(balanceQuery.data?.allowanceHours)}
              />
              <ProfileRow
                label="Použité / plánované"
                value={formatLeaveHours(balanceQuery.data?.usedHours)}
              />
              <ProfileRow
                label="Zostatok (aj s plánovanými)"
                value={formatLeaveHours(balanceQuery.data?.remainingHours)}
              />
            </div>
          )}
        </Card>
      </div>

      <Card className="max-w-xl space-y-4 p-6">
        <div>
          <h2 className="text-xl font-semibold">Zmena hesla</h2>
          <p className="text-sm text-muted-foreground">Aktualizujte svoje prihlasovacie heslo.</p>
        </div>
        <ChangePasswordForm />
      </Card>
    </div>
  );
}
