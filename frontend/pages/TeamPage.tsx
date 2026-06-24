import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useBackend } from "@/lib/backend";
import { useAuth } from "@/lib/auth";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import RequestsList from "@/components/requests/RequestsList";
import RequestFormDialog from "@/components/requests/RequestFormDialog";

export default function TeamPage() {
  const backend = useBackend();
  const { user } = useAuth();
  const isManager = user?.role === "MANAGER" || user?.role === "ADMIN";
  const [activeTab, setActiveTab] = useState("all");
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  const { data: meData } = useQuery({
    queryKey: ["me"],
    enabled: Boolean(user),
    queryFn: async () => backend.users.me(),
  });

  const { data: teamsData } = useQuery({
    queryKey: ["teams"],
    queryFn: async () => backend.teams.list(),
  });

  const visibleTeams = useMemo(() => {
    const teams = teamsData?.teams || [];
    if (user?.role === "ADMIN") {
      return teams;
    }
    const visibleTeamIds = new Set<number>(
      ((meData?.visibleTeamIds as number[] | undefined) ?? []).filter(
        (value): value is number => typeof value === "number" && Number.isFinite(value)
      )
    );
    if (isManager) {
      return teams.filter((team) => visibleTeamIds.has(team.id));
    }
    if (visibleTeamIds.size === 0) {
      return [];
    }
    return teams.filter((team) => visibleTeamIds.has(team.id));
  }, [isManager, meData?.visibleTeamIds, teamsData?.teams, user?.role]);

  useEffect(() => {
    if (isManager) {
      return;
    }
    if (visibleTeams.length === 0) {
      setActiveTab("all");
      return;
    }
    const ownTeamTab = String(visibleTeams[0].id);
    if (activeTab !== ownTeamTab) {
      setActiveTab(ownTeamTab);
    }
  }, [activeTab, isManager, visibleTeams]);

  const parsedTeamId = activeTab === "all" ? undefined : Number.parseInt(activeTab, 10);
  const selectedTeamId = Number.isNaN(parsedTeamId) ? undefined : parsedTeamId;
  const teamFilter = isManager ? selectedTeamId : meData?.teamId ?? selectedTeamId;

  const { data: requestsData, isLoading, refetch } = useQuery({
    queryKey: ["team-requests", teamFilter ?? "all"],
    queryFn: async () => {
      return backend.leave_requests.list(teamFilter ? { teamId: teamFilter } : {});
    },
  });

  const allRequests = requestsData?.requests || [];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">Prehľad tímov</h1>
        {isManager && (
          <Button onClick={() => setShowCreateDialog(true)} className="w-full sm:w-auto">
            Nová žiadosť
          </Button>
        )}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          {isManager && <TabsTrigger value="all">Všetky tímy</TabsTrigger>}
          {visibleTeams.map((team) => (
            <TabsTrigger key={team.id} value={String(team.id)}>
              {team.name}
            </TabsTrigger>
          ))}
        </TabsList>

        {isManager && (
          <TabsContent value="all" className="mt-6">
            <RequestsList requests={allRequests} isLoading={isLoading} onUpdate={refetch} showUser />
          </TabsContent>
        )}

        {visibleTeams.map((team) => (
          <TabsContent key={team.id} value={String(team.id)} className="mt-6">
            <RequestsList requests={allRequests} isLoading={isLoading} onUpdate={refetch} showUser />
          </TabsContent>
        ))}
      </Tabs>

      {showCreateDialog && (
        <RequestFormDialog
          open={showCreateDialog}
          onClose={() => {
            setShowCreateDialog(false);
            refetch();
          }}
        />
      )}
    </div>
  );
}
