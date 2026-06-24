import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import StatsLayout from "@/components/stats/StatsLayout";
import StatsFilters, { type StatsFilterState } from "@/components/stats/StatsFilters";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useBackend } from "@/lib/backend";
import { useAuth } from "@/lib/auth";
import { apiFetch } from "@/lib/apiClient";
import { buildStatsQuery } from "@/lib/stats";
import type { StatsExportFormat, StatsReportType } from "~backend/shared/types";

const reportOptions: Array<{ value: StatsReportType; label: string }> = [
  { value: "DASHBOARD_SUMMARY", label: "Dashboard - súhrn" },
  { value: "TABLE_DETAIL", label: "Tabuľka - detail" },
  { value: "YEAR_CALENDAR", label: "Ročný kalendár" },
  { value: "MONTHLY_LEAVE_REPORT", label: "Mesačný report dovoleniek" },
];

const formatOptions: Array<{ value: StatsExportFormat; label: string }> = [
  { value: "PDF", label: "PDF" },
  { value: "XLSX", label: "XLSX" },
  { value: "CSV", label: "CSV" },
];

export default function StatsExportPage() {
  const backend = useBackend();
  const { user, token } = useAuth();
  const currentYear = new Date().getFullYear();
  const isAdmin = user?.role === "ADMIN";

  const defaultFilters: StatsFilterState = {
    year: currentYear,
    month: undefined,
    quarter: undefined,
    teamId: undefined,
    memberIds: [],
    eventTypes: ["ANNUAL_LEAVE", "SICK_LEAVE", "HOME_OFFICE", "UNPAID_LEAVE", "OTHER"],
  };

  const [filters, setFilters] = useState<StatsFilterState>(defaultFilters);
  const [appliedFilters, setAppliedFilters] = useState<StatsFilterState>(defaultFilters);
  const [reportType, setReportType] = useState<StatsReportType>("DASHBOARD_SUMMARY");
  const [format, setFormat] = useState<StatsExportFormat>("PDF");
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const isMonthlyLeaveReport = reportType === "MONTHLY_LEAVE_REPORT";

  const { data: teamsData } = useQuery({
    queryKey: ["teams"],
    queryFn: () => backend.teams.list(),
    enabled: isAdmin,
  });

  const { data: usersData } = useQuery({
    queryKey: ["stats-users"],
    queryFn: () => backend.users.list(),
    enabled: Boolean(user),
  });

  const exportsQuery = useQuery({
    queryKey: ["stats-exports"],
    queryFn: () => backend.stats.exports.list(),
  });

  const members = useMemo(() => {
    const list = usersData?.users ?? [];
    if (!filters.teamId) {
      return list;
    }
    return list.filter((member) => member.teamId === filters.teamId);
  }, [filters.teamId, usersData?.users]);

  const appliedQuery = useMemo(() => buildStatsQuery(appliedFilters), [appliedFilters]);

  const handleGenerate = async () => {
    setStatusMessage(null);
    try {
      await backend.stats.exports.create({
        reportType,
        format: isMonthlyLeaveReport ? "PDF" : format,
        filters: appliedQuery,
      });
      await exportsQuery.refetch();
      setStatusMessage("Export bol úspešne pripravený.");
    } catch (error) {
      setStatusMessage((error as Error).message);
    }
  };

  const handleReset = () => {
    setFilters(defaultFilters);
    setAppliedFilters(defaultFilters);
    setReportType("DASHBOARD_SUMMARY");
    setFormat("PDF");
    setStatusMessage(null);
  };

  const handleDownload = async (job: { downloadUrl?: string | null; id: string; format: StatsExportFormat }) => {
    if (!job.downloadUrl || !token) {
      setStatusMessage("Export nemá dostupný súbor alebo chýba prihlásenie.");
      return;
    }

    try {
      const response = await apiFetch(job.downloadUrl, { token });
      const contentDisposition = response.headers.get("Content-Disposition") ?? "";
      const match = /filename="?([^"]+)"?/i.exec(contentDisposition);
      const fallbackName = `stats-export-${job.id}.${job.format.toLowerCase()}`;
      const filename = match?.[1] ?? fallbackName;
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      setStatusMessage((error as Error).message);
    }
  };

  return (
    <StatsLayout
      title="Export reportov"
      breadcrumb="Export"
      subtitle="Pripravte exportované reporty pre KPI, tabuľky alebo kalendár."
    >
      <StatsFilters
        filters={filters}
        teams={teamsData?.teams ?? []}
        members={members}
        onChange={setFilters}
        onApply={() => setAppliedFilters(filters)}
        onReset={handleReset}
        showTeamSelect={isAdmin}
      />

      <Card>
        <CardHeader>
          <CardTitle>Nastavenie exportu</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-3">
          <div className="space-y-2">
            <label className="text-sm font-medium">Typ reportu</label>
            <select
              value={reportType}
              onChange={(event) => {
                const nextReportType = event.target.value as StatsReportType;
                setReportType(nextReportType);
                if (nextReportType === "MONTHLY_LEAVE_REPORT") {
                  setFormat("PDF");
                }
              }}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            >
              {reportOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">Formát</label>
            <select
              value={format}
              onChange={(event) => setFormat(event.target.value as StatsExportFormat)}
              disabled={isMonthlyLeaveReport}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-70"
            >
              {formatOptions.map((option) => (
                <option
                  key={option.value}
                  value={option.value}
                  disabled={isMonthlyLeaveReport && option.value !== "PDF"}
                >
                  {option.label}
                </option>
              ))}
            </select>
            {isMonthlyLeaveReport && (
              <p className="text-xs text-muted-foreground">
                Mesačný dovolenkový report sa generuje iba ako PDF podľa firemnej predlohy.
              </p>
            )}
          </div>
          <div className="flex items-end">
            <Button onClick={handleGenerate} className="w-full md:w-auto">
              Vygenerovať export
            </Button>
          </div>
          {statusMessage && (
            <p className="text-sm text-muted-foreground md:col-span-3">{statusMessage}</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>História exportov</CardTitle>
        </CardHeader>
        <CardContent>
          {exportsQuery.isLoading && <p className="text-sm text-muted-foreground">Načítavam exporty...</p>}
          {exportsQuery.error && (
            <p className="text-sm text-destructive">{(exportsQuery.error as Error).message}</p>
          )}
          {!exportsQuery.isLoading && exportsQuery.data?.exports.length === 0 && (
            <p className="text-sm text-muted-foreground">Zatiaľ nemáte žiadne exporty.</p>
          )}
          <div className="grid gap-3">
            {exportsQuery.data?.exports.map((job) => (
              <div key={job.id} className="rounded-md border p-3 text-sm">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <p className="font-medium">
                      {reportOptions.find((option) => option.value === job.reportType)?.label}
                    </p>
                    <p className="text-muted-foreground">
                      {job.format} • {new Date(job.createdAt).toLocaleString("sk-SK")}
                    </p>
                  </div>
                  <span className="rounded-full bg-muted px-2 py-1 text-xs">{job.status}</span>
                </div>
                {job.downloadUrl && (
                  <button
                    type="button"
                    onClick={() => handleDownload(job)}
                    className="mt-2 inline-block text-xs font-medium text-primary underline"
                  >
                    Stiahnuť súbor
                  </button>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </StatsLayout>
  );
}
