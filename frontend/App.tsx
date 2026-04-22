import type { ReactElement } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import Navigation from "./components/layout/Navigation";
import CalendarPage from "./pages/CalendarPage";
import MyRequestsPage from "./pages/MyRequestsPage";
import TeamPage from "./pages/TeamPage";
import ApprovalsPage from "./pages/ApprovalsPage";
import AdminPage from "./pages/AdminPage";
import LoginPage from "./pages/LoginPage";
import MagicLinkPage from "./pages/MagicLinkPage";
import NotificationsPage from "./pages/NotificationsPage";
import ProfilePage from "./pages/ProfilePage";
import OnboardingPage from "./pages/OnboardingPage";
import StatsDashboardPage from "./pages/StatsDashboardPage";
import StatsCalendarPage from "./pages/StatsCalendarPage";
import StatsExportPage from "./pages/StatsExportPage";
import { AuthProvider, requiresOnboarding, useAuth } from "@/lib/auth";
import { useBackend } from "@/lib/backend";
import type { UserRole } from "~backend/shared/types";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export default function App() {
  return (
    <AuthProvider>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <div className="min-h-screen bg-background">
            <Navigation />
            <main className="container mx-auto px-4 py-4 sm:py-6">
              <Routes>
                <Route path="/" element={<Navigate to="/calendar" replace />} />
                <Route path="/login" element={<LoginPage />} />
                <Route path="/magic-link" element={<MagicLinkPage />} />
                <Route
                  path="/onboarding"
                  element={
                    <RequireOnboarding>
                      <OnboardingPage />
                    </RequireOnboarding>
                  }
                />
                <Route
                  path="/calendar"
                  element={
                    <RequireCompletedProfile>
                      <CalendarPage />
                    </RequireCompletedProfile>
                  }
                />
                <Route
                  path="/my-requests"
                  element={
                    <RequireCompletedProfile>
                      <MyRequestsPage />
                    </RequireCompletedProfile>
                  }
                />
                <Route
                  path="/team"
                  element={
                    <RequireRole roles={["MANAGER", "ADMIN"]}>
                      <TeamPage />
                    </RequireRole>
                  }
                />
                <Route
                  path="/approvals"
                  element={
                    <RequireRole roles={["MANAGER", "ADMIN"]}>
                      <ApprovalsPage />
                    </RequireRole>
                  }
                />
                <Route
                  path="/notifications"
                  element={
                    <RequireCompletedProfile>
                      <NotificationsPage />
                    </RequireCompletedProfile>
                  }
                />
                <Route
                  path="/profile"
                  element={
                    <RequireCompletedProfile>
                      <ProfilePage />
                    </RequireCompletedProfile>
                  }
                />
                <Route
                  path="/admin"
                  element={
                    <RequireRole roles={["ADMIN"]}>
                      <AdminPage />
                    </RequireRole>
                  }
                />
                <Route
                  path="/stats"
                  element={
                    <RequireRole roles={["MANAGER", "ADMIN"]}>
                      <StatsDashboardPage />
                    </RequireRole>
                  }
                />
                <Route
                  path="/stats/calendar"
                  element={
                    <RequireRole roles={["MANAGER", "ADMIN"]}>
                      <StatsCalendarPage />
                    </RequireRole>
                  }
                />
                <Route
                  path="/stats/export"
                  element={
                    <RequireRole roles={["MANAGER", "ADMIN"]}>
                      <StatsExportPage />
                    </RequireRole>
                  }
                />
              </Routes>
            </main>
            <Toaster />
          </div>
        </BrowserRouter>
      </QueryClientProvider>
    </AuthProvider>
  );
}

function RequireAuth({ children }: { children: ReactElement }) {
  const { user } = useAuth();
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

function RequireCompletedProfile({ children }: { children: ReactElement }) {
  const { user } = useAuth();
  const backend = useBackend();
  const profileQuery = useQuery({
    queryKey: ["me"],
    enabled: Boolean(user),
    queryFn: () => backend.users.me(),
  });

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (profileQuery.isLoading) {
    return <div className="py-12 text-center text-sm text-muted-foreground">Načítava sa profil...</div>;
  }

  const needsOnboarding = profileQuery.data
    ? Boolean(user.role !== "ADMIN" && profileQuery.data.onboardingCompleted !== true)
    : requiresOnboarding(user);

  if (needsOnboarding) {
    return <Navigate to="/onboarding" replace />;
  }
  return children;
}

function RequireOnboarding({ children }: { children: ReactElement }) {
  const { user } = useAuth();
  const backend = useBackend();
  const profileQuery = useQuery({
    queryKey: ["me"],
    enabled: Boolean(user),
    queryFn: () => backend.users.me(),
  });

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (profileQuery.isLoading) {
    return <div className="py-12 text-center text-sm text-muted-foreground">Načítava sa profil...</div>;
  }

  const needsOnboarding = profileQuery.data
    ? Boolean(user.role !== "ADMIN" && profileQuery.data.onboardingCompleted !== true)
    : requiresOnboarding(user);

  if (!needsOnboarding) {
    return <Navigate to="/calendar" replace />;
  }
  return children;
}

function RequireRole({ children, roles }: { children: ReactElement; roles: UserRole[] }) {
  const { user } = useAuth();
  const backend = useBackend();
  const profileQuery = useQuery({
    queryKey: ["me"],
    enabled: Boolean(user),
    queryFn: () => backend.users.me(),
  });

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (profileQuery.isLoading) {
    return <div className="py-12 text-center text-sm text-muted-foreground">Načítava sa profil...</div>;
  }

  const needsOnboarding = profileQuery.data
    ? Boolean(user.role !== "ADMIN" && profileQuery.data.onboardingCompleted !== true)
    : requiresOnboarding(user);

  if (needsOnboarding) {
    return <Navigate to="/onboarding" replace />;
  }
  if (!roles.includes(user.role)) {
    return <Navigate to="/calendar" replace />;
  }
  return children;
}
