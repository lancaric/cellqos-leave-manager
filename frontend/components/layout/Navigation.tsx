import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Bell,
  Calendar,
  FileText,
  Users,
  CheckSquare,
  Settings,
  BarChart3,
  Menu,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/lib/auth";
import { useBackend } from "@/lib/backend";

export default function Navigation() {
  const location = useLocation();
  const { user, logout } = useAuth();
  const backend = useBackend();
  const userRole = user?.role ?? "EMPLOYEE";
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { path: "/calendar", label: "Kalendár", icon: Calendar, roles: ["EMPLOYEE", "MANAGER", "ADMIN"] },
    { path: "/my-requests", label: "Moje žiadosti", icon: FileText, roles: ["EMPLOYEE", "MANAGER", "ADMIN"] },
    { path: "/notifications", label: "Notifikácie", icon: Bell, roles: ["EMPLOYEE", "MANAGER", "ADMIN"] },
    { path: "/team", label: "Tím", icon: Users, roles: ["EMPLOYEE", "MANAGER", "ADMIN"] },
    { path: "/approvals", label: "Schvaľovanie", icon: CheckSquare, roles: ["MANAGER", "ADMIN"] },
    { path: "/stats", label: "Štatistiky", icon: BarChart3, roles: ["MANAGER", "ADMIN"] },
    { path: "/admin", label: "Administrácia", icon: Settings, roles: ["ADMIN"] },
  ];

  const notificationsQuery = useQuery({
    queryKey: ["notifications"],
    enabled: Boolean(user),
    queryFn: async () => {
      const response = await backend.notifications.list();
      return response.notifications;
    },
  });

  const unreadCount = notificationsQuery.data?.filter((notification) => !notification.readAt).length ?? 0;
  const visibleItems = user ? navItems.filter((item) => item.roles.includes(userRole)) : [];
  const profileLabel = user
    ? `${user.name} (${user.role === "ADMIN" ? "Admin" : user.role === "MANAGER" ? "Manažér" : "Zamestnanec"})`
    : null;

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  return (
    <nav className="sticky top-0 z-40 border-b bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/80">
      <div className="container mx-auto px-3 sm:px-4">
        <div className="flex min-h-14 items-center justify-between gap-2 py-2 sm:min-h-16 sm:gap-3 sm:py-3">
          <div className="flex min-w-0 items-center gap-3 lg:gap-8">
            <Link to="/" className="flex min-w-0 items-center gap-2">
              <Calendar className="h-6 w-6 shrink-0 text-primary" />
              <span className="truncate text-base font-semibold sm:text-lg">CellQos Správa dovoleniek</span>
            </Link>

            <div className="hidden flex-wrap gap-1 lg:flex">
              {visibleItems.map((item) => {
                const Icon = item.icon;
                const isActive =
                  location.pathname === item.path || location.pathname.startsWith(`${item.path}/`);

                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={cn(
                      "flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors",
                      isActive
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                    )}
                  >
                    <Icon className="h-4 w-4" />
                    <span>{item.label}</span>
                    {item.path === "/notifications" && unreadCount > 0 && (
                      <Badge variant="secondary" className="ml-1 px-2 py-0 text-xs">
                        {unreadCount}
                      </Badge>
                    )}
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="hidden items-center gap-4 lg:flex">
            {user ? (
              <>
                <Link
                  to="/profile"
                  className="text-sm text-muted-foreground transition-colors hover:text-foreground"
                >
                  {profileLabel}
                </Link>
                <Button variant="outline" size="sm" onClick={logout}>
                  Odhlásiť
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" asChild>
                <Link to="/login">Prihlásiť</Link>
              </Button>
            )}
          </div>

          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="lg:hidden"
            aria-label={mobileMenuOpen ? "Zavrieť menu" : "Otvoriť menu"}
            aria-expanded={mobileMenuOpen}
            onClick={() => setMobileMenuOpen((value) => !value)}
          >
            {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
        </div>

        {mobileMenuOpen && (
          <div className="max-h-[calc(100dvh-3.5rem)] overflow-y-auto border-t py-3 lg:hidden">
            <div className="flex flex-col gap-2">
              {visibleItems.map((item) => {
                const Icon = item.icon;
                const isActive =
                  location.pathname === item.path || location.pathname.startsWith(`${item.path}/`);

                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={cn(
                      "flex items-center justify-between rounded-md px-3 py-3 text-sm font-medium transition-colors",
                      isActive
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                    )}
                  >
                    <span className="flex items-center gap-3">
                      <Icon className="h-4 w-4 shrink-0" />
                      <span>{item.label}</span>
                    </span>
                    {item.path === "/notifications" && unreadCount > 0 && (
                      <Badge variant="secondary" className="px-2 py-0 text-xs">
                        {unreadCount}
                      </Badge>
                    )}
                  </Link>
                );
              })}

              <div className="mt-2 rounded-lg border bg-muted/30 p-3">
                {user ? (
                  <div className="space-y-3">
                    <Link
                      to="/profile"
                      className="block text-sm text-muted-foreground transition-colors hover:text-foreground"
                    >
                      {profileLabel}
                    </Link>
                    <Button variant="outline" className="w-full" onClick={logout}>
                      Odhlásiť
                    </Button>
                  </div>
                ) : (
                  <Button variant="outline" className="w-full" asChild>
                    <Link to="/login">Prihlásiť</Link>
                  </Button>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
      {mobileMenuOpen && (
        <button
          type="button"
          aria-label="Zavrieť menu"
          className="fixed inset-0 top-16 z-[-1] bg-black/20 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}
    </nav>
  );
}
