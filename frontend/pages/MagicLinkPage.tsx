import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { useToast } from "@/components/ui/use-toast";
import { apiBaseUrl, requiresOnboarding, useAuth } from "@/lib/auth";

export default function MagicLinkPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setSession } = useAuth();
  const { toast } = useToast();
  const [status, setStatus] = useState("Overovanie magic linku...");

  useEffect(() => {
    const token = searchParams.get("token");
    if (!token) {
      setStatus("Chýba token v odkaze.");
      return;
    }

    const verify = async () => {
      try {
        const response = await fetch(`${apiBaseUrl}/auth/magic-link/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });

        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.message || "Magic link je neplatný");
        }

        const payload = await response.json();
        setSession(payload);
        toast({ title: "Prihlásenie cez magic link bolo úspešné" });
        navigate(requiresOnboarding(payload.user) ? "/onboarding" : "/calendar", { replace: true });
      } catch (error: any) {
        setStatus("Overenie zlyhalo.");
        toast({
          title: "Magic link zlyhal",
          description: error.message,
          variant: "destructive",
        });
      }
    };

    void verify();
  }, [navigate, searchParams, setSession, toast]);

  return (
    <div className="max-w-xl mx-auto">
      <Card className="p-6">
        <h1 className="text-2xl font-semibold">Magic link</h1>
        <p className="text-sm text-muted-foreground mt-2">{status}</p>
      </Card>
    </div>
  );
}
