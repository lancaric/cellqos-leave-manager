import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/ui/use-toast";
import { apiBaseUrl, requiresOnboarding, useAuth } from "@/lib/auth";

interface AuthResponse {
  token: string;
  user: {
    id: string;
    email: string;
    name: string;
    role: "EMPLOYEE" | "MANAGER" | "ADMIN";
    mustChangePassword?: boolean;
    profileCompleted?: boolean;
  };
}

export default function LoginPage() {
  const navigate = useNavigate();
  const { setSession } = useAuth();
  const { toast } = useToast();
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [magicEmail, setMagicEmail] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isMagicSubmitting, setIsMagicSubmitting] = useState(false);

  const handleLogin = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsSubmitting(true);
    try {
      const response = await fetch(`${apiBaseUrl}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: login, password }),
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.message || "Prihlásenie zlyhalo");
      }

      const payload = (await response.json()) as AuthResponse;
      setSession(payload);
      toast({ title: "Prihlásenie bolo úspešné" });
      navigate(requiresOnboarding(payload.user) ? "/onboarding" : "/calendar", { replace: true });
    } catch (error: any) {
      toast({
        title: "Prihlásenie zlyhalo",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleMagicLink = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsMagicSubmitting(true);
    try {
      const response = await fetch(`${apiBaseUrl}/auth/magic-link`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: magicEmail,
          redirectUrl: `${window.location.origin}/magic-link`,
        }),
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.message || "Žiadosť o magic link zlyhala");
      }

      const payload = (await response.json()) as {
        magicLinkUrl?: string;
      };

      if (payload.magicLinkUrl) {
        toast({
          title: "Magic link bol vytvorený",
          description: (
            <span>
              Odkaz pre prihlásenie nájdete tu:{" "}
              <a className="underline" href={payload.magicLinkUrl}>
                Magic link
              </a>
            </span>
          ),
        });
      } else {
        toast({
          title: "Magic link bol odoslaný",
          description: "Skontrolujte svoj email pre pokračovanie.",
        });
      }
    } catch (error: any) {
      toast({
        title: "Magic link zlyhal",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsMagicSubmitting(false);
    }
  };

  return (
    <div className="max-w-xl mx-auto space-y-6">
      <Card className="p-6 space-y-4">
        <div>
          <h1 className="text-2xl font-semibold">Prihlásenie</h1>
          <p className="text-sm text-muted-foreground">Prihláste sa pomocou emailu a hesla.</p>
        </div>
        <form className="space-y-4" onSubmit={handleLogin}>
          <div className="space-y-2">
            <Label htmlFor="email">Email alebo AD konto</Label>
            <Input
              id="email"
              type="text"
              value={login}
              onChange={(event) => setLogin(event.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Heslo</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </div>
          <Button type="submit" disabled={isSubmitting} className="w-full">
            {isSubmitting ? "Prihlasuje sa..." : "Prihlásiť"}
          </Button>
        </form>
      </Card>

      <Card className="p-6 space-y-4">
        <div>
          <h2 className="text-xl font-semibold">Magic link (voliteľné)</h2>
          <p className="text-sm text-muted-foreground">Pošlite si jednorazový odkaz na prihlásenie.</p>
        </div>
        <form className="space-y-4" onSubmit={handleMagicLink}>
          <div className="space-y-2">
            <Label htmlFor="magic-email">Email</Label>
            <Input
              id="magic-email"
              type="email"
              value={magicEmail}
              onChange={(event) => setMagicEmail(event.target.value)}
              required
            />
          </div>
          <Button type="submit" variant="outline" disabled={isMagicSubmitting} className="w-full">
            {isMagicSubmitting ? "Odosiela sa..." : "Poslať magic link"}
          </Button>
        </form>
      </Card>
    </div>
  );
}
