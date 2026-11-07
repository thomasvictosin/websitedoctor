import Dashboard from "./dashboard";
import { ConfirmProvider } from "./confirm-dialog";
import LoginForm from "./login-form";
import { authIsConfigured, hasValidSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function Home() {
  const configured = authIsConfigured();
  const isAuthenticated = configured && await hasValidSession();

  return isAuthenticated
    ? <ConfirmProvider><Dashboard /></ConfirmProvider>
    : <LoginForm configured={configured} />;
}
