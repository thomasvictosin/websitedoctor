"use client";

import { FormEvent, useState } from "react";

export default function LoginForm({ configured }: { configured: boolean }) {
  const [email, setEmail] = useState("admin@localhost");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const responseText = await response.text();
      let result: { error?: string } | null = null;
      try {
        result = responseText ? JSON.parse(responseText) as { error?: string } : null;
      } catch {
        result = null;
      }
      if (!response.ok) {
        throw new Error(result?.error ?? `Sign in failed (HTTP ${response.status}). Check that the app and its database are running.`);
      }
      if (!result) throw new Error("The sign-in service returned an invalid response. Check the app terminal for details.");
      window.location.reload();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Sign in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-shell">
      <form className="panel login-panel" onSubmit={submit}>
        <a className="brand" href="/">
          <span className="brand-mark">+</span>
          <span>website<span className="brand-accent">doctor</span></span>
        </a>
        <p className="eyebrow">SECURE SIGN IN</p>
        <h1>Sign in to your dashboard</h1>
        {!configured ? (
          <p className="login-message" role="alert">
            Authentication is not configured. Generate an scrypt verifier with <code>npm run auth:hash-password --workspace apps/web</code>, then set <code>ADMIN_PASSWORD_HASH</code> and a private <code>SESSION_SECRET</code> of at least 32 bytes in <code>.env</code>.
          </p>
        ) : (
          <>
            <label htmlFor="admin-email">EMAIL</label>
            <input id="admin-email" type="email" autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} required />
            <label htmlFor="admin-password">PASSWORD</label>
            <input id="admin-password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required />
            <button className="button primary full-width" type="submit" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"} <span>→</span>
            </button>
            {message && <p className="login-message" role="alert">{message}</p>}
          </>
        )}
      </form>
    </main>
  );
}
