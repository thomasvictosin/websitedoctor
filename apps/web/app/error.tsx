"use client";

export default function DashboardError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="app-shell">
      <section className="panel" role="alert" aria-live="assertive">
        <p className="eyebrow">Dashboard unavailable</p>
        <h1>We couldn’t load the dashboard.</h1>
        <p>Your websites and monitoring data are still stored. Try loading the dashboard again.</p>
        <button className="button button-primary" type="button" onClick={reset}>Try again</button>
      </section>
    </main>
  );
}
