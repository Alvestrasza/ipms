"use client";

export default function ErrorPage({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="state-page">
      <p className="eyebrow">Console error</p>
      <h1>Unable to display this view</h1>
      <p>The failure was contained. No infrastructure action was executed.</p>
      <button className="primary-button" type="button" onClick={reset}>
        Try again
      </button>
    </main>
  );
}
