"use client";

import { ArrowRight, LoaderCircle } from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useEffect, useState } from "react";
import { useLocale } from "@/i18n/locale-provider";
import type { IpmsSession } from "@/lib/auth-types";

export function LoginForm() {
  const router = useRouter();
  const { dictionary } = useLocale();
  const [csrfToken, setCsrfToken] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    fetch("/api/v1/auth/session/", { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("Session bootstrap failed");
        return (await response.json()) as IpmsSession;
      })
      .then((session) => {
        if (!active) return;
        if (session.authenticated) {
          setIsAuthenticated(true);
          return;
        }
        setCsrfToken(session.csrf_token);
      })
      .catch(() => {
        if (active) setError(dictionary.login.controlPlaneUnavailable);
      })
      .finally(() => {
        if (active) setIsLoading(false);
      });
    return () => {
      active = false;
    };
  }, [dictionary.login.controlPlaneUnavailable]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setIsSubmitting(true);
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/v1/auth/login/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: JSON.stringify({
          username: form.get("username"),
          password: form.get("password"),
        }),
      });
      if (!response.ok) {
        setError(dictionary.login.invalidCredentials);
        return;
      }
      router.replace("/");
      router.refresh();
    } catch {
      setError(dictionary.login.controlPlaneUnavailable);
    } finally {
      setIsSubmitting(false);
    }
  }

  const disabled = isLoading || isSubmitting || !csrfToken;

  if (isAuthenticated) {
    return (
      <button
        className="primary-button"
        type="button"
        onClick={() => router.push("/")}
      >
        <ArrowRight aria-hidden="true" size={17} />
        {dictionary.login.continueToConsole}
      </button>
    );
  }

  return (
    <form onSubmit={submit}>
      <label>
        {dictionary.login.username}
        <input
          type="text"
          name="username"
          autoComplete="username"
          required
          disabled={disabled}
          placeholder={dictionary.login.usernamePlaceholder}
        />
      </label>
      <label>
        {dictionary.login.password}
        <input
          type="password"
          name="password"
          autoComplete="current-password"
          required
          disabled={disabled}
          placeholder="••••••••••••"
        />
      </label>
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
      <button className="primary-button" type="submit" disabled={disabled}>
        {isSubmitting ? (
          <LoaderCircle className="spin" aria-hidden="true" size={17} />
        ) : (
          <ArrowRight aria-hidden="true" size={17} />
        )}
        {isSubmitting ? dictionary.login.signingIn : dictionary.login.continue}
      </button>
    </form>
  );
}
