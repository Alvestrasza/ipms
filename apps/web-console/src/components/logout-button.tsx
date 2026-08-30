"use client";

import { LogOut } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { useLocale } from "@/i18n/locale-provider";

export function LogoutButton({ csrfToken }: { csrfToken: string }) {
  const router = useRouter();
  const { dictionary } = useLocale();
  const [pending, setPending] = useState(false);

  async function logout() {
    setPending(true);
    try {
      const response = await fetch("/api/v1/auth/logout/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: "{}",
      });
      if (!response.ok) return;
      router.replace("/login");
      router.refresh();
    } finally {
      setPending(false);
    }
  }

  return (
    <button
      className="icon-button"
      type="button"
      aria-label={dictionary.shell.signOut}
      title={dictionary.shell.signOut}
      disabled={pending}
      onClick={logout}
    >
      <LogOut aria-hidden="true" size={17} />
    </button>
  );
}
