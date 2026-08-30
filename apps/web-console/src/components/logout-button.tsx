"use client";

import { LogOut } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

export function LogoutButton({ csrfToken }: { csrfToken: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);

  async function logout() {
    setPending(true);
    try {
      await fetch("/api/v1/auth/logout/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: "{}",
      });
    } finally {
      router.replace("/login");
      router.refresh();
      setPending(false);
    }
  }

  return (
    <button
      className="icon-button"
      type="button"
      aria-label="Sign out"
      title="Sign out"
      disabled={pending}
      onClick={logout}
    >
      <LogOut aria-hidden="true" size={17} />
    </button>
  );
}
