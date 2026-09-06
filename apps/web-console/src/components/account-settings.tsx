"use client";

import { KeyRound, Pencil } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import type { Locale } from "@/i18n/config";
import type { Dictionary } from "@/i18n/dictionaries";
import type { AccountIdentity, IdentityAction } from "@/lib/account-security";
import { IdentityActionDialog } from "./identity-action-dialog";

export function AccountSettings({
  account,
  csrfToken,
  locale,
  copy,
}: {
  account: AccountIdentity;
  csrfToken: string;
  locale: Locale;
  copy: Dictionary["account"];
}) {
  const router = useRouter();
  const [dialog, setDialog] = useState<IdentityAction | null>(null);
  const [notice, setNotice] = useState("");
  return (
    <>
      {notice ? (
        <p role="status" className="preview-notice preview-notice--live">
          {notice}
        </p>
      ) : null}
      <section
        className="inventory-panel account-panel"
        aria-label={copy.title}
      >
        <div className="panel__header">
          <div>
            <span>{copy.username}</span>
            <h2>{account.username}</h2>
          </div>
        </div>
        <div className="account-panel__body">
          <p>{account.display_name}</p>
          {account.authentication_source !== "local" ? (
            <p>{copy.externalIdentityManaged}</p>
          ) : null}
          <div className="agent-admin-toolbar__actions">
            <button
              type="button"
              className="outline-button"
              disabled={!account.can_rename}
              onClick={() => {
                setNotice("");
                setDialog("rename");
              }}
            >
              <Pencil size={16} aria-hidden="true" />
              {copy.rename}
            </button>
            <button
              type="button"
              className="outline-button"
              disabled={!account.can_change_password}
              onClick={() => {
                setNotice("");
                setDialog("password");
              }}
            >
              <KeyRound size={16} aria-hidden="true" />
              {copy.changePassword}
            </button>
          </div>
        </div>
      </section>
      {dialog ? (
        <IdentityActionDialog
          action={dialog}
          username={account.username}
          endpoint={`/api/v1/auth/account/${dialog === "rename" ? "rename" : "password"}/`}
          csrfToken={csrfToken}
          copy={copy}
          onClose={() => setDialog(null)}
          onCompleted={() => {
            if (dialog === "password") {
              window.location.assign(
                `/${locale}/login?notice=password-changed`,
              );
              return;
            }
            setDialog(null);
            setNotice(copy.renamed);
            router.refresh();
          }}
        />
      ) : null}
    </>
  );
}
