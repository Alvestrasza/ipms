import { LockKeyhole, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import Image from "next/image";

import { LoginForm } from "@/components/login-form";

export const metadata: Metadata = { title: "Sign in" };

export default function LoginPage() {
  return (
    <main className="login-page">
      <section
        className="login-brand-panel"
        aria-labelledby="login-brand-heading"
      >
        <div className="login-brand-panel__content">
          <Image
            src="/brand/alvestrasza-emblem.png"
            alt="Alvestrasza Corporation emblem"
            width={118}
            height={118}
            priority
          />
          <p className="eyebrow">Alvestrasza Corporation</p>
          <h1 id="login-brand-heading">
            Independent Platform Management System
          </h1>
          <p>
            One secure control plane for physical, virtual, network, storage,
            monitoring, and backup infrastructure.
          </p>
          <div className="login-trust">
            <ShieldCheck aria-hidden="true" size={18} /> Tenant isolated ·
            Audited · Read only foundation
          </div>
        </div>
      </section>
      <section className="login-form-panel" aria-labelledby="sign-in-heading">
        <div className="login-card">
          <div className="login-card__icon">
            <LockKeyhole aria-hidden="true" size={22} />
          </div>
          <p className="eyebrow">IPMS Console</p>
          <h2 id="sign-in-heading">Sign in</h2>
          <p>Use your IPMS account to enter the selected environment.</p>
          <LoginForm />
          <small>Credentials are handled only by the IPMS Control Plane.</small>
        </div>
      </section>
    </main>
  );
}
