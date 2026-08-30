import { LockKeyhole, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import Image from "next/image";
import { LanguageSwitcher } from "@/components/language-switcher";
import { LoginForm } from "@/components/login-form";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.login.title };
}

export default async function LocalizedLoginPage() {
  const dictionary = getDictionary(await resolveLocale());
  return (
    <main className="login-page">
      <section
        className="login-brand-panel"
        aria-labelledby="login-brand-heading"
      >
        <div className="login-brand-panel__content">
          <Image
            src="/brand/alvestrasza-emblem.png"
            alt={dictionary.brand.emblemAlt}
            width={118}
            height={118}
            priority
          />
          <p className="eyebrow">{dictionary.login.company}</p>
          <h1 id="login-brand-heading">{dictionary.login.product}</h1>
          <p>{dictionary.login.description}</p>
          <div className="login-trust">
            <ShieldCheck aria-hidden="true" size={18} />
            {dictionary.login.trust}
          </div>
        </div>
      </section>
      <section className="login-form-panel" aria-labelledby="sign-in-heading">
        <div className="login-card">
          <div className="login-card__language">
            <LanguageSwitcher />
          </div>
          <div className="login-card__icon">
            <LockKeyhole aria-hidden="true" size={22} />
          </div>
          <p className="eyebrow">{dictionary.login.console}</p>
          <h2 id="sign-in-heading">{dictionary.login.heading}</h2>
          <p>{dictionary.login.prompt}</p>
          <LoginForm />
          <small>{dictionary.login.credentialNote}</small>
        </div>
      </section>
    </main>
  );
}
