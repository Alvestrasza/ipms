"use client";

import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

import { useLocale } from "@/i18n/locale-provider";

type Theme = "dark" | "light";

export function ThemeToggle() {
  const { dictionary } = useLocale();
  const [theme, setTheme] = useState<Theme>("dark");

  useEffect(() => {
    const storedTheme = window.localStorage.getItem("ipms-theme");
    const initialTheme: Theme = storedTheme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = initialTheme;
    setTheme(initialTheme);
  }, []);

  function toggleTheme() {
    const nextTheme: Theme = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = nextTheme;
    window.localStorage.setItem("ipms-theme", nextTheme);
    setTheme(nextTheme);
  }

  const nextThemeLabel =
    theme === "dark"
      ? dictionary.shell.switchToLight
      : dictionary.shell.switchToDark;

  return (
    <button
      className="icon-button"
      type="button"
      onClick={toggleTheme}
      aria-label={nextThemeLabel}
    >
      {theme === "dark" ? (
        <Sun aria-hidden="true" size={18} />
      ) : (
        <Moon aria-hidden="true" size={18} />
      )}
    </button>
  );
}
