"use client";

import { Activity, Cpu, HardDrive, MemoryStick } from "lucide-react";
import { useEffect, useState } from "react";

import { documentLocale } from "@/i18n/config";
import type { WindowsServerTelemetry as Telemetry } from "@/lib/windows-server-types";

type Copy = {
  heading: string;
  hint: string;
  refresh: string;
  unavailable: string;
  cpu: string;
  memory: string;
  used: string;
  available: string;
  volumes: string;
  volume: string;
  capacity: string;
  free: string;
  observed: string;
};

function formatBytes(bytes: number) {
  if (bytes >= 1024 ** 4) return `${(bytes / 1024 ** 4).toFixed(1)} TiB`;
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
}

function formatDate(value: string, locale: "de" | "en") {
  return new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

export function WindowsServerTelemetry({
  serverId,
  tenantId,
  locale,
  initialTelemetry,
  copy,
}: {
  serverId: string;
  tenantId: string;
  locale: "de" | "en";
  initialTelemetry: Telemetry | null;
  copy: Copy;
}) {
  const [telemetry, setTelemetry] = useState(initialTelemetry);
  const [available, setAvailable] = useState(true);

  useEffect(() => {
    let active = true;
    let request: AbortController | null = null;
    const poll = async () => {
      if (document.visibilityState !== "visible") return;
      request?.abort();
      request = new AbortController();
      try {
        const response = await fetch(
          `/api/v1/windows-servers/${encodeURIComponent(serverId)}/telemetry/`,
          {
            cache: "no-store",
            credentials: "same-origin",
            headers: { "X-IPMS-Tenant-ID": tenantId },
            signal: request.signal,
          },
        );
        if (!active) return;
        if (response.ok) {
          setTelemetry((await response.json()) as Telemetry);
          setAvailable(true);
        } else {
          setAvailable(false);
        }
      } catch (error) {
        if (
          active &&
          !(error instanceof DOMException && error.name === "AbortError")
        ) {
          setAvailable(false);
        }
      }
    };
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") void poll();
    };
    void poll();
    const interval = window.setInterval(poll, 10_000);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      active = false;
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      request?.abort();
    };
  }, [serverId, tenantId]);

  return (
    <section
      className="panel live-telemetry"
      aria-labelledby="telemetry-heading"
    >
      <div className="bmc-identity__title">
        <span className="connector-mark">
          <Activity aria-hidden="true" size={18} />
        </span>
        <div>
          <strong id="telemetry-heading">{copy.heading}</strong>
          <small>{copy.hint}</small>
        </div>
        <span className="live-telemetry__refresh">{copy.refresh}</span>
      </div>

      {!telemetry ? (
        <p className="live-telemetry__unavailable">{copy.unavailable}</p>
      ) : (
        <>
          <div className="live-telemetry__metrics">
            <article>
              <Cpu aria-hidden="true" size={20} />
              <span>{copy.cpu}</span>
              <strong>{telemetry.cpu_used_percent}%</strong>
              <progress
                aria-label={copy.cpu}
                max={100}
                value={telemetry.cpu_used_percent}
              >
                {telemetry.cpu_used_percent}%
              </progress>
            </article>
            <article>
              <MemoryStick aria-hidden="true" size={20} />
              <span>{copy.memory}</span>
              <strong>{telemetry.memory_used_percent}%</strong>
              <progress
                aria-label={copy.memory}
                max={100}
                value={telemetry.memory_used_percent}
              >
                {telemetry.memory_used_percent}%
              </progress>
              <small>
                {copy.used}: {formatBytes(telemetry.memory_used_bytes)} ·{" "}
                {copy.available}:{" "}
                {formatBytes(telemetry.memory_available_bytes)}
              </small>
            </article>
          </div>

          <div className="live-telemetry__volumes">
            <h3>
              <HardDrive aria-hidden="true" size={18} />
              {copy.volumes}
            </h3>
            {telemetry.fixed_volumes.map((volume) => (
              <article key={volume.name}>
                <div>
                  <strong>{volume.name}</strong>
                  <span>
                    {volume.label || volume.filesystem || copy.volume}
                  </span>
                </div>
                <div>
                  <span>
                    {volume.used_percent}% {copy.used}
                  </span>
                  <progress
                    aria-label={`${copy.volume} ${volume.name}`}
                    max={100}
                    value={volume.used_percent}
                  >
                    {volume.used_percent}%
                  </progress>
                </div>
                <small>
                  {copy.capacity}: {formatBytes(volume.total_bytes)} ·{" "}
                  {copy.free}: {formatBytes(volume.free_bytes)}
                </small>
              </article>
            ))}
          </div>
          <p className="live-telemetry__timestamp" aria-live="polite">
            {available ? copy.observed : copy.unavailable}:{" "}
            {formatDate(telemetry.observed_at, locale)}
          </p>
        </>
      )}
    </section>
  );
}
