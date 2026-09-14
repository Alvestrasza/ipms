/**
 * File Name: wsus-endpoint-fields.tsx
 * Version: v0.1.0
 * Created: 2026-09-13
 * Last Modified: 2026-09-13
 * Author: Alice Endelgard
 * Organization: Alvestrasza Corporation
 * Description: Shared WSUS server address fields for source creation and editing.
 */
import type { WsusCopy } from "@/i18n/wsus-copy";
import type { WsusSource } from "@/lib/wsus-types";
import styles from "./wsus-console.module.css";

export function WsusEndpointFields({
  prefix,
  copy,
  disabled,
  source,
}: {
  prefix: string;
  copy: WsusCopy;
  disabled: boolean;
  source?: WsusSource;
}) {
  return (
    <div className={styles.endpointFields}>
      <label className={styles.field} htmlFor={`${prefix}-host`}>
        {copy.host}
        <input
          id={`${prefix}-host`}
          name="wsus_host"
          defaultValue={source?.wsus_host ?? ""}
          maxLength={253}
          required
          disabled={disabled}
          autoComplete="off"
          spellCheck={false}
          aria-describedby={`${prefix}-host-hint`}
        />
      </label>
      <label className={styles.field} htmlFor={`${prefix}-port`}>
        {copy.port}
        <input
          id={`${prefix}-port`}
          name="wsus_port"
          type="number"
          min={1}
          max={65535}
          step={1}
          defaultValue={source?.wsus_port ?? 8531}
          required
          disabled={disabled}
        />
      </label>
      <label className={styles.checkbox} htmlFor={`${prefix}-ssl`}>
        <input
          id={`${prefix}-ssl`}
          name="wsus_use_ssl"
          type="checkbox"
          defaultChecked={source?.wsus_use_ssl ?? true}
          disabled={disabled}
        />
        {copy.ssl}
      </label>
      <small className={styles.endpointHint} id={`${prefix}-host-hint`}>
        {copy.hostHint}
      </small>
    </div>
  );
}
