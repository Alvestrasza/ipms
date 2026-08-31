"use client";

import { TriangleAlert } from "lucide-react";

import type { Dictionary } from "@/i18n/dictionaries";
import type { ConnectorEndpoint } from "@/lib/server-physical";

type Props = {
  connector: ConnectorEndpoint;
  locale: "de" | "en";
  copy: Dictionary["physical"];
};

const errorMessageKeys = {
  authentication_failed: "authenticationFailed",
  certificate_pin_mismatch: "certificatePinMismatch",
  connection_failed: "connectionFailed",
  connection_timeout: "connectionTimeout",
  redfish_request_failed: "redfishRequestFailed",
  session_creation_failed: "sessionCreationFailed",
  unsupported_service: "unsupportedService",
} as const;

export function ConnectorOperations({ connector, locale, copy }: Props) {
  const detail = connector.last_error_detail;
  const errorKey =
    errorMessageKeys[
      connector.last_error_code as keyof typeof errorMessageKeys
    ];
  const explanation = errorKey ? copy[errorKey] : copy.unknownConnectorError;

  return (
    <div className="connector-operations">
      {connector.last_error_code ? (
        <details className="connector-log" open>
          <summary>
            <TriangleAlert aria-hidden="true" size={16} />
            {copy.errorLog}
          </summary>
          <p>{explanation}</p>
          <dl>
            <div>
              <dt>{copy.errorCode}</dt>
              <dd>
                <code>{connector.last_error_code}</code>
              </dd>
            </div>
            {typeof detail.http_status === "number" ? (
              <div>
                <dt>{copy.httpStatus}</dt>
                <dd>{detail.http_status}</dd>
              </div>
            ) : null}
            {detail.method && detail.path ? (
              <div>
                <dt>{copy.request}</dt>
                <dd>
                  <code>
                    {detail.method} {detail.path}
                  </code>
                </dd>
              </div>
            ) : null}
            {detail.redfish_error_code ? (
              <div>
                <dt>{copy.redfishErrorCode}</dt>
                <dd>
                  <code>{detail.redfish_error_code}</code>
                </dd>
              </div>
            ) : null}
            {detail.redfish_message_id ? (
              <div>
                <dt>{copy.redfishMessageId}</dt>
                <dd>
                  <code>{detail.redfish_message_id}</code>
                </dd>
              </div>
            ) : null}
            {detail.token_state ? (
              <div>
                <dt>{copy.sessionToken}</dt>
                <dd>{detail.token_state}</dd>
              </div>
            ) : null}
            {detail.location_state ? (
              <div>
                <dt>{copy.sessionLocation}</dt>
                <dd>{detail.location_state}</dd>
              </div>
            ) : null}
            {connector.last_attempt_at ? (
              <div>
                <dt>{copy.lastAttempt}</dt>
                <dd>
                  {new Intl.DateTimeFormat(locale, {
                    dateStyle: "medium",
                    timeStyle: "medium",
                  }).format(new Date(connector.last_attempt_at))}
                </dd>
              </div>
            ) : null}
          </dl>
          <p className="connector-log__privacy">{copy.errorLogPrivacy}</p>
        </details>
      ) : null}
    </div>
  );
}
