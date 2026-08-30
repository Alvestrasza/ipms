import {
  CircleAlert,
  CircleCheck,
  CircleHelp,
  LoaderCircle,
  XCircle,
} from "lucide-react";

type Status =
  | "healthy"
  | "warning"
  | "critical"
  | "unknown"
  | "succeeded"
  | "running"
  | "failed";

const labels: Record<Status, string> = {
  healthy: "Healthy",
  warning: "Warning",
  critical: "Critical",
  unknown: "Unknown",
  succeeded: "Succeeded",
  running: "Running",
  failed: "Failed",
};

const icons = {
  healthy: CircleCheck,
  warning: CircleAlert,
  critical: XCircle,
  unknown: CircleHelp,
  succeeded: CircleCheck,
  running: LoaderCircle,
  failed: XCircle,
};

export function StatusPill({ status }: { status: Status }) {
  const Icon = icons[status];
  return (
    <span className={`status-pill status-pill--${status}`}>
      <Icon aria-hidden="true" size={14} strokeWidth={2} />
      {labels[status]}
    </span>
  );
}
