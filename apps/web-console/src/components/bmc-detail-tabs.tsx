"use client";

import {
  Activity,
  BatteryCharging,
  Cpu,
  Fan,
  HardDrive,
  MemoryStick,
  Network,
  PlugZap,
  Power,
  Thermometer,
} from "lucide-react";
import { type KeyboardEvent, type ReactNode, useState } from "react";
import { documentLocale, type Locale } from "@/i18n/config";
import type { Dictionary } from "@/i18n/dictionaries";
import type {
  BmcDetailSnapshot,
  DetailInventoryItem,
  DetailStatus,
} from "@/lib/server-physical";

type Copy = Dictionary["bmcDetail"];
type TabKey =
  | "fans"
  | "temperatures"
  | "power"
  | "processors"
  | "memory"
  | "network"
  | "device_inventory"
  | "storage"
  | "firmware"
  | "software";

type TableColumn = { key: string; label: string };
type TableRow = Record<string, ReactNode>;

const subsystemDefinitions = [
  ["agentless_management_service", Activity],
  ["smart_storage_battery_status", BatteryCharging],
  ["bios_hardware_health", Cpu],
  ["fan_redundancy", Fan],
  ["fans", Fan],
  ["memory", MemoryStick],
  ["network", Network],
  ["power_status", Power],
  ["power_supplies", PlugZap],
  ["processors", Cpu],
  ["storage", HardDrive],
  ["temperatures", Thermometer],
] as const;

function value(value: unknown, suffix = ""): ReactNode {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return `${String(value)}${suffix}`;
}

function statusBadge(status: DetailStatus, copy: Copy) {
  return (
    <span className={`detail-status detail-status--${status}`}>
      {copy[status]}
    </span>
  );
}

function capacity(value: unknown, locale: Locale): ReactNode {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toLocaleString(documentLocale(locale), { maximumFractionDigits: 1 })} ${units[unit]}`;
}

function deviceTypeLabel(deviceType: unknown, copy: Copy): ReactNode {
  const labels: Record<string, string> = {
    drive: copy.drive,
    ethernet_interface: copy.ethernetInterface,
    fibre_channel_adapter: copy.fibreChannelAdapter,
    logical_drive: copy.logicalDrive,
    pcie_device: copy.pcieDevice,
    pcie_function: copy.pcieFunction,
    physical_drive: copy.physicalDrive,
    storage_controller: copy.storageController,
    storage_device: copy.storageDevice,
    storage_enclosure: copy.storageEnclosure,
  };
  return labels[String(deviceType)] ?? value(deviceType);
}

function DetailTable({
  columns,
  rows,
  empty,
}: {
  columns: TableColumn[];
  rows: TableRow[];
  empty: string;
}) {
  if (!rows.length) return <div className="detail-empty">{empty}</div>;
  return (
    <div className="table-scroll detail-table-scroll">
      <table className="detail-table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>{column.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={columns
                .map((column) => String(row[column.key] ?? ""))
                .join("|")}
            >
              {columns.map((column) => (
                <td key={column.key}>{row[column.key] ?? "—"}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function inventoryRows(items: DetailInventoryItem[], copy: Copy): TableRow[] {
  return items.map((item) => ({
    name: value(item.name),
    model: value(item.model),
    manufacturer: value(item.manufacturer),
    serial_number: value(item.serial_number),
    firmware_version: value(item.firmware_version),
    status: statusBadge(item.status, copy),
    state: value(item.state),
  }));
}

export function BmcDetailTabs({
  snapshot,
  copy,
  locale,
}: {
  snapshot: BmcDetailSnapshot;
  copy: Copy;
  locale: Locale;
}) {
  const [activeTab, setActiveTab] = useState<TabKey>("fans");
  const tabs: Array<{ key: TabKey; label: string }> = [
    { key: "fans", label: copy.fans },
    { key: "temperatures", label: copy.temperatures },
    { key: "power", label: copy.power },
    { key: "processors", label: copy.processors },
    { key: "memory", label: copy.memory },
    { key: "network", label: copy.network },
    { key: "device_inventory", label: copy.deviceInventory },
    { key: "storage", label: copy.storage },
    { key: "firmware", label: copy.firmware },
    { key: "software", label: copy.software },
  ];
  const subsystemByKey = new Map(
    (snapshot.subsystems ?? []).map((subsystem) => [subsystem.key, subsystem]),
  );
  const subsystemLabels: Record<string, string> = {
    agentless_management_service: copy.agentless_management_service,
    smart_storage_battery_status: copy.smart_storage_battery_status,
    bios_hardware_health: copy.bios_hardware_health,
    fan_redundancy: copy.fan_redundancy,
    fans: copy.fansSubsystem,
    memory: copy.memorySubsystem,
    network: copy.networkSubsystem,
    power_status: copy.power_status,
    power_supplies: copy.power_supplies,
    processors: copy.processorsSubsystem,
    storage: copy.storageSubsystem,
    temperatures: copy.temperaturesSubsystem,
  };

  function handleTabKeyDown(
    event: KeyboardEvent<HTMLButtonElement>,
    currentIndex: number,
  ) {
    let nextIndex: number | undefined;
    if (event.key === "ArrowRight")
      nextIndex = (currentIndex + 1) % tabs.length;
    if (event.key === "ArrowLeft") {
      nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    }
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = tabs.length - 1;
    if (nextIndex === undefined) return;

    event.preventDefault();
    setActiveTab(tabs[nextIndex].key);
    const tabButtons =
      event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>(
        '[role="tab"]',
      );
    tabButtons?.[nextIndex]?.focus();
  }

  function tabContent() {
    if (activeTab === "fans") {
      return (
        <DetailTable
          empty={copy.noData}
          columns={[
            { key: "name", label: copy.name },
            { key: "status", label: copy.status },
            { key: "reading", label: copy.reading },
            { key: "minimum", label: copy.minimum },
            { key: "maximum", label: copy.maximum },
            { key: "state", label: copy.state },
            { key: "context", label: copy.context },
          ]}
          rows={(snapshot.fans ?? []).map((fan) => ({
            name: value(fan.name),
            status: statusBadge(fan.status, copy),
            reading: value(fan.reading, fan.units ? ` ${fan.units}` : ""),
            minimum: value(
              fan.minimum_reading,
              fan.units ? ` ${fan.units}` : "",
            ),
            maximum: value(
              fan.maximum_reading,
              fan.units ? ` ${fan.units}` : "",
            ),
            state: value(fan.state),
            context: value(fan.context),
          }))}
        />
      );
    }
    if (activeTab === "temperatures") {
      return (
        <DetailTable
          empty={copy.noData}
          columns={[
            { key: "name", label: copy.name },
            { key: "status", label: copy.status },
            { key: "current", label: copy.currentTemperature },
            { key: "caution", label: copy.cautionThreshold },
            { key: "critical", label: copy.criticalThreshold },
            { key: "context", label: copy.context },
          ]}
          rows={(snapshot.temperatures ?? []).map((sensor) => ({
            name: value(sensor.name),
            status: statusBadge(sensor.status, copy),
            current: value(sensor.reading_celsius, " °C"),
            caution: value(sensor.upper_caution_celsius, " °C"),
            critical: value(sensor.upper_critical_celsius, " °C"),
            context: value(sensor.context),
          }))}
        />
      );
    }
    if (activeTab === "power") {
      const power = snapshot.power ?? {};
      return (
        <div className="power-detail">
          <div className="detail-metrics">
            <article>
              <span>{copy.consumedPower}</span>
              <strong>{value(power.consumed_watts, " W")}</strong>
            </article>
            <article>
              <span>{copy.capacity}</span>
              <strong>{value(power.capacity_watts, " W")}</strong>
            </article>
            <article>
              <span>{copy.requestedPower}</span>
              <strong>{value(power.requested_watts, " W")}</strong>
            </article>
            <article>
              <span>{copy.averagePower}</span>
              <strong>{value(power.average_consumed_watts, " W")}</strong>
            </article>
            <article>
              <span>{copy.minimumPower}</span>
              <strong>{value(power.minimum_consumed_watts, " W")}</strong>
            </article>
            <article>
              <span>{copy.maximumPower}</span>
              <strong>{value(power.maximum_consumed_watts, " W")}</strong>
            </article>
            <article>
              <span>{copy.measurementInterval}</span>
              <strong>{value(power.metrics_interval_minutes, " min")}</strong>
            </article>
          </div>
          {(power.redundancy ?? []).map((item) => (
            <p
              className="detail-note"
              key={`${item.mode}-${item.minimum_needed}-${item.maximum_supported}`}
            >
              {copy.redundancy}: {value(item.mode)} · {copy.minimumNeeded}:{" "}
              {value(item.minimum_needed)} · {copy.maximumSupported}:{" "}
              {value(item.maximum_supported)}
            </p>
          ))}
          <DetailTable
            empty={copy.noData}
            columns={[
              { key: "name", label: copy.name },
              { key: "model", label: copy.model },
              { key: "status", label: copy.status },
              { key: "firmware_version", label: copy.firmwareVersion },
              { key: "bay", label: copy.bay },
              { key: "capacity", label: copy.capacity },
              { key: "output", label: copy.outputPower },
              { key: "input", label: copy.inputVoltage },
              { key: "type", label: copy.powerSupplyType },
              { key: "hotplug", label: copy.hotplug },
              { key: "mismatch", label: copy.mismatch },
            ]}
            rows={(power.supplies ?? []).map((supply) => ({
              name: value(supply.name),
              model: value(supply.model),
              status: statusBadge(supply.status, copy),
              firmware_version: value(supply.firmware_version),
              bay: value(supply.bay_number),
              capacity: value(supply.capacity_watts, " W"),
              output: `${[supply.last_output_watts, supply.average_output_watts, supply.maximum_output_watts].map((item) => item ?? "—").join(" / ")} W`,
              input: value(supply.line_input_voltage, " V"),
              type: value(
                supply.power_supply_type || supply.line_input_voltage_type,
              ),
              hotplug: value(supply.hotplug_capable),
              mismatch: value(supply.mismatched),
            }))}
          />
        </div>
      );
    }
    if (activeTab === "processors") {
      return (
        <DetailTable
          empty={copy.noData}
          columns={[
            { key: "name", label: copy.name },
            { key: "model", label: copy.model },
            { key: "socket", label: copy.socket },
            { key: "cores", label: copy.cores },
            { key: "threads", label: copy.threads },
            { key: "speed", label: copy.speed },
            { key: "status", label: copy.status },
          ]}
          rows={(snapshot.processors ?? []).map((processor) => ({
            name: value(processor.name),
            model: value(processor.model),
            socket: value(processor.socket),
            cores: value(processor.cores),
            threads: value(processor.threads),
            speed: value(processor.speed_mhz, " MHz"),
            status: statusBadge(processor.status, copy),
          }))}
        />
      );
    }
    if (activeTab === "memory") {
      return (
        <DetailTable
          empty={copy.noData}
          columns={[
            { key: "name", label: copy.name },
            { key: "location", label: copy.location },
            { key: "manufacturer", label: copy.manufacturer },
            { key: "model", label: copy.model },
            { key: "capacity", label: copy.capacity },
            { key: "memory_type", label: copy.memoryType },
            { key: "speed", label: copy.speed },
            { key: "state", label: copy.state },
            { key: "status", label: copy.status },
          ]}
          rows={(snapshot.memory ?? []).map((module) => ({
            name: value(module.name),
            location: value(module.location),
            manufacturer: value(module.manufacturer),
            model: value(module.model),
            capacity: value(
              typeof module.capacity_mib === "number"
                ? module.capacity_mib / 1024
                : null,
              " GiB",
            ),
            memory_type: value(module.memory_type),
            speed: value(module.speed_mhz, " MHz"),
            state: value(module.state),
            status: statusBadge(module.status, copy),
          }))}
        />
      );
    }
    if (activeTab === "network") {
      const networkRows = (snapshot.network ?? []).map((item) => ({
        name: value(item.name),
        device_type: deviceTypeLabel(
          item.device_type || "ethernet_interface",
          copy,
        ),
        location: value(item.location),
        mac: value(item.mac_address),
        wwpn: value(item.wwpn),
        wwnn: value(item.wwnn),
        speed: value(item.speed_mbps, " Mbps"),
        link: value(item.link_status),
        status: statusBadge(item.status, copy),
      }));
      const hasUnavailableIlo4Wwn = (snapshot.network ?? []).some(
        (item) => item.wwn_source === "unavailable_in_ilo4_redfish",
      );
      return (
        <div className="detail-stack">
          {hasUnavailableIlo4Wwn ? (
            <p className="detail-note">{copy.ilo4WwnUnavailable}</p>
          ) : null}
          <DetailTable
            empty={copy.noData}
            columns={[
              { key: "name", label: copy.name },
              { key: "device_type", label: copy.deviceType },
              { key: "location", label: copy.location },
              { key: "mac", label: copy.macAddress },
              { key: "wwpn", label: copy.wwpn },
              { key: "wwnn", label: copy.wwnn },
              { key: "speed", label: copy.speed },
              { key: "link", label: copy.linkStatus },
              { key: "status", label: copy.status },
            ]}
            rows={networkRows}
          />
        </div>
      );
    }
    if (activeTab === "storage") {
      const allStorage = [
        ...(snapshot.storage ?? []),
        ...(snapshot.device_inventory ?? []).filter((item) =>
          ["storage_enclosure", "physical_drive"].includes(
            String(item.device_type),
          ),
        ),
      ];
      const groups = [
        ["storage_controller", copy.storageControllers],
        ["storage_enclosure", copy.driveEnclosures],
        ["physical_drive", copy.physicalDisks],
        ["logical_drive", copy.logicalDisks],
      ] as const;
      return (
        <div className="detail-stack">
          {groups.map(([type, heading]) => {
            const items = allStorage.filter(
              (item) => item.device_type === type,
            );
            return (
              <section className="storage-group" key={type}>
                <h3>{heading}</h3>
                <DetailTable
                  empty={copy.noData}
                  columns={[
                    { key: "name", label: copy.name },
                    { key: "model", label: copy.model },
                    { key: "location", label: copy.location },
                    { key: "capacity", label: copy.capacity },
                    { key: "raid", label: copy.raid },
                    { key: "mode", label: copy.operatingMode },
                    { key: "interface", label: copy.interfaceType },
                    { key: "speed", label: copy.speed },
                    { key: "temperature", label: copy.temperature },
                    { key: "firmware", label: copy.firmwareVersion },
                    { key: "serial", label: copy.serialNumber },
                    { key: "status", label: copy.status },
                  ]}
                  rows={items.map((item) => ({
                    name: value(item.name),
                    model: value(item.model),
                    location: value(item.location),
                    capacity: capacity(item.capacity_bytes, locale),
                    raid: value(item.raid),
                    mode: value(item.operating_mode || item.logical_drive_type),
                    interface: value(item.interface_type),
                    speed: value(item.interface_speed_mbps, " Mbps"),
                    temperature: value(
                      item.current_temperature_celsius ||
                        item.temperature_celsius,
                      " °C",
                    ),
                    firmware: value(item.firmware_version),
                    serial: value(item.serial_number || item.wwid),
                    status: statusBadge(item.status, copy),
                  }))}
                />
              </section>
            );
          })}
        </div>
      );
    }
    if (activeTab === "device_inventory") {
      return (
        <DetailTable
          empty={copy.noData}
          columns={[
            { key: "name", label: copy.name },
            { key: "device_type", label: copy.deviceType },
            { key: "model", label: copy.model },
            { key: "capacity", label: copy.capacity },
            { key: "media_type", label: copy.mediaType },
            { key: "interface_type", label: copy.interfaceType },
            { key: "location", label: copy.location },
            { key: "serial_number", label: copy.serialNumber },
            { key: "status", label: copy.status },
          ]}
          rows={(snapshot.device_inventory ?? []).map((item) => ({
            name: value(item.name),
            device_type: deviceTypeLabel(item.device_type, copy),
            model: value(item.model),
            capacity: capacity(item.capacity_bytes, locale),
            media_type: value(item.media_type),
            interface_type: value(item.interface_type),
            location: value(item.location),
            serial_number: value(item.serial_number),
            status: statusBadge(item.status, copy),
          }))}
        />
      );
    }
    const inventories: Record<
      Exclude<
        TabKey,
        | "fans"
        | "temperatures"
        | "power"
        | "processors"
        | "memory"
        | "network"
        | "storage"
        | "device_inventory"
      >,
      DetailInventoryItem[]
    > = {
      firmware: snapshot.firmware ?? [],
      software: snapshot.software ?? [],
    };
    return (
      <DetailTable
        empty={copy.noData}
        columns={[
          { key: "name", label: copy.name },
          { key: "model", label: copy.model },
          { key: "manufacturer", label: copy.manufacturer },
          { key: "serial_number", label: copy.serialNumber },
          { key: "firmware_version", label: copy.firmwareVersion },
          { key: "status", label: copy.status },
        ]}
        rows={inventoryRows(inventories[activeTab], copy)}
      />
    );
  }

  return (
    <>
      <section
        className="subsystem-section"
        aria-labelledby="subsystem-heading"
      >
        <div className="panel__header">
          <div>
            <p className="eyebrow">Redfish</p>
            <h2 id="subsystem-heading">{copy.subsystems}</h2>
          </div>
        </div>
        <div className="subsystem-grid">
          {subsystemDefinitions.map(([key, Icon]) => {
            const subsystem = subsystemByKey.get(key) ?? {
              status: "unknown" as const,
              value: "unknown" as const,
            };
            return (
              <article
                className={`subsystem-card subsystem-card--${subsystem.status}`}
                key={key}
              >
                <span className="subsystem-card__icon">
                  <Icon aria-hidden="true" size={19} />
                </span>
                <span>
                  <strong>{subsystemLabels[key]}</strong>
                  <small>{copy[subsystem.value]}</small>
                </span>
              </article>
            );
          })}
        </div>
      </section>

      <section className="panel bmc-detail-panel">
        <div className="bmc-tabs" role="tablist" aria-label={copy.title}>
          {tabs.map((tab, index) => (
            <button
              className={
                activeTab === tab.key ? "bmc-tab bmc-tab--active" : "bmc-tab"
              }
              id={`bmc-tab-${tab.key}`}
              key={tab.key}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.key}
              aria-controls={`bmc-panel-${tab.key}`}
              tabIndex={activeTab === tab.key ? 0 : -1}
              onClick={() => setActiveTab(tab.key)}
              onKeyDown={(event) => handleTabKeyDown(event, index)}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <div
          className="bmc-tab-panel"
          id={`bmc-panel-${activeTab}`}
          role="tabpanel"
          aria-labelledby={`bmc-tab-${activeTab}`}
        >
          {tabContent()}
        </div>
      </section>
    </>
  );
}
