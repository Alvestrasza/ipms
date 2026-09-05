import {
  type NativeCertificate,
  NativeConsoleChannel,
  type NativeFailureCode,
} from "./native-console-channel";

type GuacStatus = { code: number; message: string };
export type GuacTunnel = {
  connect: (data?: string) => void;
  disconnect: () => void;
  sendMessage: (...elements: (string | number)[]) => void;
  oninstruction: ((opcode: string, parameters: string[]) => void) | null;
  onerror: ((status: GuacStatus) => void) | null;
  setState: (state: number) => void;
  setUUID: (uuid: string) => void;
};
type MouseState = {
  x: number;
  y: number;
  left: boolean;
  middle: boolean;
  right: boolean;
  up: boolean;
  down: boolean;
};
type Display = {
  getElement: () => HTMLDivElement;
  getWidth: () => number;
  getHeight: () => number;
  scale: (scale: number) => void;
  onresize: ((width: number, height: number) => void) | null;
};
export type GuacClient = {
  getDisplay: () => Display;
  connect: () => void;
  disconnect: () => void;
  sendKeyEvent: (pressed: boolean, keysym: number) => void;
  sendMouseState: (state: MouseState, applyDisplayScale?: boolean) => void;
  onerror: ((status: GuacStatus) => void) | null;
};
export type GuacamoleRuntime = {
  Tunnel: new () => GuacTunnel;
  Parser: new () => {
    receive: (data: string) => void;
    oninstruction: ((opcode: string, parameters: string[]) => void) | null;
  };
  Client: new (tunnel: GuacTunnel) => GuacClient;
  Keyboard: new (
    element: HTMLElement,
  ) => {
    onkeydown: ((keysym: number) => boolean) | null;
    onkeyup: ((keysym: number) => void) | null;
    reset: () => void;
  };
  Mouse: new (
    element: HTMLElement,
  ) => {
    currentState: MouseState;
    onEach: (
      types: string[],
      listener: (event: { state: MouseState }) => void,
    ) => void;
    offEach: (
      types: string[],
      listener: (event: { state: MouseState }) => void,
    ) => void;
    reset: () => void;
  };
};
declare global {
  interface Window {
    Guacamole?: GuacamoleRuntime;
  }
}

export function createNativeTunnel(
  runtime: GuacamoleRuntime,
  options: {
    url: string;
    width: number;
    height: number;
    onCertificate: (certificate: NativeCertificate) => void;
    onReady: () => void;
    onFailure: (code: NativeFailureCode) => void;
  },
) {
  const tunnel = new runtime.Tunnel();
  const parser = new runtime.Parser();
  let ping: ReturnType<typeof setInterval> | null = null;
  const stopPing = () => {
    if (ping) clearInterval(ping);
    ping = null;
  };
  const channel = new NativeConsoleChannel({
    ...options,
    onProtocol: (data) => parser.receive(data),
    onReady: () => {
      tunnel.setState(1);
      ping = setInterval(
        () => tunnel.sendMessage("", "ping", Date.now()),
        1000,
      );
      options.onReady();
    },
    onFailure: (code) => {
      stopPing();
      tunnel.setState(2);
      options.onFailure(code);
    },
  });
  parser.oninstruction = (opcode, parameters) => {
    if (opcode === "") {
      if (parameters.length === 1) tunnel.setUUID(parameters[0]);
      return;
    }
    tunnel.oninstruction?.(opcode, parameters);
  };
  tunnel.connect = () => {
    tunnel.setState(0);
    channel.connect();
  };
  tunnel.disconnect = () => {
    stopPing();
    channel.dispose();
    tunnel.setState(2);
  };
  tunnel.sendMessage = (...elements) => {
    const message = `${elements
      .map((value) => {
        const text = String(value);
        return `${Array.from(text).length}.${text}`;
      })
      .join(",")};`;
    channel.sendProtocol(message);
  };
  return { tunnel, channel };
}
