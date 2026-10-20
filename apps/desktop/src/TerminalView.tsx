import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { connect, createWriter, disconnect, resize, type ConnectTarget, type CursorStyle } from "./api";
import { DEFAULT_FONT, xtermTheme, type ThemeColors } from "./themes";

export type TabStatus = "connecting" | "connected" | "failed" | "closed";

/** Lets other parts of the UI type into a connected terminal. */
/** Keys from the phone's extra-key row. */
export type ExtraKey = "esc" | "tab" | "up" | "down" | "left" | "right" | "|" | "~" | "/";

export interface TermControl {
  /** Inserts text as a paste (bracketed when the remote shell supports it). */
  paste: (text: string) => void;
  /** Pastes the text, then presses Enter. */
  run: (text: string) => void;
  /** Types a key from the extra-key row (arrows follow the application cursor mode). */
  key: (k: ExtraKey) => void;
  /** Applies Ctrl to the next key typed; `used` is called when it does. */
  ctrl: (on: boolean, used: () => void) => void;
  /** Sends input as if typed here (what another pane broadcasts). */
  send: (data: string) => void;
}

const ARROWS: Partial<Record<ExtraKey, string>> = { up: "A", down: "B", right: "C", left: "D" };

/** Seconds before each automatic reconnect after a connection is lost. */
const RETRIES = [2, 5, 15, 30];

/** How a session ended: the remote side exited, the connection was lost, or it never opened. */
type Ended = "exited" | "lost" | "failed";

/** The control character for `c` (Ctrl+C → \x03), or null when Ctrl doesn't apply to it. */
function control(c: string): string | null {
  if (c === " ") return "\x00";
  if (c === "?") return "\x7f";
  const code = c.toUpperCase().charCodeAt(0);
  return code >= 64 && code <= 95 ? String.fromCharCode(code - 64) : null;
}

/** How a terminal looks: its theme, and this device's font and cursor. */
export interface TerminalLook {
  theme: ThemeColors;
  fontFamily: string;
  fontSize: number;
  cursorStyle: CursorStyle;
  cursorBlink: boolean;
  /** Bold text in the bright colors. */
  boldBright: boolean;
  /** Colors too close to their background are adjusted to this ratio (1 = off). */
  minimumContrast: number;
}

const options = (look: TerminalLook) => ({
  theme: xtermTheme(look.theme),
  fontFamily: look.fontFamily || DEFAULT_FONT,
  fontSize: look.fontSize,
  cursorStyle: look.cursorStyle,
  cursorBlink: look.cursorBlink,
  drawBoldTextInBrightColors: look.boldBright,
  minimumContrastRatio: look.minimumContrast,
});

interface Props {
  target: ConnectTarget;
  title: string;
  /** Shown (alone, or as one of a tab's split panes). */
  active: boolean;
  /** Takes the keyboard when shown (default: when active). */
  focused?: boolean;
  /** The terminal took the keyboard (a click into a split pane). */
  onFocus?: () => void;
  /** What was typed here, as sent to the session (to broadcast to other panes). */
  onInput?: (data: string) => void;
  /** Changes apply to the open session. */
  look: TerminalLook;
  onStatus: (status: TabStatus) => void;
  register: (control: TermControl | null) => void;
  /** The session is being recorded into this session log. */
  onRecording?: (logId: string) => void;
}

export function TerminalView({ target, title, active, focused, onFocus, onInput, look, onStatus, register, onRecording }: Props) {
  const el = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const onStatusRef = useRef(onStatus);
  onStatusRef.current = onStatus;
  const registerRef = useRef(register);
  registerRef.current = register;
  const onRecordingRef = useRef(onRecording);
  onRecordingRef.current = onRecording;
  const onFocusRef = useRef(onFocus);
  onFocusRef.current = onFocus;
  const onInputRef = useRef(onInput);
  onInputRef.current = onInput;
  const lookRef = useRef(look);
  lookRef.current = look;
  const [ended, setEnded] = useState<Ended | null>(null);
  const [retryIn, setRetryIn] = useState<number | null>(null);
  const reconnectRef = useRef<() => void>(() => {});

  useEffect(() => {
    const term = new Terminal({
      ...options(lookRef.current),
      lineHeight: 1.15,
      scrollback: 10_000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el.current!);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    let id: number | null = null;
    let disposed = false;
    let write: ((d: string) => void) | null = null;
    // Set while the phone's Ctrl key is latched: called once it applies.
    let ctrlUsed: (() => void) | null = null;
    // The last thing sent was the Esc key alone. A shell's line editor (readline) then waits for
    // the key it modifies, and would take a snippet's first bytes for it: Ctrl+G first cancels
    // that (Esc Ctrl+G is readline's abort), and is harmless elsewhere (vim, less: file info).
    let afterEsc = false;
    const clearEsc = () => {
      if (afterEsc) write?.("\x07");
      afterEsc = false;
    };
    const unlatch = () => {
      const used = ctrlUsed;
      ctrlUsed = null;
      used?.();
    };

    // Reconnecting: a lost connection retries on its own (after RETRIES, once the network is
    // back); any ended session can be reopened by hand. Each attempt is a new session in the same
    // terminal (and, for hosts that keep their session, the same tmux session).
    let opened = false;
    let attempt = 0;
    let timer: number | null = null;
    const online = () => start();
    const retry = () => {
      if (disposed || attempt >= RETRIES.length) return setRetryIn(null);
      const wait = RETRIES[attempt++];
      setRetryIn(wait);
      timer = window.setTimeout(() => {
        timer = null;
        if (navigator.onLine) start();
        else window.addEventListener("online", online, { once: true });
      }, wait * 1000);
    };
    const start = () => {
      if (disposed) return;
      if (timer !== null) window.clearTimeout(timer);
      timer = null;
      window.removeEventListener("online", online);
      setEnded(null);
      setRetryIn(null);
      onStatusRef.current("connecting");
      term.write(opened ? `\r\n\x1b[90mReconnecting to ${title}…\x1b[0m\r\n` : `\x1b[90mConnecting to ${title}…\x1b[0m\r\n`);
      let exited = false;
      connect(
        target,
        { cols: term.cols, rows: term.rows },
        (bytes) => term.write(bytes),
        (event) => {
          if (event.kind === "recording") {
            onRecordingRef.current?.(event.logId);
          } else if (event.kind === "exit") {
            exited = true;
            term.write(`\r\n\x1b[90m[process exited with status ${event.status}]\x1b[0m`);
          } else {
            term.write(`\r\n\x1b[90m[${exited ? "connection closed" : "connection lost"}]\x1b[0m\r\n`);
            id = null;
            write = null;
            registerRef.current(null);
            onStatusRef.current("closed");
            setEnded(exited ? "exited" : "lost");
            if (!exited) retry();
          }
        },
      )
        .then(onOpened)
        .catch((err) => {
          term.write(`\x1b[31m${String(err)}\x1b[0m\r\n`);
          onStatusRef.current("failed");
          setEnded("failed");
          // Only a session that worked before tries again by itself.
          if (opened) retry();
        });
    };
    reconnectRef.current = () => {
      attempt = 0;
      start();
    };

    const onOpened = (sessionId: number) => {
      if (disposed) {
        void disconnect(sessionId);
        return;
      }
      opened = true;
      attempt = 0;
      id = sessionId;
      write = createWriter(sessionId);
      registerRef.current({
        paste: (text) => {
          clearEsc();
          term.paste(text);
        },
        run: (text) => {
          clearEsc();
          term.paste(text.replace(/\n+$/, ""));
          term.input("\r");
        },
        key: (k) => {
          afterEsc = false;
          const arrow = ARROWS[k];
          if (arrow && ctrlUsed) {
            write?.(`\x1b[1;5${arrow}`);
            unlatch();
          } else if (arrow) {
            write?.((term.modes.applicationCursorKeysMode ? "\x1bO" : "\x1b[") + arrow);
          } else if (k === "esc") {
            write?.("\x1b");
            afterEsc = true;
          } else if (k === "tab") write?.("\t");
          else term.input(k);
          // No focus here: on a phone that opens the keyboard. The key's button doesn't take the
          // focus, so the keyboard stays as it was.
        },
        ctrl: (on, used) => {
          ctrlUsed = on ? used : null;
          // The next key is usually a letter: the keyboard comes up for it.
          term.focus();
        },
        send: (data) => write?.(data),
      });
      onStatusRef.current("connected");
      term.focus();
    };
    start();

    const input = term.onData((d) => {
      afterEsc = false;
      const c = ctrlUsed && d.length === 1 ? control(d) : null;
      if (c !== null) unlatch();
      write?.(c ?? d);
      onInputRef.current?.(c ?? d);
    });
    const focused = () => onFocusRef.current?.();
    term.textarea?.addEventListener("focus", focused);
    const resized = term.onResize((size) => {
      if (id !== null) void resize(id, size).catch(() => {});
    });
    const observer = new ResizeObserver(() => {
      if (el.current?.offsetParent) fit.fit();
    });
    observer.observe(el.current!);

    return () => {
      disposed = true;
      if (timer !== null) window.clearTimeout(timer);
      window.removeEventListener("online", online);
      registerRef.current(null);
      observer.disconnect();
      input.dispose();
      term.textarea?.removeEventListener("focus", focused);
      resized.dispose();
      if (id !== null) void disconnect(id).catch(() => {});
      term.dispose();
    };
    // The session is bound to the target it was opened with; it never reconnects on prop changes.
  }, []);

  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    const next = options(look);
    term.options.theme = next.theme;
    term.options.fontFamily = next.fontFamily;
    term.options.fontSize = next.fontSize;
    term.options.cursorStyle = next.cursorStyle;
    term.options.cursorBlink = next.cursorBlink;
    term.options.drawBoldTextInBrightColors = next.drawBoldTextInBrightColors;
    term.options.minimumContrastRatio = next.minimumContrastRatio;
    // A new font size changes how many rows and columns fit.
    if (el.current?.offsetParent) fitRef.current?.fit();
  }, [look]);

  const takesKeys = active && (focused ?? true);
  useEffect(() => {
    if (!active) return;
    requestAnimationFrame(() => {
      fitRef.current?.fit();
      if (takesKeys) termRef.current?.focus();
    });
  }, [active, takesKeys]);

  return (
    <>
      <div className="terminal" ref={el} hidden={!active} style={{ background: look.theme.background }} />
      {active && ended && (
        <div className="reconnect-bar" role="status">
          <span>
            {ended === "exited"
              ? "The session ended."
              : ended === "failed"
                ? "Couldn't connect."
                : retryIn !== null
                  ? `Connection lost. Retrying in ${retryIn} s…`
                  : "Connection lost."}
          </span>
          <button type="button" className="secondary small-button" onClick={() => reconnectRef.current()}>
            {retryIn !== null ? "Retry now" : "Reconnect"}
          </button>
        </div>
      )}
    </>
  );
}
