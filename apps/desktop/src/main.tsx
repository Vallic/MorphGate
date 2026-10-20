import { createRoot } from "react-dom/client";
import "@xterm/xterm/css/xterm.css";
import "./tokens.css";
import "./styles.css";
import { App } from "./App";
import { focusOnlyByTouch } from "./touchFocus";

focusOnlyByTouch();

// No StrictMode: its double-mounted effects would open every SSH session twice.
createRoot(document.getElementById("root")!).render(<App />);
