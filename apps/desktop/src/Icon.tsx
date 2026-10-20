// The app's line icons (the MorphGate Brand design system's Icons): a 24px grid, 2px stroke,
// round caps and joins, no fills, stroked in the text's color.

export type IconName =
  | "security"
  | "lock"
  | "key"
  | "files"
  | "edit"
  | "vpn"
  | "update"
  | "teams"
  | "sync"
  | "identity"
  | "group"
  | "chevron"
  | "host"
  | "snippet"
  | "tunnel"
  | "logs"
  | "open";

const PATHS: Record<IconName, React.ReactNode> = {
  security: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="M11 12l8-8M16 7l2 2M14 9l2 2" strokeLinecap="round" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="M11 12l8-8M16 7l2 2" strokeLinecap="round" />
    </>
  ),
  files: <path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" strokeLinejoin="round" />,
  edit: <path d="M4 20h4L19 9l-4-4L4 16v4z" strokeLinejoin="round" />,
  vpn: <path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6z" strokeLinejoin="round" />,
  update: <path d="M12 4v11M7 10l5 5 5-5M5 20h14" strokeLinecap="round" strokeLinejoin="round" />,
  teams: (
    <>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.6a3.5 3.5 0 0 1 0 6.8M18 14.5a6.5 6.5 0 0 1 3.5 5.5" strokeLinecap="round" />
    </>
  ),
  sync: <path d="M7 18h10a4 4 0 0 0 .5-7.97A6 6 0 0 0 6.1 9.2 4.5 4.5 0 0 0 7 18z" strokeLinejoin="round" />,
  identity: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21a8 8 0 0 1 16 0" strokeLinecap="round" />
    </>
  ),
  group: (
    <path
      d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM12 10v6M9 13h6"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  ),
  chevron: <path d="M9 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" />,
  host: (
    <>
      <rect x="4" y="4" width="16" height="7" rx="2" />
      <rect x="4" y="13" width="16" height="7" rx="2" />
      <path d="M8 7.5h.01M8 16.5h.01" strokeLinecap="round" />
    </>
  ),
  snippet: <path d="M5 8l4 4-4 4M12 16h7" strokeLinecap="round" strokeLinejoin="round" />,
  tunnel: <path d="M4 8h15l-3-3M20 16H5l3 3" strokeLinecap="round" strokeLinejoin="round" />,
  open: <path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" strokeLinecap="round" strokeLinejoin="round" />,
  logs: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="M7 10l3 2-3 2M12 14h4" strokeLinecap="round" strokeLinejoin="round" />
    </>
  ),
};

/** `title` makes it meaningful on its own; without it, it's decoration (give its button a label). */
export function Icon({ name, size = 16, title }: { name: IconName; size?: number; title?: string }) {
  return (
    <svg
      className="icon-svg"
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      role={title ? "img" : undefined}
      aria-label={title}
      aria-hidden={title ? undefined : true}
    >
      {PATHS[name]}
    </svg>
  );
}
