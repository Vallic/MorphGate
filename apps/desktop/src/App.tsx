import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  answerHostKey,
  errorText,
  links as linksApi,
  groups as groupsApi,
  hosts as hostsApi,
  identities as identitiesApi,
  hostCas as hostCasApi,
  keys as keysApi,
  snippets as snippetsApi,
  cloud as cloudApi,
  forwards as forwardsApi,
  device as deviceApi,
  sync as syncApi,
  vpns as vpnsApi,
  updates as updatesApi,
  teams as teamsApi,
  appearance as appearanceApi,
  vault,
  vaultEntries,
  type ChangedHostKey,
  type ConnectTarget,
  type HostInput,
  type HostKeyPrompt,
  type GroupView,
  type HostView,
  type IdentityView,
  type HostCaView,
  type ApprovalNeed,
  type SsoNeed,
  type KeyView,
  type UpdateInfo,
  type SnippetView,
  type ForwardView,
  type Moved,
  type SyncStatus,
  type VpnPrompt,
  type VpnView,
  type VaultStatus,
  type OrgInfo,
  type VaultInfo,
  type TerminalSettings,
  type VaultTheme,
  type SecurityKeyTouch,
  type Link,
  type ReceivedLink,
} from "./api";
import { AppearancePanel } from "./AppearancePanel";
import { APP_THEME_SCHEMES, BUILTIN_THEMES, PRODUCTION_THEME, findTheme } from "./themes";
import { ConnectForm, type ConnectPrefill } from "./ConnectForm";
import { ForwardEditor } from "./ForwardEditor";
import { HostEditor } from "./HostEditor";
import { GroupEditor, IdentityEditor } from "./Identities";
import { HostCaPanel } from "./HostCaPanel";
import { HostKeyChangedDialog, HostKeyDialog } from "./HostKeyDialog";
import { SnippetCheckDialog } from "./SnippetCheck";
import { RouteBar } from "./RouteBar";
import { addPane, dividers, holds, moveDivider, panes, rects, removePane, type Divider, type Rect, type Split } from "./splits";
import { SessionLogsPanel } from "./SessionLogs";
import { SsoSignIn } from "./SsoSignIn";
import { ApprovalWait } from "./ApprovalWait";
import { MobileWorkspace, type MorePanel } from "./mobile/MobileWorkspace";
import { mobileOs, onPhone, useNarrow } from "./mobile/useMobile";
import { VpnPromptDialog } from "./VpnPromptDialog";
import { KeyDetail, NewKey } from "./KeyPanel";
import { PasswordDialog } from "./PasswordDialog";
import { CloudPage } from "./CloudPage";
import { ImportHostsPage } from "./ImportHosts";
import { ImportSnippetsPage } from "./ImportSnippets";
import { GroupPage, GroupsPage, HostsPage, KeysPage, SnippetsPage, TunnelsPage, VpnsPage, type KeysTab } from "./Lists";
import { MoveContext } from "./Move";
import { Sidebar, type LiveState, type PageKind } from "./Sidebar";
import { SnippetPanel } from "./SnippetPanel";
import { SyncOffer, syncOfferTime, SyncPanel } from "./SyncPanel";
import { VpnPanel } from "./VpnPanel";
import { SecurityPanel } from "./SecurityPanel";
import { TeamsPanel } from "./TeamsPanel";
import { AboutPanel } from "./AboutPanel";
import { SftpView } from "./SftpView";
import { TerminalView, type TabStatus, type TermControl, type TerminalLook } from "./TerminalView";
import { noKeychainAutoUnlock, SetupScreen, UnlockScreen, type Erased } from "./VaultGate";

/** "You're no longer in Acme and Lab: …" */
function orgsGone(names: string[]): string {
  const list = names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}` : names[0];
  return `You're no longer in ${list}: you left on another device, an admin removed you, or the team was deleted. Its vaults left this device; your own vault is as it was.`;
}

export function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [fatal, setFatal] = useState("");
  // Device settings, readable while the vault is locked: the unlock screen takes the app theme too.
  const [termSettings, setTermSettings] = useState<TerminalSettings | null>(null);
  const loadTermSettings = useCallback(() => void appearanceApi.settings().then(setTermSettings, () => {}), []);
  useEffect(loadTermSettings, [loadTermSettings]);
  const appTheme = useAppTheme(termSettings?.appTheme ?? "dark");

  useEffect(() => {
    vault.status().then(setStatus, (e) => setFatal(errorText(e)));
  }, []);
  // Signed out by its sync account, or disconnected and cleared: back to the start, saying why.
  const [erased, setErased] = useState<Erased | null>(null);
  useEffect(() => {
    const off = listen<Erased>("device-erased", (e) => (setErased(e.payload), setStatus("uninitialized"), loadTermSettings()));
    return () => void off.then((f) => f());
  }, [loadTermSettings]);

  if (fatal) return <div className="gate"><p className="error">{fatal}</p></div>;
  if (status === null) return <div className="gate" />;
  if (status === "uninitialized") return <SetupScreen erased={erased} onDone={(fresh) => (setErased(null), fresh ? syncOfferTime.schedule() : syncOfferTime.forget(), setStatus("unlocked"))} />;
  if (status === "locked") return <UnlockScreen onUnlocked={() => setStatus("unlocked")} />;
  return (
    <Workspace
      onLock={() => void vault.lock().then(() => setStatus("locked"))}
      termSettings={termSettings}
      onSettingsChanged={loadTermSettings}
      appTheme={appTheme}
    />
  );
}

/** Where a new session goes: a pane beside (`row`) or below (`column`) the session `beside`. */
interface Place {
  beside: number;
  dir: "row" | "column";
}

/** A pane's place in the workspace, in percent. */
const paneStyle = (r: Rect | undefined) => (r ? { left: `${r.left}%`, top: `${r.top}%`, width: `${r.width}%`, height: `${r.height}%` } : undefined);

interface Tab {
  key: number;
  kind: "terminal" | "sftp";
  title: string;
  target: ConnectTarget;
  status: TabStatus;
  /** When it was opened (ms). */
  opened: number;
  /** The session log it is recorded into. */
  recording?: string;
}

type View =
  | { kind: "tab"; key: number }
  | { kind: "quick" }
  /** Quick connect on a phone (where "quick" is the host list). */
  | { kind: "connect" }
  | { kind: "host"; id?: string }
  | { kind: "identity"; id?: string }
  | { kind: "hostCa"; id?: string }
  | { kind: "group"; id?: string }
  | { kind: "key"; id?: string }
  | { kind: "snippet"; id?: string }
  | { kind: "forward"; id?: string }
  /** `totp`: straight to turning on two-step verification (teams wait for it). */
  | { kind: "sync"; totp?: boolean }
  | { kind: "security" }
  | { kind: "about" }
  | { kind: "teams" }
  | { kind: "appearance" }
  | { kind: "vpn"; id?: string }
  /** Recorded sessions, of one host or all. */
  | { kind: "logs"; hostId?: string }
  /** The pages listing one kind of item. */
  | { kind: "hosts" }
  /** Hosts from OpenSSH's configuration. */
  | { kind: "importHosts" }
  | { kind: "importSnippets" }
  | { kind: "cloud"; add?: "feed" }
  | { kind: "groups" }
  /** One group and everything in it. */
  | { kind: "groupPage"; id: string }
  /** `tab`: Keys (the default), Identities or Host CAs. */
  | { kind: "keys"; tab?: KeysTab }
  | { kind: "snippets" }
  | { kind: "forwards" }
  | { kind: "vpns" };

/** Views that fill the workspace: with no session open, the tab bar makes room for them too. */
const PAGES = new Set<View["kind"]>(["hosts", "importHosts", "importSnippets", "cloud", "groups", "groupPage", "keys", "snippets", "forwards", "vpns", "logs", "teams", "sync"]);

/** Pages opened from another page (Import from Snippets, a group from Groups): closing one
 * returns to that page, where a page opened from the sidebar replaces the one shown. */
const SUBPAGES = new Set<View["kind"]>(["importHosts", "importSnippets", "cloud", "groupPage", "logs"]);

/** Editors: opening one from another keeps the first one's way back. */
const EDITORS = new Set<View["kind"]>(["host", "identity", "group", "key", "snippet", "forward", "vpn", "hostCa"]);

let nextKey = 1;

/** Locks after `minutes` without keyboard or mouse use in the app (0 = never). */
function useIdleLock(minutes: number, lock: () => void) {
  const lockRef = useRef(lock);
  lockRef.current = lock;
  useEffect(() => {
    if (minutes <= 0) return;
    let last = Date.now();
    const seen = () => (last = Date.now());
    const events = ["keydown", "mousedown", "mousemove", "wheel", "touchstart"] as const;
    events.forEach((e) => window.addEventListener(e, seen, { passive: true, capture: true }));
    const timer = setInterval(() => {
      if (Date.now() - last >= minutes * 60_000) lockRef.current();
    }, 10_000);
    return () => {
      clearInterval(timer);
      events.forEach((e) => window.removeEventListener(e, seen, { capture: true }));
    };
  }, [minutes]);
}

/** Tells sync whether someone is using the app: the window shown, and input in the last 5 minutes.
 * Nobody: it syncs every 5 minutes instead of every minute, and at once on coming back. */
function useSyncPresence() {
  useEffect(() => {
    let last = Date.now();
    let reported: boolean | null = null;
    const report = () => {
      const present = document.visibilityState === "visible" && Date.now() - last < 5 * 60_000;
      if (present !== reported) {
        reported = present;
        void syncApi.presence(present).catch(() => {});
      }
    };
    const seen = () => {
      last = Date.now();
      if (reported === false) report();
    };
    const events = ["keydown", "mousedown", "mousemove", "wheel", "touchstart", "focus"] as const;
    events.forEach((e) => window.addEventListener(e, seen, { passive: true, capture: true }));
    document.addEventListener("visibilitychange", report);
    const timer = setInterval(report, 30_000);
    report();
    return () => {
      clearInterval(timer);
      events.forEach((e) => window.removeEventListener(e, seen, { capture: true }));
      document.removeEventListener("visibilitychange", report);
    };
  }, []);
}

interface WorkspaceProps {
  onLock: () => void;
  termSettings: TerminalSettings | null;
  onSettingsChanged: () => void;
  /** The app theme in effect. */
  appTheme: "dark" | "light";
}

function Workspace({ onLock, termSettings, onSettingsChanged: loadTermSettings, appTheme }: WorkspaceProps) {
  const [hostList, setHosts] = useState<HostView[]>([]);
  const [identityList, setIdentities] = useState<IdentityView[]>([]);
  const [hostCaList, setHostCas] = useState<HostCaView[]>([]);
  const [groupList, setGroups] = useState<GroupView[]>([]);
  const [keyList, setKeys] = useState<KeyView[]>([]);
  const [snippetList, setSnippets] = useState<SnippetView[]>([]);
  const [forwardList, setForwards] = useState<ForwardView[]>([]);
  const [vpnList, setVpns] = useState<VpnView[]>([]);
  const [vaultList, setVaultList] = useState<VaultInfo[]>([]);
  const [orgList, setOrgs] = useState<OrgInfo[]>([]);
  const [themeList, setThemes] = useState<VaultTheme[]>([]);
  // Teams without a usable plan (plans enforced): their vaults are view only. Asked again when the
  // window comes back (a plan bought in the browser) and when sync's problem changes (a push
  // refused because the plan ended, or that settled).
  const [lockedOrgs, setLockedOrgs] = useState<Set<string>>(new Set());
  const vaults = useMemo(() => vaultEntries(vaultList, orgList, lockedOrgs), [vaultList, orgList, lockedOrgs]);
  const [pending, setPending] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState("");

  // morphgate:// links: they wait (in the app) while the vault is locked, and open a screen,
  // filled in; nothing happens without a click there.
  const sameServer = (a: string, b: string) => {
    try {
      return new URL(a).origin === new URL(b).origin;
    } catch {
      return false;
    }
  };
  const openLink = useRef<(r: ReceivedLink) => void>(() => {});
  openLink.current = ({ link, error }: ReceivedLink) => {
    const n = (linked?.n ?? 0) + 1;
    if (!link) return setNotice(error ?? "MorphGate can't open this link.");
    switch (link.kind) {
      case "sync":
        return open({ kind: "sync" });
      case "teams":
        setLinked({ n, org: link.orgId ?? undefined });
        return open({ kind: "teams" });
      case "invite":
        if (!syncStatus?.enabled || syncStatus.signedOut) {
          setWaitingInvite(link);
          setNotice(
            `This is an invite to a team${link.server ? ` on ${new URL(link.server).host}` : ""}. Turn on sync with the invited address: Teams opens with the invite once it's on.`,
          );
          return open({ kind: "sync" });
        }
        if (link.server && syncStatus.server && !sameServer(link.server, syncStatus.server)) {
          return setNotice(`This invite is for a team on ${new URL(link.server).host}, but this device syncs with ${syncStatus.server}.`);
        }
        setLinked({ n, invite: link.token });
        return open({ kind: "teams" });
      case "connect":
        setLinked({ n, connect: link });
        return open({ kind: mobile ? "connect" : "quick" });
    }
  };
  const [syncStatus, setSyncStatus] = useState<SyncStatus | null>(null);
  // Links are taken once sync's state is known: an invite needs it.
  const statusKnown = syncStatus !== null;
  useEffect(() => {
    if (!statusKnown) return;
    const take = () => void linksApi.take().then((all) => all.forEach((r) => openLink.current(r)), () => {});
    take();
    const unlisten = listen("links-pending", take);
    return () => void unlisten.then((f) => f());
  }, [statusKnown]);
  // An invite that came while sync was off: Teams opens with it once sync is on.
  const [waitingInvite, setWaitingInvite] = useState<Link | null>(null);
  useEffect(() => {
    if (!waitingInvite || !syncStatus?.enabled || syncStatus.signedOut) return;
    setWaitingInvite(null);
    setNotice("");
    openLink.current({ link: waitingInvite, error: null });
  }, [waitingInvite, syncStatus?.enabled, syncStatus?.signedOut]);

  useEffect(() => {
    if (orgList.length === 0) return setLockedOrgs(new Set());
    const ask = () => void teamsApi.locked().then((ids) => setLockedOrgs(new Set(ids)), () => {});
    ask();
    window.addEventListener("focus", ask);
    return () => window.removeEventListener("focus", ask);
  }, [orgList, syncStatus?.lastError]);
  const controls = useRef(new Map<number, TermControl>());
  // Tabs split into panes (a session each); a tab in none is a single pane.
  const [splits, setSplits] = useState<Split[]>([]);
  const [lastTerminal, setLastTerminal] = useState<number | null>(null);
  const [loadError, setLoadError] = useState("");
  const [tabs, setTabs] = useState<Tab[]>([]);
  // The phone layout follows the window only while no session is open: switching layouts
  // would reopen every session.
  const narrow = useNarrow();
  const [mobile, setMobile] = useState(onPhone || narrow);
  // What the last morphgate:// link filled in (`n` remounts the screen it opened).
  const [linked, setLinked] = useState<{ n: number; connect?: ConnectPrefill; invite?: string; org?: string } | null>(null);
  useEffect(() => {
    if (tabs.length === 0) setMobile(onPhone || narrow);
  }, [narrow, tabs.length]);
  const [view, setView] = useState<View>({ kind: "quick" });
  // Home, where the workspace opens and where closing the last page or tab lands: the hosts once
  // there are any (on a phone, "quick" is the host list already), else quick connect.
  const home = (): View => (!mobile && hostList.length > 0 ? { kind: "hosts" } : { kind: "quick" });
  // The way back: closing a view returns to the page, editor or session it was opened from.
  const [trail, setTrail] = useState<View[]>([]);
  const open = (v: View) => {
    if (v.kind === "tab" || v.kind === "quick") setTrail([]);
    else {
      // An editor replaces an editor, a page a page: what was under the first stays the way back.
      // A page's own pages (its import, a group) keep it as the way back.
      const editor = (k: View["kind"]) => EDITORS.has(k);
      const from = view.kind === "tab" || view.kind === "quick" ? null : editor(view.kind);
      if (view.kind !== "quick" && (from !== editor(v.kind) || SUBPAGES.has(v.kind))) setTrail((t) => [...t, view].slice(-8));
    }
    setView(v);
  };
  const close = () => {
    const rest = [...trail];
    // Closing home itself goes to quick connect.
    let next: View = view.kind === "hosts" ? { kind: "quick" } : home();
    while (rest.length) {
      const v = rest.pop()!;
      if (v.kind !== "tab" || tabs.some((t) => t.key === v.key)) {
        next = v;
        break;
      }
    }
    setTrail(rest);
    setView(next);
  };
  // Once you leave the screen a link filled in, it's forgotten (Teams won't look the invite up
  // again, quick connect shows what you last used).
  useEffect(() => {
    if (linked && !["teams", "quick", "connect"].includes(view.kind)) setLinked(null);
  }, [view.kind]);
  // A week after a vault was created without sync, sync is offered (once).
  const [offering, setOffering] = useState(syncOfferTime.due);
  // Sync turned on another way (Sync in the sidebar, an invite): no offer any more.
  useEffect(() => {
    if (syncStatus?.enabled) syncOfferTime.forget();
  }, [syncStatus?.enabled]);
  const [prompts, setPrompts] = useState<HostKeyPrompt[]>([]);
  // A security key waiting for a touch to sign in.
  const [touch, setTouch] = useState<SecurityKeyTouch | null>(null);
  const [changedKeys, setChangedKeys] = useState<ChangedHostKey[]>([]);
  // A feed's snippet that changed since this device last sent it, waiting for a yes.
  const [checking, setChecking] = useState<{ snippet: SnippetView; run: boolean; go: () => void } | null>(null);
  const [vpnPrompts, setVpnPrompts] = useState<VpnPrompt[]>([]);
  const [autoLock, setAutoLock] = useState(0);
  useIdleLock(autoLock, onLock);
  useSyncPresence();
  const [autoUpdate, setAutoUpdate] = useState(false);
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  useUpdateChecks(autoUpdate, setUpdate);
  useEffect(noKeychainAutoUnlock, []);
  const [askPassword, setAskPassword] = useState<{ host: HostView; then: (password: string) => void } | null>(null);
  const [ssoFor, setSsoFor] = useState<SsoNeed | null>(null);
  const [approvalFor, setApprovalFor] = useState<ApprovalNeed | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [h, k, sn, f, v, vl, o, id, gr] = await Promise.all([
        hostsApi.list(),
        keysApi.list(),
        snippetsApi.list(),
        forwardsApi.list(),
        vpnsApi.list(),
        teamsApi.vaults(),
        teamsApi.orgs(),
        identitiesApi.list(),
        groupsApi.list(),
      ]);
      // Themes come with the rest: a sync can bring a host's theme.
      void appearanceApi.themes().then(setThemes, () => {});
      void hostCasApi.list().then(setHostCas, () => {});
      setHosts(h);
      setIdentities(id);
      setGroups(gr);
      setKeys(k);
      setSnippets(sn);
      setForwards(f);
      setVpns(v);
      setVaultList(vl);
      setOrgs(o);
      setLoadError("");
    } catch (e) {
      setLoadError(errorText(e));
    }
  }, []);

  // Feeds refresh themselves on desktops: once the first sync since unlocking has brought what
  // other devices refreshed (at once without sync; after 20 s at the latest), then every 15
  // minutes. The backend skips a feed refreshed on any device in the last 10.
  const feedsRan = useRef(false);
  const feedsSyncAt = useRef<number | null | undefined>(undefined);
  const refreshFeeds = useCallback(() => {
    feedsRan.current = true;
    // What it changed shows at once (the lists otherwise follow only a sync).
    void cloudApi.autoRefresh().then((n) => n > 0 && void refresh(), () => {});
  }, [refresh]);
  useEffect(() => {
    if (mobileOs) return;
    const first = window.setTimeout(() => feedsRan.current || refreshFeeds(), 20_000);
    const every = window.setInterval(refreshFeeds, 15 * 60_000);
    return () => (window.clearTimeout(first), window.clearInterval(every));
  }, [refreshFeeds]);
  useEffect(() => {
    if (mobileOs || feedsRan.current || !syncStatus) return;
    const syncing = syncStatus.enabled && !syncStatus.signedOut;
    if (feedsSyncAt.current === undefined) {
      feedsSyncAt.current = syncStatus.lastSyncAt;
      if (syncing) return;
    }
    if (!syncing || (!syncStatus.syncing && syncStatus.lastSyncAt !== feedsSyncAt.current)) refreshFeeds();
  }, [syncStatus, refreshFeeds]);

  // After a move, the editor in front shows the item where it went (a copy has a new id).
  const moves = useMemo(
    () => ({
      vaults,
      onMoved: (m: Moved) =>
        void refresh().then(() =>
          setView((v) => ("id" in v && v.id && m.ids[v.id] && m.ids[v.id] !== v.id ? ({ ...v, id: m.ids[v.id] } as View) : v)),
        ),
    }),
    [vaults, refresh],
  );

  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    void refresh().then(() => setLoaded(true));
  }, [refresh]);
  // Opened (unlocked) with hosts: home is the hosts, unless a link filled in quick connect meanwhile.
  // The view as it is now: a page opened in the moment before this runs stays open.
  useEffect(() => {
    if (loaded && !linked?.connect) setView((v) => (v.kind === "quick" ? home() : v));
  }, [loaded]);

  useEffect(() => {
    if (view.kind === "tab" && tabs.find((t) => t.key === view.key)?.kind === "terminal") setLastTerminal(view.key);
    // A split's tab reopens on the pane last used in it.
    if (view.kind === "tab") setSplits((all) => all.map((x) => (holds(x.layout, view.key) && x.focus !== view.key ? { ...x, focus: view.key } : x)));
  }, [view]);

  // VPN "connected" markers follow sessions and tunnels opening and closing.
  const usage = tabs.map((t) => t.status).join() + forwardList.map((f) => f.running).join();
  useEffect(() => {
    if (vpnList.length) void vpnsApi.list().then(setVpns, () => {});
  }, [usage]);

  // Live counters while tunnels run; also notices tunnels whose connection dropped.
  const anyRunning = forwardList.some((f) => f.running);
  useEffect(() => {
    if (!anyRunning) return;
    const timer = setInterval(() => void forwardsApi.list().then(setForwards, () => {}), 3000);
    return () => clearInterval(timer);
  }, [anyRunning]);

  useEffect(() => {
    const unlisten = [
      listen<HostKeyPrompt>("hostkey-prompt", (e) => setPrompts((p) => [...p, e.payload])),
      listen<ChangedHostKey>("hostkey-changed", (e) =>
        // One dialog per host, however many connections it refused.
        setChangedKeys((c) => (c.some((x) => x.host === e.payload.host && x.port === e.payload.port) ? c : [...c, e.payload])),
      ),
      listen<VpnPrompt>("vpn-prompt", (e) => setVpnPrompts((p) => [...p, e.payload])),
      // The connect stopped waiting (a web sign-in finished, or the connect failed).
      listen<number>("vpn-prompt-closed", (e) => setVpnPrompts((p) => p.filter((x) => x.promptId !== e.payload))),
      listen<SyncStatus>("sync-status", (e) => setSyncStatus(e.payload)),
      listen<SecurityKeyTouch>("security-key", (e) => setTouch(e.payload.key ? e.payload : null)),
      listen("vault-changed", () => void refresh()),
      // No longer in an organization (left on another device, removed, or it was deleted): its vaults left.
      listen<string[]>("orgs-gone", (e) => setNotice(orgsGone(e.payload))),
      // The sync account was deleted on another device or the website: sync is off here now.
      listen<string>("account-deleted", (e) =>
        setNotice(
          `The sync account ${e.payload} was deleted (on another device or the website). Its team vaults left this device; your own vault stays here, no longer syncing.`,
        ),
      ),
    ];
    void syncApi.status().then(setSyncStatus, () => {});
    void deviceApi.status().then(
      (d) => (setAutoLock(d.autoLockMinutes), setAutoUpdate(d.autoUpdateCheck)),
      () => {},
    );
    return () => unlisten.forEach((u) => void u.then((f) => f()));
  }, [refresh]);

  /** `place`: a new pane beside (`row`) or below (`column`) the session `beside`, in its tab. */
  const openTab = (target: ConnectTarget, title: string, kind: Tab["kind"] = "terminal", place?: Place) => {
    const key = nextKey++;
    setTabs((t) => [...t, { key, kind, title, target, status: "connecting", opened: Date.now() }]);
    if (place) {
      setSplits((all) =>
        all.some((x) => holds(x.layout, place.beside))
          ? all.map((x) => (holds(x.layout, place.beside) ? { ...x, layout: addPane(x.layout, place.beside, key, place.dir) } : x))
          : [...all, { layout: addPane({ pane: place.beside }, place.beside, key, place.dir), broadcast: false, focus: key }],
      );
    }
    open({ kind: "tab", key });
  };

  const needsPassword = (h: HostView | undefined) => h?.auth.kind === "password" && !h.auth.saved;

  const connectHost = (h: HostView, password?: string, kind: Tab["kind"] = "terminal", place?: Place) => {
    if (needsPassword(h) && password === undefined) {
      setAskPassword({ host: h, then: (pw) => connectHost(h, pw, kind, place) });
      return;
    }
    // Hosts that keep their session: each terminal tab gets its own tmux session there.
    let tmux: string | undefined;
    if (h.keepSession && kind === "terminal") {
      const taken = new Set(
        tabs.flatMap((t) => (t.target.kind === "saved" && t.target.hostId === h.id && t.target.tmux ? [t.target.tmux] : [])),
      );
      for (let n = 1; !tmux; n++) {
        const name = n === 1 ? "morphgate" : `morphgate-${n}`;
        if (!taken.has(name)) tmux = name;
      }
    }
    openTab({ kind: "saved", hostId: h.id, password, tmux }, h.label, kind, place);
  };
  // A host's session: its latest tab (or a new one, if it closed meanwhile).
  const showSession = (h: HostView) => {
    const t = [...tabs].reverse().find((x) => x.target.kind === "saved" && x.target.hostId === h.id);
    if (t) open({ kind: "tab", key: t.key });
    else connectHost(h);
  };

  const busy = (id: string, on: boolean) =>
    setPending((p) => {
      const next = new Set(p);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });

  const startForward = (f: ForwardView, password?: string) => {
    const host = hostList.find((h) => h.id === f.hostId);
    if (needsPassword(host) && password === undefined && host) {
      setAskPassword({ host, then: (pw) => startForward(f, pw) });
      return;
    }
    busy(f.id, true);
    forwardsApi
      .start(f.id, password)
      .then(
        (started) => setForwards((all) => all.map((x) => (x.id === started.id ? started : x))),
        (e) => setNotice(`Tunnel “${f.label}”: ${errorText(e)}`),
      )
      .finally(() => busy(f.id, false));
  };

  const toggleForward = (f: ForwardView) => {
    if (!f.running) return startForward(f);
    busy(f.id, true);
    void forwardsApi
      .stop(f.id)
      .then(refresh, (e) => setNotice(errorText(e)))
      .finally(() => busy(f.id, false));
  };

  const splitOf = (key: number) => splits.find((x) => holds(x.layout, key));

  /** Closes these sessions; what's left of their split stays together. */
  const closeTabs = (keys: number[]) => {
    const rest = tabs.filter((x) => !keys.includes(x.key));
    setTabs(rest);
    setSplits((all) =>
      all.flatMap((x) => {
        let layout: Split["layout"] | null = x.layout;
        for (const k of keys) layout = layout && removePane(layout, k);
        if (!layout || "pane" in layout) return [];
        const left = panes(layout);
        return [{ ...x, layout, focus: left.includes(x.focus) ? x.focus : left[0] }];
      }),
    );
    if (lastTerminal !== null && keys.includes(lastTerminal)) setLastTerminal(null);
    if (view.kind === "tab" && keys.includes(view.key)) {
      // The next pane of the same split, else the last tab.
      const sibling = splitOf(view.key) && panes(splitOf(view.key)!.layout).find((k) => !keys.includes(k));
      const next = sibling ?? rest.at(-1)?.key;
      setView(next !== undefined ? { kind: "tab", key: next } : home());
    }
  };
  const closeTab = (key: number) => closeTabs([key]);

  const setStatus = useCallback((key: number, status: TabStatus) => {
    setTabs((t) => t.map((x) => (x.key === key ? { ...x, status } : x)));
  }, []);

  const answerVpn = (prompt: VpnPrompt, answers: string[] | null) => {
    void vpnsApi.answer(prompt.promptId, answers);
    setVpnPrompts((p) => p.filter((x) => x.promptId !== prompt.promptId));
  };

  const answer = (prompt: HostKeyPrompt, accept: boolean) => {
    void answerHostKey(prompt.promptId, accept);
    setPrompts((p) => p.filter((x) => x.promptId !== prompt.promptId));
  };

  const saveQuickHost = async (input: HostInput) => {
    await hostsApi.save(input);
    await refresh();
  };

  const activeTab = view.kind === "tab" ? view.key : null;
  const selected = "id" in view ? (view.id ?? null) : null;
  const sendTarget = tabs.find((t) => t.key === lastTerminal && t.kind === "terminal" && t.status === "connected") ?? null;

  const deviceScheme = !termSettings || termSettings.followAppTheme ? APP_THEME_SCHEMES[appTheme] : termSettings.theme;

  // Each tab's look: the host's own scheme, else this device's (or the app theme's).
  const looks = useMemo(() => {
    const out = new Map<number, { look: TerminalLook; prod: boolean }>();
    if (!termSettings) return out;
    for (const t of tabs) {
      const host = t.target.kind === "saved" ? hostList.find((h) => h.id === (t.target as { hostId: string }).hostId) : undefined;
      const id = host?.themeId ?? deviceScheme;
      const builtin = BUILTIN_THEMES.find((b) => b.id === id);
      out.set(t.key, {
        look: lookFor(termSettings, findTheme(id, themeList), builtin?.minimumContrast),
        prod: id === PRODUCTION_THEME,
      });
    }
    return out;
  }, [tabs, hostList, themeList, termSettings, appTheme]);

  // Session logs play in this device's scheme.
  const deviceLook = termSettings
    ? lookFor(termSettings, findTheme(deviceScheme, themeList), BUILTIN_THEMES.find((b) => b.id === deviceScheme)?.minimumContrast)
    : DEFAULT_LOOK;
  const recording = (key: number) => (logId: string) =>
    setTabs((all) => all.map((x) => (x.key === key ? { ...x, recording: logId } : x)));

  const sendTo = (key: number, body: string, run: boolean, show = true) => {
    const control = controls.current.get(key);
    if (!control) return;
    if (run) control.run(body);
    else control.paste(body);
    if (show) open({ kind: "tab", key });
  };

  // Broadcast: what's typed in one pane of a broadcasting split goes to its other connected panes.
  const splitsRef = useRef(splits);
  splitsRef.current = splits;
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const broadcastFrom = useCallback((key: number, data: string) => {
    const split = splitsRef.current.find((x) => x.broadcast && holds(x.layout, key));
    if (!split) return;
    for (const k of panes(split.layout)) {
      if (k !== key && tabsRef.current.find((t) => t.key === k)?.status === "connected") controls.current.get(k)?.send(data);
    }
  }, []);
  const focusPane = (key: number) => {
    if (view.kind !== "tab" || view.key !== key) open({ kind: "tab", key });
  };

  /** What this device sent of a feed's snippet: a later change of it asks first. */
  const markSent = (id: string) =>
    void snippetsApi.sent(id).then(
      () => setSnippets((all) => all.map((x) => (x.id === id ? { ...x, changed: false } : x))),
      () => {},
    );
  /** Sends a snippet (`go`), asking first where its feed changed it since this device last did. */
  const guardSnippet = (snippet: SnippetView | undefined, run: boolean, go: () => void) => {
    if (snippet?.source && snippet.changed) return setChecking({ snippet, run, go });
    go();
    if (snippet?.source) markSent(snippet.id);
  };
  const sendSnippet = (body: string, run: boolean, snippet?: SnippetView) =>
    sendTarget && guardSnippet(snippet, run, () => sendTo(sendTarget.key, body, run));

  const hostOf = (t: Tab) => (t.target.kind === "saved" ? hostList.find((h) => h.id === (t.target as { hostId: string }).hostId) : undefined);
  const current = tabs.find((t) => t.key === activeTab);
  const currentHost = current && hostOf(current);
  // The split the shown session is in: its panes are all shown, each in its place.
  const currentSplit = activeTab !== null ? splitOf(activeTab) : undefined;
  const paneRects = currentSplit ? rects(currentSplit.layout) : null;
  const shown = (key: number) => (currentSplit ? holds(currentSplit.layout, key) : activeTab === key);

  /** Opens `hostId` (`null`: the current session's host again) in a new pane beside or below it. */
  const splitWith = (dir: Place["dir"], hostId: string | null) => {
    if (!current || current.kind !== "terminal") return;
    const place = { beside: current.key, dir };
    const host = hostId ? hostList.find((h) => h.id === hostId) : currentHost;
    if (host) {
      const typed = current.target.kind === "saved" && current.target.hostId === host.id ? current.target.password : undefined;
      connectHost(host, typed, "terminal", place);
    } else if (!hostId) openTab(current.target, current.title, "terminal", place);
  };

  // Dragging the border between two panes.
  const contentRef = useRef<HTMLDivElement>(null);
  const drag = (d: Divider, lead: number) => (e: React.PointerEvent) => {
    e.preventDefault();
    const box = contentRef.current!.getBoundingClientRect();
    const handle = e.currentTarget as HTMLElement;
    try {
      handle.setPointerCapture(e.pointerId);
    } catch {
      // A pointer the browser doesn't track (a synthesized one): the moves still come here.
    }
    const move = (ev: PointerEvent) => {
      const at = d.dir === "row" ? ((ev.clientX - box.left) / box.width) * 100 : ((ev.clientY - box.top) / box.height) * 100;
      setSplits((all) => all.map((x) => (holds(x.layout, lead) ? { ...x, layout: moveDivider(x.layout, d, at) } : x)));
    };
    const up = () => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", up);
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
  };

  // Hosts with an open session, for the sidebar's status squares.
  const live = useMemo(() => {
    const out = new Map<string, LiveState>();
    for (const t of tabs) {
      if (t.target.kind !== "saved" || (t.status !== "connected" && t.status !== "connecting")) continue;
      if (out.get(t.target.hostId) !== "connected") out.set(t.target.hostId, t.status);
    }
    return out;
  }, [tabs]);

  const banner = (loadError || notice) && (
    <div className="banner error" role="alert">
      <span>{loadError || notice}</span>
      {notice && (
        <button className="icon small" onClick={() => setNotice("")} aria-label="Dismiss">
          ×
        </button>
      )}
    </div>
  );

  const panels = (
    <>
      {(view.kind === "connect" || (view.kind === "quick" && !mobile)) && (
        <ConnectForm
          key={linked?.connect ? linked.n : 0}
          prefill={linked?.connect}
          onConnect={(target, title) => (setLinked(null), openTab(target, title))}
          onSaveHost={saveQuickHost}
        />
      )}
      {view.kind === "host" && (
        <HostEditor
          key={view.id ?? "new"}
          host={hostList.find((h) => h.id === view.id)}
          hosts={hostList}
          groups={groupList}
          identities={identityList}
          keys={keyList}
          vpns={vpnList}
          vaults={vaults}
          themes={themeList}
          deviceTheme={deviceScheme}
          onLogs={(id) => open({ kind: "logs", hostId: id })}
          onSaved={(h, connect) =>
            void refresh().then(() => (connect ? connectHost(h) : setView({ kind: "host", id: h.id })))
          }
          onDeleted={() => (void refresh(), close())}
          onCancel={close}
          onNewKey={() => open({ kind: "key" })}
        />
      )}
      {view.kind === "identity" && (
        <IdentityEditor
          key={view.id ?? "new"}
          identity={identityList.find((i) => i.id === view.id)}
          hosts={hostList}
          groups={groupList}
          keys={keyList}
          vaults={vaults}
          onSaved={(i) => void refresh().then(() => setView({ kind: "identity", id: i.id }))}
          onDeleted={() => (void refresh(), close())}
          onCancel={close}
          onNewKey={() => open({ kind: "key" })}
        />
      )}
      {view.kind === "hostCa" && (
        <HostCaPanel
          key={view.id ?? "new"}
          ca={hostCaList.find((c) => c.id === view.id)}
          vaults={vaults}
          // Saved: back to where it was opened from, with the list showing it.
          onSaved={() => void refresh().then(close)}
          onDeleted={() => (void refresh(), close())}
          onCancel={close}
        />
      )}
      {view.kind === "group" && (
        <GroupEditor
          key={view.id ?? "new"}
          group={groupList.find((g) => g.id === view.id)}
          hosts={hostList}
          identities={identityList}
          vpns={vpnList}
          themes={themeList}
          vaults={vaults}
          onSaved={(g) => void refresh().then(() => setView({ kind: "group", id: g.id }))}
          onDeleted={() => (void refresh(), close())}
          onCancel={close}
        />
      )}
      {view.kind === "key" &&
        (view.id && keyList.some((k) => k.id === view.id) ? (
          <KeyDetail
            key={view.id}
            k={keyList.find((k) => k.id === view.id)!}
            vaults={vaults}
            onChanged={() => void refresh()}
            onDeleted={() => (void refresh(), close())}
            onClose={close}
          />
        ) : (
          <NewKey vaults={vaults} onCreated={(k) => void refresh().then(() => setView({ kind: "key", id: k.id }))} onCancel={close} />
        ))}
      {view.kind === "vpn" && (
        <VpnPanel
          key={view.id ?? "new"}
          vpn={vpnList.find((v) => v.id === view.id)}
          hosts={hostList}
          vaults={vaults}
          // Saved: back to where it was opened from, with the list showing it.
          onSaved={() => void refresh().then(close)}
          onChanged={() => void refresh()}
          onDeleted={() => (void refresh(), close())}
          onClose={close}
        />
      )}
      {view.kind === "security" && (
        <SecurityPanel
          sync={syncStatus}
          onChanged={() => void syncApi.status().then(setSyncStatus, () => {})}
          onDeviceChanged={(d) => setAutoLock(d.autoLockMinutes)}
          onClose={close}
        />
      )}
      {view.kind === "about" && (
        <AboutPanel update={update} onUpdate={setUpdate} onAutoCheckChanged={setAutoUpdate} onClose={close} />
      )}
      {view.kind === "appearance" && termSettings && (
        <AppearancePanel
          settings={termSettings}
          themes={themeList}
          vaults={vaults}
          appTheme={appTheme}
          onChanged={() => (loadTermSettings(), void appearanceApi.themes().then(setThemes, () => {}))}
          onClose={close}
        />
      )}
      {view.kind === "logs" && (
        <SessionLogsPanel key={view.hostId ?? "all"} hostId={view.hostId} hosts={hostList} groups={groupList} vaults={vaults} look={deviceLook} onClose={close} />
      )}
      {view.kind === "teams" && (
        <TeamsPanel
          key={linked?.invite || linked?.org ? linked.n : 0}
          vaults={vaults}
          orgs={orgList}
          keys={keyList}
          syncStatus={syncStatus}
          onChanged={refresh}
          onClose={close}
          onSso={(orgId, orgName) => setSsoFor({ orgId, orgName })}
          totpRequired={syncStatus?.totpRequired.map((o) => o.orgId) ?? []}
          onTotp={() => open({ kind: "sync", totp: true })}
          invite={linked?.invite}
          openOrg={linked?.org}
        />
      )}
      {view.kind === "sync" && syncStatus && (
        <SyncPanel
          key={view.totp ? "totp" : "sync"}
          startTotp={view.totp}
          status={syncStatus}
          orgs={orgList}
          onChanged={() => void syncApi.status().then(setSyncStatus).then(refresh)}
          onClose={close}
          onOpenTeams={() => open({ kind: "teams" })}
        />
      )}
      {view.kind === "forward" && (
        <ForwardEditor
          key={view.id ?? "new"}
          forward={forwardList.find((f) => f.id === view.id)}
          hosts={hostList}
          vaults={vaults}
          onSaved={(f, start) =>
            void refresh().then(() => {
              setView({ kind: "forward", id: f.id });
              if (start) startForward(f);
            })
          }
          onDeleted={() => (void refresh(), close())}
          onCancel={close}
        />
      )}
      {view.kind === "snippet" && (
        <SnippetPanel
          key={view.id ?? "new"}
          snippet={snippetList.find((s) => s.id === view.id)}
          vaults={vaults}
          targetTitle={sendTarget?.title ?? null}
          onSaved={(s) => void refresh().then(() => setView({ kind: "snippet", id: s.id }))}
          onDeleted={() => (void refresh(), close())}
          onCancel={close}
          onSend={sendSnippet}
        />
      )}
      {view.kind === "hosts" && (
        <HostsPage onChanged={() => void refresh()}
          hosts={hostList}
          groups={groupList}
          identities={identityList}
          keys={keyList}
          vpns={vpnList}
          vaults={vaults}
          live={live}
          onConnect={(h) => connectHost(h)}
          onShowSession={showSession}
          onFiles={(h) => connectHost(h, undefined, "sftp")}
          onEdit={(id) => open({ kind: "host", id })}
          onEditGroup={(id) => open({ kind: "group", id })}
          onOpenGroup={(id) => open({ kind: "groupPage", id })}
          onImport={() => open({ kind: "importHosts" })}
          onCloud={(add) => open({ kind: "cloud", add })}
          onQuickConnect={mobile ? undefined : () => open({ kind: "quick" })}
          onClose={close}
        />
      )}
      {view.kind === "importHosts" && <ImportHostsPage vaults={vaults} onImported={() => void refresh()} onClose={close} />}
      {view.kind === "cloud" && (
        <CloudPage key={view.add ?? "clouds"} vaults={vaults} keys={keyList} hosts={hostList} adding={view.add} onChanged={() => void refresh()} onClose={close} />
      )}
      {(view.kind === "groups" || (view.kind === "groupPage" && !groupList.some((g) => g.id === view.id))) && (
        <GroupsPage onChanged={() => void refresh()}
          groups={groupList}
          hosts={hostList}
          identities={identityList}
          keys={keyList}
          vpns={vpnList}
          vaults={vaults}
          live={live}
          onOpen={(id) => open({ kind: "groupPage", id })}
          onEdit={(id) => open({ kind: "group", id })}
          onClose={close}
        />
      )}
      {view.kind === "groupPage" && groupList.some((g) => g.id === view.id) && (
        <GroupPage
          group={groupList.find((g) => g.id === view.id)!}
          groups={groupList}
          hosts={hostList}
          identities={identityList}
          keys={keyList}
          vpns={vpnList}
          forwards={forwardList}
          vaults={vaults}
          live={live}
          pending={pending}
          onConnect={(h) => connectHost(h)}
          onShowSession={showSession}
          onFiles={(h) => connectHost(h, undefined, "sftp")}
          onEditHost={(id) => open({ kind: "host", id })}
          onEditGroup={(id) => open({ kind: "group", id })}
          onToggleForward={toggleForward}
          onOpenForward={(id) => open({ kind: "forward", id })}
          onOpenKey={(id) => open({ kind: "key", id })}
          onOpenIdentity={(id) => open({ kind: "identity", id })}
          onOpenVpn={(id) => open({ kind: "vpn", id })}
          onBack={() => setView({ kind: "groups" })}
          onClose={close}
        />
      )}
      {view.kind === "keys" && (
        <KeysPage onChanged={() => void refresh()}
          keys={keyList}
          identities={identityList}
          hostCas={hostCaList}
          hosts={hostList}
          groups={groupList}
          vaults={vaults}
          onOpenKey={(id) => open({ kind: "key", id })}
          onEditIdentity={(id) => open({ kind: "identity", id })}
          onEditHostCa={(id) => open({ kind: "hostCa", id })}
          tab={view.tab ?? "keys"}
          onTab={(tab) => setView({ kind: "keys", tab })}
          onClose={close}
        />
      )}
      {view.kind === "snippets" && (
        <SnippetsPage onChanged={() => void refresh()}
          snippets={snippetList}
          vaults={vaults}
          target={sendTarget?.title ?? null}
          onOpen={(id) => open({ kind: "snippet", id })}
          onImport={() => open({ kind: "importSnippets" })}
          onSend={sendSnippet}
          onClose={close}
        />
      )}
      {view.kind === "importSnippets" && <ImportSnippetsPage snippets={snippetList} vaults={vaults} onImported={() => void refresh()} onClose={close} />}
      {view.kind === "forwards" && (
        <TunnelsPage onChanged={() => void refresh()}
          forwards={forwardList}
          hosts={hostList}
          vaults={vaults}
          live={live}
          pending={pending}
          onToggle={toggleForward}
          onOpen={(id) => open({ kind: "forward", id })}
          onClose={close}
        />
      )}
      {view.kind === "vpns" && (
        <VpnsPage onChanged={() => void refresh()} vpns={vpnList} hosts={hostList} groups={groupList} vaults={vaults} onOpen={(id) => open({ kind: "vpn", id })} onClose={close} />
      )}
    </>
  );

  const dialogs = (
    <>
      {offering && syncStatus && !syncStatus.enabled && (
        <SyncOffer
          later={mobile ? "More › Sync" : "Sync, at the bottom of the sidebar"}
          onDone={(enabled) => {
            setOffering(false);
            syncOfferTime.forget();
            if (enabled) void syncApi.status().then(setSyncStatus).then(refresh);
          }}
        />
      )}
      {approvalFor && <ApprovalWait key={approvalFor.orgId} need={approvalFor} onClose={() => setApprovalFor(null)} />}
      {ssoFor && <SsoSignIn key={ssoFor.orgId} orgId={ssoFor.orgId} orgName={ssoFor.orgName} onDone={() => setSsoFor(null)} onClose={() => setSsoFor(null)} />}
      {vpnPrompts[0] && <VpnPromptDialog key={vpnPrompts[0].promptId} prompt={vpnPrompts[0]} onAnswer={(a) => answerVpn(vpnPrompts[0], a)} />}
      {changedKeys[0] && (
        <HostKeyChangedDialog
          key={`${changedKeys[0].host}:${changedKeys[0].port}`}
          changed={changedKeys[0]}
          label={hostList.find((h) => h.hostname === changedKeys[0].host && h.port === changedKeys[0].port)?.label}
          onClose={() => setChangedKeys((c) => c.slice(1))}
        />
      )}
      {touch?.key && (
        <div className="touch-key" role="status">
          <strong>Touch your security key</strong>
          <span>
            to sign in to {touch.host}
            {touch.key.comment ? ` (${touch.key.comment})` : ""}
          </span>
        </div>
      )}
      {prompts[0] && <HostKeyDialog key={prompts[0].promptId} prompt={prompts[0]} onAnswer={(a) => answer(prompts[0], a)} />}
      {checking && (
        <SnippetCheckDialog
          key={checking.snippet.id}
          snippet={checking.snippet}
          run={checking.run}
          onAnswer={(send) => {
            setChecking(null);
            if (!send) return;
            checking.go();
            markSent(checking.snippet.id);
          }}
        />
      )}
      {askPassword && (
        <PasswordDialog
          title={`Password for ${askPassword.host.user}@${askPassword.host.hostname}`}
          message="Not saved in the vault. It is used for this connection only."
          onSubmit={(pw) => {
            const { then } = askPassword;
            setAskPassword(null);
            then(pw);
          }}
          onCancel={() => setAskPassword(null)}
        />
      )}
    </>
  );

  if (mobile) {
    return (
      <MoveContext.Provider value={moves}>
        <MobileWorkspace
          hosts={hostList}
          groups={groupList}
          keys={keyList}
          snippets={snippetList}
          vpns={vpnList}
          forwards={forwardList}
          pendingForwards={pending}
          vaults={vaults}
          syncStatus={syncStatus}
          update={update}
          tabs={tabs.map((t) => ({ ...t, prod: !!looks.get(t.key)?.prod }))}
          activeTab={activeTab}
          panel={view.kind === "tab" || view.kind === "quick" ? null : { title: panelTitle(view), node: panels }}
          banner={banner}
          terminal={(t, active) => (
            <TerminalView
              target={t.target}
              title={t.title}
              active={active}
              look={looks.get(t.key)?.look ?? DEFAULT_LOOK}
              onStatus={(s) => setStatus(t.key, s)}
              register={(c) => (c ? controls.current.set(t.key, c) : controls.current.delete(t.key))}
              onRecording={recording(t.key)}
            />
          )}
          onSftpStatus={setStatus}
          onConnect={(h, kind) => connectHost(h, undefined, kind)}
          onShowTab={(key) => open({ kind: "tab", key })}
          onCloseTab={closeTab}
          onHome={() => open({ kind: "quick" })}
          onEditHost={(id) => open({ kind: "host", id })}
          onOpenKey={(id) => open({ kind: "key", id })}
          onOpenSnippet={(id) => open({ kind: "snippet", id })}
          onImportSnippets={() => open({ kind: "importSnippets" })}
          onOpenVpn={(id) => open({ kind: "vpn", id })}
          onOpenForward={(id) => open({ kind: "forward", id })}
          onToggleForward={toggleForward}
          onOpenMore={(p: MorePanel) =>
            open(p === "quick" ? { kind: "connect" } : p === "forwards" ? { kind: "forward" } : p === "logs" ? { kind: "logs" } : { kind: p })
          }
          onLock={onLock}
          onTotp={() => open({ kind: "sync", totp: true })}
          onSso={setSsoFor}
          onApproval={setApprovalFor}
          onSend={(key, body, run, snippet) => guardSnippet(snippet, run, () => sendTo(key, body, run))}
          onKey={(key, k) => controls.current.get(key)?.key(k)}
          onCtrl={(key, on, used) => controls.current.get(key)?.ctrl(on, used)}
        />
        {dialogs}
      </MoveContext.Provider>
    );
  }

  return (
    <MoveContext.Provider value={moves}>
      <div className="shell">
        <Sidebar
          hosts={hostList}
          groups={groupList}
          identities={identityList}
          keys={keyList}
          snippets={snippetList}
          forwards={forwardList}
          vpns={vpnList}
          page={
            view.kind === "groupPage" ? "groups" : PAGES.has(view.kind) && view.kind !== "teams" && view.kind !== "sync" ? (view.kind as PageKind) : null
          }
          onOpenPage={(page) => open({ kind: page })}
          selected={selected}
          activeHost={currentHost?.id ?? null}
          live={live}
          onConnect={(h) => connectHost(h)}
          onShowSession={showSession}
          onOpenFiles={(h) => connectHost(h, undefined, "sftp")}
          onEditHost={(id) => open({ kind: "host", id })}
          onEditGroup={(id) => open({ kind: "group", id })}
          onOpenGroup={(id) => open({ kind: "groupPage", id })}
          syncStatus={syncStatus}
          onOpenSync={() => open({ kind: "sync" })}
          vaults={vaults}
          onOpenTeams={() => open({ kind: "teams" })}
          onTotp={() => open({ kind: "sync", totp: true })}
          onSso={setSsoFor}
          onApproval={setApprovalFor}
          onOpenAppearance={() => open({ kind: "appearance" })}
          onOpenSecurity={() => open({ kind: "security" })}
          update={update}
          onOpenAbout={() => open({ kind: "about" })}
          onLock={onLock}
        />

        <section className="workspace">
          <header className="tabbar" hidden={tabs.length === 0 && PAGES.has(view.kind)}>
            <nav className="tabs" role="tablist">
              {tabs
                // A split is one tab, shown with its first pane.
                .filter((t) => {
                  const split = splitOf(t.key);
                  return !split || panes(split.layout)[0] === t.key;
                })
                .map((t) => {
                  const split = splitOf(t.key);
                  const keys = split ? panes(split.layout) : [t.key];
                  const on = activeTab !== null && keys.includes(activeTab);
                  return (
                    <div
                      key={t.key}
                      role="tab"
                      aria-selected={on}
                      className={`tab ${on ? "active" : ""} ${looks.get(t.key)?.prod ? "prod" : ""} ${split?.broadcast ? "broadcasting" : ""}`}
                      onClick={() => open({ kind: "tab", key: split ? split.focus : t.key })}
                    >
                      <span className={`dot ${t.status}`} />
                      {looks.get(t.key)?.prod && <span className="tab-marker">PROD</span>}
                      {t.recording && t.status === "connected" && (
                        <span className="rec-marker" title="This session is recorded into the vault">
                          REC
                        </span>
                      )}
                      {t.kind === "sftp" && <span className="tab-kind">SFTP</span>}
                      <span className="label">{t.title}</span>
                      {split && (
                        <span className="tab-panes" title={`${keys.length} panes${split.broadcast ? ", typing goes to all of them" : ""}`}>
                          +{keys.length - 1}
                        </span>
                      )}
                      <button
                        className="close"
                        aria-label={split ? "Close the tab and its panes" : "Close tab"}
                        onClick={(e) => {
                          e.stopPropagation();
                          closeTabs(keys);
                        }}
                      >
                        <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                          <path d="M6 6l12 12M18 6L6 18" />
                        </svg>
                      </button>
                    </div>
                  );
                })}
              <button className={`tab new ${view.kind === "quick" ? "active" : ""}`} onClick={() => open({ kind: "quick" })} aria-label="Quick connect" title="Quick connect">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                  <path d="M12 5v14M5 12h14" />
                </svg>
              </button>
            </nav>
          </header>
          {current?.kind === "terminal" && (
            <RouteBar
              key={current.key}
              target={current.target}
              status={current.status}
              hosts={hostList}
              vpns={vpnList}
              onFiles={currentHost && (() => connectHost(currentHost, undefined, "sftp"))}
              snippets={snippetList}
              onSend={(snippet, run) =>
                guardSnippet(snippet, run, () =>
                  currentSplit?.broadcast
                    ? panes(currentSplit.layout).forEach((k) => tabs.find((t) => t.key === k)?.status === "connected" && sendTo(k, snippet.body, run, false))
                    : sendTo(current.key, snippet.body, run),
                )
              }
              onSplit={splitWith}
              broadcast={currentSplit ? { on: currentSplit.broadcast, panes: panes(currentSplit.layout).length } : null}
              onBroadcast={() =>
                setSplits((all) => all.map((x) => (x === currentSplit ? { ...x, broadcast: !x.broadcast } : x)))
              }
              onNewSnippet={() => open({ kind: "snippet" })}
              recording={!!current.recording && current.status === "connected"}
              onLogs={() => open({ kind: "logs", hostId: currentHost?.id })}
            />
          )}

          <main className="content">
            {banner}
            {/* Pages and panes fill what the banner leaves. */}
            <div className="content-body" ref={contentRef}>
              {panels}
              {tabs.map((t) => {
                if (t.kind === "sftp") {
                  return <SftpView key={t.key} target={t.target} title={t.title} active={activeTab === t.key} onStatus={(s) => setStatus(t.key, s)} />;
                }
                // Every terminal stays mounted here; a split only places it.
                const rect = paneRects?.get(t.key);
                const split = rect ? currentSplit : undefined;
                return (
                  <div
                    key={t.key}
                    className={`pane ${rect ? "split" : ""} ${split?.broadcast ? "broadcast" : ""} ${rect && activeTab === t.key ? "focused" : ""}`}
                    style={paneStyle(rect)}
                    hidden={!shown(t.key)}
                  >
                    {rect && (
                      <div className="pane-head" onMouseDown={() => focusPane(t.key)}>
                        <span className={`dot ${t.status}`} />
                        {looks.get(t.key)?.prod && <span className="tab-marker">PROD</span>}
                        <span className="label">{t.title}</span>
                        {split?.broadcast && <span className="tab-marker broadcast-marker">BROADCAST</span>}
                        <button type="button" className="close" aria-label={`Close the pane ${t.title}`} onClick={() => closeTab(t.key)}>
                          <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                            <path d="M6 6l12 12M18 6L6 18" />
                          </svg>
                        </button>
                      </div>
                    )}
                    <TerminalView
                      target={t.target}
                      title={t.title}
                      active={shown(t.key)}
                      focused={activeTab === t.key}
                      onFocus={() => focusPane(t.key)}
                      onInput={(d) => broadcastFrom(t.key, d)}
                      look={looks.get(t.key)?.look ?? DEFAULT_LOOK}
                      onStatus={(s) => setStatus(t.key, s)}
                      register={(c) => (c ? controls.current.set(t.key, c) : controls.current.delete(t.key))}
                      onRecording={recording(t.key)}
                    />
                  </div>
                );
              })}
              {currentSplit &&
                dividers(currentSplit.layout).map((d) => (
                  <div
                    key={`${d.path.join(".")}-${d.index}`}
                    className={`pane-divider ${d.dir}`}
                    role="separator"
                    aria-orientation={d.dir === "row" ? "vertical" : "horizontal"}
                    style={
                      d.dir === "row"
                        ? { left: `${d.at}%`, top: `${d.box.top}%`, height: `${d.box.height}%` }
                        : { top: `${d.at}%`, left: `${d.box.left}%`, width: `${d.box.width}%` }
                    }
                    onPointerDown={drag(d, panes(currentSplit.layout)[0])}
                  />
                ))}
            </div>
          </main>
        </section>

        {dialogs}
      </div>
    </MoveContext.Provider>
  );
}

/** A full-screen panel's title on a phone. */
function panelTitle(view: View): string {
  const named = (id: string | undefined, it: string, fresh: string) => (id ? it : fresh);
  switch (view.kind) {
    case "connect":
      return "Quick connect";
    case "host":
      return named(view.id, "Edit host", "New host");
    case "key":
      return named(view.id, "Key", "New key");
    case "snippet":
      return named(view.id, "Snippet", "New snippet");
    case "importSnippets":
      return "Import snippets";
    case "forward":
      return named(view.id, "Tunnel", "New tunnel");
    case "vpn":
      return named(view.id, "VPN", "New VPN");
    case "sync":
      return "Sync";
    case "security":
      return "Security";
    case "about":
      return "About";
    case "teams":
      return "Teams";
    case "appearance":
      return "Settings";
    case "logs":
      return "Session logs";
    default:
      return "";
  }
}

/** Before this device's settings load. */
const DEFAULT_LOOK: TerminalLook = {
  theme: findTheme(null, []),
  fontFamily: "",
  fontSize: 14,
  cursorStyle: "block",
  cursorBlink: true,
  boldBright: false,
  minimumContrast: 4.5,
};

/** The terminal's look from this device's settings and a scheme (an imported one has no
 * minimum contrast of its own: its colors are drawn as they are unless the device sets one). */
function lookFor(s: TerminalSettings, theme: TerminalLook["theme"], schemeContrast?: number): TerminalLook {
  return {
    theme,
    fontFamily: s.fontFamily,
    fontSize: s.fontSize,
    cursorStyle: s.cursorStyle,
    cursorBlink: s.cursorBlink,
    boldBright: s.boldBright,
    minimumContrast: s.minimumContrast ?? schemeContrast ?? 1,
  };
}

/** Applies the app theme (Console or Greenbar, or the system's) and returns the one in effect. */
function useAppTheme(choice: "dark" | "light" | "system"): "dark" | "light" {
  const query = "(prefers-color-scheme: light)";
  const [systemLight, setSystemLight] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const m = window.matchMedia(query);
    const on = () => setSystemLight(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  const theme = choice === "system" ? (systemLight ? "light" : "dark") : choice;
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  return theme;
}

const UPDATE_EVERY_MS = 12 * 60 * 60 * 1000;

/** Looks for a newer release shortly after opening and then twice a day, while turned on. Failures stay quiet (offline is normal); "Check now" in About shows them. */
function useUpdateChecks(on: boolean, found: (u: UpdateInfo | null) => void) {
  useEffect(() => {
    // Phones and tablets update through their app store.
    if (!on || mobileOs) return;
    const check = () => void updatesApi.check().then(found, () => {});
    const first = setTimeout(check, 5000);
    const every = setInterval(check, UPDATE_EVERY_MS);
    return () => (clearTimeout(first), clearInterval(every));
  }, [on, found]);
}
