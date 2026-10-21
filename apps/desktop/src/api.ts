import { Channel, invoke } from "@tauri-apps/api/core";
import type { ThemeColors } from "./themes";

// ------------------------------------------------------------------ SSH

export type AuthRequest =
  | { kind: "password"; password: string }
  /** A private key the person chose or pasted, for this connection only. */
  | { kind: "key"; privateKey: string; passphrase?: string }
  | { kind: "agent" };

export type ConnectTarget =
  | { kind: "adhoc"; host: string; port: number; user: string; auth: AuthRequest }
  /** `tmux` names the tab's session on the server, for hosts that keep theirs. */
  | { kind: "saved"; hostId: string; password?: string; tmux?: string };

export interface TermSize {
  cols: number;
  rows: number;
}

export type StatusEvent =
  | { kind: "exit"; status: number }
  | { kind: "closed" }
  /** The session is recorded into this session log. */
  | { kind: "recording"; logId: string };

export interface HostKeyPrompt {
  promptId: number;
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
}

/** A host answered with a different key than the one pinned (`hostkey-changed`). */
export interface ChangedHostKey {
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  pinnedAlgorithm: string | null;
  pinnedFingerprint: string | null;
  /** The known_hosts file and line holding the pinned key. */
  file: string | null;
  line: number | null;
}

export interface PinnedKey {
  algorithm: string;
  fingerprint: string;
}

/** "ssh-ed25519" → "ED25519", "ecdsa-sha2-nistp256" → "ECDSA", "rsa-sha2-512" → "RSA". */
export function keyType(algorithm: string): string {
  const a = algorithm.toLowerCase();
  if (a.includes("ed25519")) return "ED25519";
  if (a.includes("ed448")) return "ED448";
  if (a.includes("ecdsa")) return "ECDSA";
  if (a.includes("rsa")) return "RSA";
  if (a.includes("dss")) return "DSA";
  return algorithm.toUpperCase();
}

export function connect(
  target: ConnectTarget,
  size: TermSize,
  onOutput: (bytes: Uint8Array) => void,
  onStatus: (event: StatusEvent) => void,
): Promise<number> {
  const output = new Channel<ArrayBuffer | number[]>();
  output.onmessage = (data) => onOutput(data instanceof ArrayBuffer ? new Uint8Array(data) : Uint8Array.from(data));
  const status = new Channel<StatusEvent>();
  status.onmessage = onStatus;
  return invoke<number>("ssh_connect", { request: { target, size }, onOutput: output, onStatus: status });
}

/** Keeps keystrokes in order: one write in flight, everything typed meanwhile goes in the next one. */
export function createWriter(id: number) {
  let pending = "";
  let inflight = false;
  const flush = async () => {
    inflight = true;
    try {
      while (pending) {
        const data = pending;
        pending = "";
        await invoke("ssh_write", { id, data });
      }
    } finally {
      inflight = false;
    }
  };
  return (data: string) => {
    pending += data;
    if (!inflight) void flush().catch(() => {});
  };
}

export const resize = (id: number, size: TermSize) => invoke("ssh_resize", { id, size });
export const disconnect = (id: number) => invoke("ssh_disconnect", { id });
export const answerHostKey = (promptId: number, accept: boolean) => invoke("hostkey_answer", { promptId, accept });

// ------------------------------------------------------------------ Vault

export type VaultStatus = "uninitialized" | "locked" | "unlocked";

/** zxcvbn's estimate of a master password, as the app checks it. */
export interface PasswordStrength {
  /** Long enough (10) and hard enough to guess (10^10 guesses). */
  ok: boolean;
  guessesLog10: number;
  warning: string | null;
  suggestions: string[];
}

export const vault = {
  /** How strong a master password would be (desktop and phone check alike). */
  strength: (password: string) => invoke<PasswordStrength>("password_strength", { password }),
  status: () => invoke<VaultStatus>("vault_status"),
  /** Resolves to the recovery code, shown once. */
  create: (password: string) => invoke<string>("vault_create", { password }),
  unlock: (password: string) => invoke<void>("vault_unlock", { password }),
  lock: () => invoke<void>("vault_lock"),
  recover: (recoveryCode: string, newPassword: string) => invoke<void>("vault_recover", { recoveryCode, newPassword }),
  changePassword: (current: string, newPassword: string) => invoke<void>("vault_change_password", { current, newPassword }),
  /** The old recovery code stops working; the new one is returned to show once. */
  newRecoveryCode: (password: string) => invoke<string>("vault_new_recovery_code", { password }),
  /** Saves a readable copy of the vault in Downloads; resolves to its path. */
  export: (password: string, secrets: boolean, teamVaults: boolean) =>
    invoke<string>("vault_export", { password, secrets, teamVaults }),
};

/** What the OS asks for to confirm it's the user: Touch ID, Face ID, Windows Hello, or (Linux
 * polkit, a Mac without Touch ID) the system's own authentication; on an iPhone or iPad without
 * Face ID or Touch ID, the passcode. "biometric": Android's fingerprint or face check, which the
 * unlock key itself depends on. */
export type PresenceKind = "touchId" | "faceId" | "windowsHello" | "system" | "passcode" | "biometric";

export interface Presence {
  kind: PresenceKind;
  /** "setup": Linux needs MorphGate's polkit action installed first. */
  status: "ready" | "setup" | "unavailable";
  detail?: string;
}

export interface DeviceStatus {
  keychainAvailable: boolean;
  keychainEnabled: boolean;
  /** 0 = never. */
  autoLockMinutes: number;
  presence: Presence;
  /** Keychain unlock asks the OS to verify the user first. */
  presenceRequired: boolean;
  /** Look for updates at launch and twice a day. */
  autoUpdateCheck: boolean;
}

export const presenceName = (kind: PresenceKind) =>
  kind === "touchId"
    ? "Touch ID"
    : kind === "faceId"
      ? "Face ID"
      : kind === "windowsHello"
        ? "Windows Hello"
        : kind === "biometric"
          ? "fingerprint or face"
          : kind === "passcode"
            ? "your passcode"
            : "system authentication";

/** Unlock options of this device (not synced). */
export const device = {
  status: () => invoke<DeviceStatus>("device_status"),
  enableKeychain: (password: string) => invoke<void>("keychain_enable", { password }),
  disableKeychain: () => invoke<void>("keychain_disable"),
  unlockWithKeychain: () => invoke<void>("vault_unlock_keychain"),
  /** Turning it on shows the OS prompt once, to check that it works. */
  requirePresence: (enabled: boolean) => invoke<void>("presence_require", { enabled }),
  /** Linux: installs the polkit action (asks for an administrator password). */
  setupPresence: () => invoke<void>("presence_setup"),
  setAutoLock: (minutes: number) => invoke<void>("set_auto_lock", { minutes }),
  setAutoUpdateCheck: (enabled: boolean) => invoke<void>("set_auto_update_check", { enabled }),
};

// ------------------------------------------------------------------ updates

export interface About {
  version: string;
  /** How this copy was installed; absent for a development build (which can't update itself). */
  package?: "appimage" | "deb" | "rpm" | "app" | "dmg" | "msi" | "nsis";
}

export interface UpdateInfo {
  version: string;
  notes?: string;
  /** RFC 3339. */
  date?: string;
}

export type UpdateProgress = { kind: "downloading"; downloaded: number; total: number | null } | { kind: "installing" };

export const updates = {
  about: () => invoke<About>("about"),
  /** The newer release, or null when this is the latest. */
  check: () => invoke<UpdateInfo | null>("update_check"),
  /** Verifies and installs the update from the last check, then restarts MorphGate (so this only settles on failure). */
  install: (onProgress: (p: UpdateProgress) => void) => {
    const ch = new Channel<UpdateProgress>();
    ch.onmessage = onProgress;
    return invoke<void>("update_install", { onProgress: ch });
  },
};

/** An SSH agent: `agent` names which (`null`: the system's; `1password`, `bitwarden`, `secretive`,
 * `pageant`, `custom` with `path`), `key` the one key offered (`null`: every key it holds). */
export interface AgentChoice {
  agent: string | null;
  path: string | null;
  key: string | null;
}

export type HostAuthView = { kind: "password"; saved: boolean } | { kind: "key"; keyId: string } | ({ kind: "agent" } & AgentChoice);

export interface HostView {
  id: string;
  /** The vault it lives in. */
  vaultId: string;
  label: string;
  hostname: string;
  port: number;
  user: string;
  auth: HostAuthView;
  /** Host this one is reached through (ProxyJump). */
  jumpId: string | null;
  /** VPN profile used when this host is dialed directly. */
  vpnId: string | null;
  /** Terminal theme for this host (a vault theme's id or `builtin:…`); null = the device's. */
  themeId: string | null;
  /** Its sessions are recorded into the vault. */
  recordSessions: boolean;
  /** It attaches to a tmux session on the server (itself, or its group). */
  keepSession: boolean;
  /** The SSH agent is forwarded to it. */
  forwardAgent: boolean;
  /** Run at login, with a terminal, instead of the shell. */
  loginCommand: string | null;
  /** How its jump host carries it: a command the jump host runs (`%h`, `%p`, `%r`). */
  jumpCommand: string | null;
  /** A command on this computer whose input and output are the connection (`ProxyCommand`). */
  proxyCommand: string | null;
  /** This device runs `proxyCommand`: it was typed or imported here, or allowed. */
  proxyAllowed: boolean;
  /** The cloud source that keeps it in step with a provider, if one does. */
  source: {
    sourceId: string;
    provider: CloudProvider | "";
    gone: boolean;
    noSftp: boolean;
    noForwarding: boolean;
    state: string | null;
    /** Reached through its cloud. */
    via: CloudReachKind | null;
  } | null;
  groupId: string | null;
  /** Shared credentials it signs in with. */
  identityId: string | null;
  tags: string[];
  notes: string;
  updatedAt: number;
  /**
   * What the host itself says. The fields above are as it connects: user and sign-in from its
   * identity (or its group's), and the jump host, VPN, theme and session keeping it leaves to
   * its group.
   */
  own: {
    user: string;
    auth: HostAuthView;
    jumpId: string | null;
    vpnId: string | null;
    themeId: string | null;
    keepSession: boolean;
  };
}

/** Credentials several hosts share. */
export interface IdentityView {
  id: string;
  vaultId: string;
  label: string;
  user: string;
  auth: HostAuthView;
  updatedAt: number;
}

export interface IdentityInput {
  id?: string;
  vaultId?: string;
  label: string;
  user: string;
  auth: HostAuthInput;
}

/** Hosts that belong together, and the defaults they share. */
export interface GroupView {
  id?: string;
  vaultId?: string;
  name: string;
  identityId: string | null;
  jumpId: string | null;
  vpnId: string | null;
  themeId: string | null;
  keepSession: boolean;
}

/** `password: null` keeps the saved one, `""` forgets it. */
export type HostAuthInput = { kind: "password"; password: string | null } | { kind: "key"; keyId: string } | ({ kind: "agent" } & AgentChoice);

export interface HostInput {
  id?: string;
  /** A new item goes into this vault (default: the personal one). */
  vaultId?: string;
  label: string;
  hostname: string;
  port: number;
  user: string;
  auth: HostAuthInput;
  jumpId?: string | null;
  vpnId?: string | null;
  themeId?: string | null;
  recordSessions?: boolean;
  keepSession?: boolean;
  forwardAgent?: boolean;
  loginCommand?: string | null;
  jumpCommand?: string | null;
  proxyCommand?: string | null;
  groupId?: string | null;
  identityId?: string | null;
  tags: string[];
  notes: string;
}

/** An OpenSSH user certificate, as the app reads it. */
export interface CertInfo {
  /** The certificate as one line. */
  certificate: string;
  keyId: string;
  /** The users it signs in as; empty: any the server allows. */
  principals: string[];
  /** Unix seconds. A certificate that never expires has a `validBefore` past 2^63. */
  validAfter: number;
  validBefore: number;
  /** The CA that signed it (`SHA256:…`). */
  ca: string;
}

export interface KeyView {
  id: string;
  /** The vault it lives in. */
  vaultId: string;
  label: string;
  algorithm: string;
  fingerprint: string;
  publicKey: string;
  encrypted: boolean;
  /** Its OpenSSH certificate, presented when signing in. */
  certificate: CertInfo | null;
  /** A certificate is stored but can't be read (or isn't for this key). */
  certificateError: string | null;
  /** How its certificate is renewed: a command (given the public key) and where it leaves it. */
  renew: { command: string; file: string | null } | null;
  /** This device runs the renewal command (typed here, or allowed). */
  renewAllowed: boolean;
  updatedAt: number;
}

export type KeySource = { kind: "text"; text: string } | { kind: "file"; path: string };

export const hosts = {
  list: () => invoke<HostView[]>("hosts_list"),
  save: (input: HostInput) => invoke<HostView>("host_save", { input }),
  remove: (id: string) => invoke<void>("host_delete", { id }),
  /** Lets this device run the host's proxy command (one that came with the vault). */
  allowProxy: (id: string) => invoke<HostView>("host_allow_proxy", { id }),
  /** The host key `host:port` is pinned to, once it has connected. */
  pinnedKey: (host: string, port: number) => invoke<PinnedKey | null>("host_pinned_key", { host, port }),
};

export const identities = {
  list: () => invoke<IdentityView[]>("identities_list"),
  save: (input: IdentityInput) => invoke<IdentityView>("identity_save", { input }),
  remove: (id: string) => invoke<void>("identity_delete", { id }),
};

export const groups = {
  list: () => invoke<GroupView[]>("groups_list"),
  save: (input: GroupView) => invoke<GroupView>("group_save", { input }),
  /** Its hosts stay, keeping what they took from it. */
  remove: (id: string) => invoke<void>("group_delete", { id }),
};

export const keys = {
  list: () => invoke<KeyView[]>("keys_list"),
  generate: (label: string, vaultId?: string) => invoke<KeyView>("key_generate", { label, vaultId }),
  import: (label: string, source: KeySource, passphrase?: string, vaultId?: string) =>
    invoke<KeyView>("key_import", { input: { label, source, passphrase, vaultId } }),
  remove: (id: string) => invoke<void>("key_delete", { id }),
  /** Gives the key a certificate (a `-cert.pub` file or its text), or removes it (`null`). */
  certificate: (id: string, source: KeySource | null) => invoke<KeyView>("key_certificate", { id, source }),
  /** How its certificate is renewed (`null`: it isn't). */
  renewal: (id: string, renewal: { command: string; file?: string | null } | null) => invoke<KeyView>("key_renewal", { id, renewal }),
  /** Lets this device run the key's renewal command. */
  allowRenewal: (id: string) => invoke<KeyView>("key_allow_renewal", { id }),
  /** Renews its certificate now. */
  renew: (id: string) => invoke<KeyView>("key_renew", { id }),
};

export interface SnippetView {
  id: string;
  /** The vault it lives in. */
  vaultId: string;
  name: string;
  body: string;
  tags: string[];
  updatedAt: number;
}

export interface SnippetInput {
  id?: string;
  /** A new item goes into this vault (default: the personal one). */
  vaultId?: string;
  name: string;
  body: string;
  tags: string[];
}

// ------------------------------------------------------------------ host CAs

/** A CA whose signed host keys are trusted for the hosts its patterns match (`@cert-authority`). */
export interface HostCaView {
  id: string;
  vaultId: string;
  label: string;
  publicKey: string;
  algorithm: string;
  /** `SHA256:…` */
  fingerprint: string;
  hosts: string[];
}

export const hostCas = {
  list: () => invoke<HostCaView[]>("host_cas_list"),
  /** `publicKey`: the CA's key, or a whole `@cert-authority` line (its hosts come along). */
  save: (input: { id?: string; vaultId?: string; label: string; publicKey: string; hosts: string[] }) => invoke<HostCaView>("host_ca_save", { input }),
  remove: (id: string) => invoke<void>("host_ca_delete", { id }),
  /** The CA vouching for `host:port`, by name, where one does. */
  certifiedBy: (host: string, port: number) => invoke<string | null>("host_certified_by", { host, port }),
};

export const snippets = {
  list: () => invoke<SnippetView[]>("snippets_list"),
  save: (input: SnippetInput) => invoke<SnippetView>("snippet_save", { input }),
  remove: (id: string) => invoke<void>("snippet_delete", { id }),
  /** The snippets in a CSV file's text (Name, Command, Tags columns); `name` is the file's. */
  readCsv: (name: string, text: string) => invoke<SnippetCsv>("snippets_read_csv", { name, text }),
  /** Saves an example of that CSV in the downloads folder; says where. */
  saveCsvExample: () => invoke<string>("snippets_csv_example"),
};

/** A snippet a CSV file holds, not saved yet. */
export interface CsvSnippet {
  name: string;
  body: string;
  tags: string[];
}

export interface SnippetCsv {
  snippets: CsvSnippet[];
  /** Lines left out, and why. */
  warnings: string[];
}

export type ForwardRule =
  | { kind: "local"; bindHost: string; bindPort: number; targetHost: string; targetPort: number }
  | { kind: "remote"; bindHost: string; bindPort: number; targetHost: string; targetPort: number }
  | { kind: "dynamic"; bindHost: string; bindPort: number };

export interface ForwardView {
  id: string;
  /** The vault it lives in. */
  vaultId: string;
  label: string;
  hostId: string;
  rule: ForwardRule;
  running: boolean;
  /** Listening port while running (server-side for remote forwards). */
  port: number | null;
  active: number;
  updatedAt: number;
}

export interface ForwardInput {
  id?: string;
  /** A new item goes into this vault (default: the personal one). */
  vaultId?: string;
  label: string;
  hostId: string;
  rule: ForwardRule;
}

export const forwards = {
  list: () => invoke<ForwardView[]>("forwards_list"),
  save: (input: ForwardInput) => invoke<ForwardView>("forward_save", { input }),
  remove: (id: string) => invoke<void>("forward_delete", { id }),
  start: (id: string, password?: string) => invoke<ForwardView>("forward_start", { id, password }),
  stop: (id: string) => invoke<void>("forward_stop", { id }),
};

export interface SyncStatus {
  enabled: boolean;
  server: string | null;
  email: string | null;
  lastSyncAt: number | null;
  lastError: string | null;
  syncing: boolean;
  /** Sync is on but the server ended this device's session: sign in again. */
  signedOut: boolean;
  /** Organizations whose vaults wait for this account to turn on two-step verification. */
  totpRequired: SsoNeed[];
  /** Organizations whose vaults wait for this device to sign in at their identity provider. */
  ssoRequired: SsoNeed[];
  /** Organizations whose vaults wait for this device to be approved, or that denied it. */
  approvalRequired: ApprovalNeed[];
  /** Other devices waiting for this account's approval. */
  approvalsWaiting: ApprovalsWaiting[];
  /** Organizations that want this account's SSH keys published. */
  memberKeysDue: SsoNeed[];
}

export interface ApprovalNeed {
  orgId: string;
  orgName: string;
  denied: boolean;
}

export interface ApprovalsWaiting {
  orgId: string;
  orgName: string;
  count: number;
}

/** A device's request to open an organization's vaults. */
export interface DeviceRequest {
  accountId: string;
  email: string | null;
  deviceId: string;
  name: string | null;
  platform: string | null;
  status: "pending" | "approved" | "denied";
  requestedAt: string;
  decidedAt: string | null;
  /** One of this account's devices. */
  mine: boolean;
  thisDevice: boolean;
}

export interface SsoNeed {
  orgId: string;
  orgName: string;
}

/** Which teams wait for two-step verification, and what for. */
export function totpTitle(orgs: SsoNeed[]): string {
  const names = orgs.map((o) => o.orgName);
  const list = names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}` : names[0];
  return `${list} ${names.length > 1 ? "require" : "requires"} two-step verification: ${names.length > 1 ? "their" : "its"} vaults open here once your account has it`;
}

/** An organization's identity provider and this device's session with it. */
export interface SsoView {
  configured: boolean;
  required: boolean;
  protocol: "oidc" | "saml" | null;
  issuer: string | null;
  sessionExpiresAt: string | null;
}

export interface SyncDevice {
  id: string;
  name: string;
  platform: string;
  createdAt: string;
  lastSeenAt: string | null;
  current: boolean;
}

export interface SyncServer {
  name: string;
  version: string;
  registrationOpen: boolean;
  billing: boolean;
  /** New accounts confirm their address with a mailed code. */
  emailVerification: boolean;
  totp: boolean;
  /** The terms new accounts accept; null when the server asks for none. */
  terms: SyncTerms | null;
}

export interface SyncTerms {
  version: string;
  termsUrl: string;
  privacyUrl: string;
}

export interface SyncPlan {
  plan: string;
  /** trialing, active, grace, lapsed or canceled */
  status: string | null;
  expiresAt: string | null;
  /** While grace: until when it keeps syncing. */
  graceEndsAt: string | null;
  /** In grace because a seat in this team covered it and ended (expiresAt: when). */
  seatTeam: string | null;
}

/** The sync account as the server sees it, and what the server offers for it. */
export interface SyncAccount {
  email: string;
  /** null when the server doesn't verify addresses */
  emailVerified: boolean | null;
  totpEnabled: boolean;
  /** The server offers two-step verification. */
  totp: boolean;
  /** The server can move the account to another address. */
  emailChange: boolean;
  /** The server has an account portal. */
  portal: boolean;
  plan: SyncPlan | null;
  /** The server's terms changed since this account accepted them (or it never did). */
  termsToAccept: SyncTerms | null;
}

export interface TotpSetup {
  /** Base32, to type into an authenticator app. */
  secret: string;
  uri: string;
  /** QR code of the uri. */
  qrSvg: string;
}

export const sync = {
  /** Someone is using the app (window shown, input in the last 5 minutes): sync every minute, else
   * every 5, and at once on coming back. */
  presence: (present: boolean) => invoke<void>("sync_presence", { present }),
  status: () => invoke<SyncStatus>("sync_status"),
  check: (server: string) => invoke<SyncServer>("sync_check", { server }),
  /** Servers with email verification: mails the code `enable` needs. */
  startRegistration: (server: string, email: string) => invoke<void>("sync_start_registration", { server, email }),
  /** Resolves to a new recovery code if the vault had to rotate it. */
  /** `acceptedTerms`: the version of the server's terms the person accepted. */
  enable: (server: string, email: string, password: string, emailCode?: string, acceptedTerms?: string) =>
    invoke<{ recoveryCode: string | null }>("sync_enable", {
      signup: { server, email, password, emailCode: emailCode ?? null, acceptedTerms: acceptedTerms ?? null },
    }),
  /** Rejects with `isTotpRequired` when the account needs an authenticator code. */
  signIn: (server: string, email: string, password: string, totp?: string) =>
    invoke<void>("sync_sign_in", { server, email, password, totp }),
  /** This device's own vault joins an existing account (its items go along); resolves to how many. */
  join: (server: string, email: string, password: string, totp?: string) =>
    invoke<number>("sync_join", { server, email, password, totp }),
  recoverSignIn: (server: string, email: string, recoveryCode: string, newPassword: string) =>
    invoke<void>("sync_recover_sign_in", { server, email, recoveryCode, newPassword }),
  /** Rejects with `isTotpRequired` when the account needs an authenticator code. */
  signInAgain: (password: string, totp?: string) => invoke<void>("sync_sign_in_again", { password, totp }),
  account: () => invoke<SyncAccount>("sync_account"),
  totpStart: (password: string) => invoke<TotpSetup>("sync_totp_start", { password }),
  totpEnable: (code: string) => invoke<void>("sync_totp_enable", { code }),
  totpDisable: (password: string, code: string) => invoke<void>("sync_totp_disable", { password, code }),
  emailStart: (newEmail: string) => invoke<void>("sync_email_start", { newEmail }),
  emailChange: (password: string, newEmail: string, code: string) =>
    invoke<void>("sync_email_change", { password, newEmail, code }),
  /** The account portal, signed in; `next`: the page it lands on (`/account/team/<org>/billing`). */
  openPortal: (next?: string) => invoke<void>("sync_open_portal", { next: next ?? null }),
  /** Saves what the server keeps about the account as JSON in Downloads; resolves to its path. */
  exportAccount: () => invoke<string>("sync_export_account"),
  /** Deletes the sync account; this device keeps its vault, with sync off. */
  deleteAccount: (password: string) => invoke<void>("sync_delete_account", { password }),
  acceptTerms: (version: string) => invoke<void>("sync_accept_terms", { version }),
  devices: () => invoke<SyncDevice[]>("sync_devices"),
  revokeDevice: (id: string) => invoke<void>("sync_revoke_device", { id }),
  now: () => invoke<void>("sync_now"),
  /** Signs this device out. `remove`: and erases it (back to first run, `device-erased`); otherwise the
   * personal vault stays here, unsynced. */
  disable: (remove: boolean) => invoke<void>("sync_disable", { remove }),
};

// ------------------------------------------------------------------ teams

export type Access = "read" | "write" | "manage";
export type Role = "owner" | "admin" | "member";

export const ACCESS_NAMES: Record<Access, string> = { read: "Can view", write: "Can edit", manage: "Can manage" };
export const ROLE_NAMES: Record<Role, string> = { owner: "Owner", admin: "Admin", member: "Member" };

/** A vault on this device: the personal one, or an organization's. */
export interface VaultInfo {
  id: string;
  /** null for the personal vault. */
  name: string | null;
  orgId: string | null;
  personal: boolean;
  access: Access;
  /** Someone lost access and the vault's key hasn't been rotated yet. */
  rotationDue: boolean;
  items: number;
  /** The organization's member key directory: members' SSH public keys, every member can add theirs. */
  directory: boolean;
}

export interface SharingStatus {
  available: boolean;
  /** Why teams aren't available. */
  reason: string | null;
  accountId: string | null;
  /** This account's fingerprint, to read out to whoever confirms it. */
  fingerprint: string | null;
}

export interface OrgInfo {
  id: string;
  name: string;
  role: Role;
  /** "accepted": joined, waiting for an admin to confirm. */
  status: "accepted" | "confirmed";
  rootFingerprint: string;
}

export interface MemberView {
  accountId: string;
  email: string;
  role: Role;
  status: "accepted" | "confirmed";
  /** Compare it with the member (call, in person) before confirming. */
  fingerprint: string;
  /** The keys check out against the organization's certificates. */
  verified: boolean;
  me: boolean;
  /** Vaults their invite grants once confirmed (wire names). */
  pendingVaults: { vault_id: string; permission: Access }[];
}

export interface InviteView {
  id: string;
  email: string;
  role: Role;
  vaults: { vaultId: string; access: Access }[];
  expiresAt: string;
  /** Right after creating it, on servers that don't email invites: pass it on. */
  token: string | null;
}

export interface InvitePreview {
  orgId: string;
  orgName: string;
  email: string;
  role: Role;
  inviterEmail: string;
  /** Compare it with the owner before joining. */
  ownerFingerprint: string;
  expiresAt: string;
}

export interface VaultAccess {
  accountId: string;
  email: string;
  access: Access;
  /** Owners and admins: comes with the role. */
  implicit: boolean;
}

export interface Policies {
  /** Members without two-step verification can't open the organization's vaults. */
  requireTotp: boolean;
  membersCanCreateVaults: boolean;
  /** Invites only to these domains; empty = any. */
  allowedEmailDomains: string[];
  /** The server deletes team session logs older than this; 0 keeps them. */
  sessionLogRetentionDays: number;
  /** Set on the website with the identity provider; the app sends it back unchanged. */
  requireSso: boolean;
  /** New devices wait for approval before they open the organization's vaults. */
  requireDeviceApproval: boolean;
  /** Members publish the SSH keys they use on its servers; null: the server doesn't say. */
  requireMemberKeys: boolean | null;
}

export interface OrgPlan {
  plan: string;
  status: "trialing" | "active" | "grace" | "lapsed" | "canceled" | null;
  expiresAt: string | null;
  /** While grace: until when shared vaults keep syncing. */
  graceEndsAt: string | null;
  seats: number | null;
}

/** What the server says about an organization now. */
export interface OrgDetails {
  policies: Policies;
  /** Hosted servers only. */
  plan: OrgPlan | null;
  /** The server offers two-step verification, so it can be required. */
  totpOffered: boolean;
  /** Plans and seats are managed in the server's account portal. */
  portal: boolean;
  /** The server sells plans (hosted): a team without one says so. */
  plansOffered: boolean;
  /** Vaults without a usable plan refuse changes. */
  plansEnforced: boolean;
  /** The plan's features (`sso`, `scim`, `session_logs`); null: the server has no plans. */
  features: string[] | null;
  /** The server stores session logs. */
  sessionLogsOffered: boolean;
  /** The server can put the organization behind its identity provider. */
  ssoOffered: boolean;
}

export interface OrgEvent {
  seq: number;
  at: string;
  kind: string;
  actorId: string | null;
  targetId: string | null;
  vaultId: string | null;
  detail: string | null;
}

export interface Activity {
  /** Newest first. */
  events: OrgEvent[];
  /** Account and vault ids to names, as far as this device knows them. */
  names: Record<string, string>;
  /** Older events exist beyond what was loaded. */
  truncated: boolean;
}

/** An SSH public key a member published in the organization's directory. */
export interface MemberKeyView {
  id: string;
  accountId: string;
  email: string | null;
  /** OpenSSH `type base64`. */
  publicKey: string;
  label: string;
  fingerprint: string | null;
  /** Signed by that member. */
  verified: boolean;
  mine: boolean;
}

export const teams = {
  status: () => invoke<SharingStatus>("sharing_status"),
  ssoStatus: (orgId: string) => invoke<SsoView>("org_sso_status", { orgId }),
  /** Saves the whole activity log in Downloads (owners and admins); resolves to its path. */
  exportActivity: (orgId: string, format: "csv" | "jsonl") => invoke<string>("org_events_export", { orgId, format }),
  /** Certifies a confirmed member again, after comparing their fingerprint. */
  recertify: (orgId: string, accountId: string, fingerprint: string) =>
    invoke<void>("org_member_recertify", { orgId, accountId, fingerprint }),
  /** Waiting and denied devices: everyone's for owners and admins, your own otherwise. */
  deviceRequests: (orgId: string) => invoke<DeviceRequest[]>("org_device_requests", { orgId }),
  decideDevice: (orgId: string, accountId: string, deviceId: string, approve: boolean) =>
    invoke<void>("org_device_decide", { orgId, accountId, deviceId, approve }),
  /** Opens the sign-in page in the browser. */
  ssoStart: (orgId: string) => invoke<{ url: string; expiresIn: number }>("org_sso_start", { orgId }),
  vaults: () => invoke<VaultInfo[]>("vaults_list"),
  orgs: () => invoke<OrgInfo[]>("orgs_list"),
  createOrg: (name: string) => invoke<string>("org_create", { name }),
  createVault: (orgId: string, name: string) => invoke<string>("org_vault_create", { orgId, name }),
  members: (orgId: string) => invoke<MemberView[]>("org_members", { orgId }),
  invite: (orgId: string, email: string, role: Role, vaults: { vaultId: string; access: Access }[]) =>
    invoke<InviteView>("org_invite", { orgId, email, role, vaults }),
  invites: (orgId: string) => invoke<InviteView[]>("org_invites", { orgId }),
  cancelInvite: (orgId: string, inviteId: string) => invoke<void>("org_invite_cancel", { orgId, inviteId }),
  preview: (token: string) => invoke<InvitePreview>("invite_preview", { token }),
  /** `fingerprint`: the owner's, as compared; joining fails if it no longer matches. */
  accept: (token: string, fingerprint: string) => invoke<string>("invite_accept", { token, fingerprint }),
  confirm: (orgId: string, accountId: string, fingerprint: string) =>
    invoke<void>("member_confirm", { orgId, accountId, fingerprint }),
  setRole: (orgId: string, accountId: string, role: Role) => invoke<void>("member_role", { orgId, accountId, role }),
  /** Removes a member, or leaves when it's this account. */
  remove: (orgId: string, accountId: string) => invoke<void>("member_remove", { orgId, accountId }),
  access: (vaultId: string) => invoke<VaultAccess[]>("vault_access", { vaultId }),
  setAccess: (vaultId: string, accountId: string, access: Access) =>
    invoke<void>("vault_access_set", { vaultId, accountId, access }),
  revokeAccess: (vaultId: string, accountId: string) => invoke<void>("vault_access_revoke", { vaultId, accountId }),
  rotate: (vaultId: string) => invoke<void>("vault_rotate", { vaultId }),
  transfer: (orgId: string, accountId: string, password: string) =>
    invoke<void>("org_transfer", { orgId, accountId, password }),
  deleteOrg: (orgId: string, password: string) => invoke<void>("org_delete", { orgId, password }),
  /** Teams without a usable plan, where the server enforces plans: locked until they have one. */
  locked: () => invoke<string[]>("orgs_locked"),
  details: (orgId: string) => invoke<OrgDetails>("org_details", { orgId }),
  setPolicies: (orgId: string, policies: Policies) => invoke<void>("org_policies_set", { orgId, policies }),
  /** Owners and admins. */
  activity: (orgId: string) => invoke<Activity>("org_activity", { orgId }),
  /** Works offline: what this device has of the organization's directory. */
  memberKeys: (orgId: string) => invoke<MemberKeyView[]>("member_keys", { orgId }),
  /** Publishes the public half of a vault SSH key; the next sync shares it. */
  publishKey: (orgId: string, keyId: string) => invoke<string>("member_key_publish", { orgId, keyId }),
  unpublishKey: (id: string) => invoke<void>("member_key_unpublish", { id }),
};

/** A vault with the name the app shows: "Personal", or "Organization / Vault". */
// ------------------------------------------------------------------ morphgate:// links

/** What a link opens (it never joins, connects or changes anything by itself). */
export type Link =
  | { kind: "invite"; token: string; server: string | null }
  | { kind: "sync" }
  | { kind: "teams"; orgId: string | null }
  | { kind: "connect"; host: string; port: number | null; user: string | null; label: string | null };

/** A received link, or why it can't be opened. */
export interface ReceivedLink {
  link: Link | null;
  error: string | null;
}

export const links = {
  /** The links received since the last call (waiting while the vault was locked). */
  take: () => invoke<ReceivedLink[]>("links_take"),
};

// ------------------------------------------------------------------ SSH agents

export interface AgentKey {
  /** `SHA256:…` */
  fingerprint: string;
  algorithm: string;
  comment: string;
  certificate: boolean;
  /** A FIDO2 security key: signing waits for a touch. */
  securityKey: boolean;
}

export interface AgentInfo {
  /** What a host stores (`system`, `1password`, …, `custom`). */
  id: string;
  name: string;
  /** Where it listens on this device. */
  location: string;
  running: boolean;
  keys: AgentKey[];
  error: string | null;
}

export const agents = {
  /** This device's agents and their keys (`custom` with `path`'s). */
  list: (path?: string | null) => invoke<AgentInfo[]>("agents_list", { path: path ?? null }),
};

/** A security key waits for a touch (`key: null` once it signed). */
export interface SecurityKeyTouch {
  host: string;
  key: AgentKey | null;
}

// ------------------------------------------------------------------ importing hosts

export interface ImportHost {
  /** What to pick it by (an alias, a session name, a line of a CSV file). */
  id: string;
  label: string;
  hostname: string;
  port: number;
  user: string;
  auth: "key" | "agent" | "password";
  /** A password comes along (saved in the vault). */
  password: boolean;
  /** The key file it signs in with (`~/…`). */
  key: string | null;
  /** The jump hosts it goes through, first to last. */
  jumps: string[];
  /** The agent it signs in with, when not the system's. */
  agent: string | null;
  /** The one agent key it offers. */
  agentKey: string | null;
  forwardAgent: boolean;
  /** A command on this computer that connects it (`ProxyCommand`); importing allows it here. */
  proxyCommand: string | null;
  /** The group it goes in (made when the vault has none by that name). */
  group: string | null;
  tags: string[];
  /** What the other client does for it that the import leaves out. */
  unsupported: string[];
  /** A host with this address, port and user is in the vault already. */
  exists: boolean;
}

export interface ImportKey {
  path: string;
  fingerprint: string | null;
  algorithm: string | null;
  /** Needs its passphrase to be imported. */
  encrypted: boolean;
  /** The vault has this key already: hosts use that one. */
  inVault: boolean;
  error: string | null;
  /** How its hosts sign in when it can't be imported. */
  fallback: "agent" | "password";
  /** Its OpenSSH certificate, which comes along. */
  certificate: CertInfo | null;
  usedBy: string[];
}

export interface ImportPreview {
  /** What was read (`~/.ssh/config`, a file's name, "PuTTY's saved sessions"). */
  source: string;
  hosts: ImportHost[];
  keys: ImportKey[];
  warnings: string[];
}

export interface ImportResult {
  hosts: number;
  keys: number;
  groups: number;
  /** Certificates added to keys (new ones, or keys the vault had). */
  certificates: number;
  notes: string[];
}

/** Where hosts are imported from: a file (`path`, or one chosen in the app as `data`, base64), or
 * the source's usual place. */
export interface ImportSource {
  kind: "sshConfig" | "putty" | "csv" | "royal";
  path?: string | null;
  data?: string | null;
  name?: string | null;
}

export const hostImport = {
  /** What importing from `source` would bring. */
  preview: (source: ImportSource) => invoke<ImportPreview>("import_preview", { source }),
  run: (input: { source: ImportSource; ids: string[]; vaultId: string | null; passphrases: Record<string, string> }) =>
    invoke<ImportResult>("import_hosts", { input }),
};

export interface VaultEntry extends VaultInfo {
  label: string;
  /** Its team has no usable plan (and the server enforces plans): view only until it has one. */
  locked?: boolean;
}

/** `locked`: teams without a usable plan; their vaults count as view only. */
export const vaultEntries = (vaults: VaultInfo[], orgs: OrgInfo[], locked: Set<string> = new Set()): VaultEntry[] =>
  vaults.map((v) => {
    const entry: VaultEntry = {
      ...v,
      label: v.personal ? "Personal" : `${orgs.find((o) => o.id === v.orgId)?.name ?? "Team"} / ${v.name ?? "Shared vault"}`,
    };
    return v.orgId && locked.has(v.orgId) ? { ...entry, access: "read", locked: true } : entry;
  });

// ------------------------------------------------------------------ terminal appearance

/** A theme kept in the vault (imported from another terminal's theme file). */
export interface VaultTheme extends ThemeColors {
  id: string;
  vaultId: string;
}

export type CursorStyle = "block" | "bar" | "underline";

export type AppTheme = "dark" | "light" | "system";

/** This device's appearance (not synced). */
export interface TerminalSettings {
  /** Console (dark), Greenbar (light) or the system's choice. */
  appTheme: AppTheme;
  /** Default scheme: `builtin:…` or a vault theme's id. */
  theme: string;
  /** Console while the app is dark, Greenbar while it is light (instead of `theme`). */
  followAppTheme: boolean;
  /** CSS font list; "" = the app's. */
  fontFamily: string;
  fontSize: number;
  cursorStyle: CursorStyle;
  cursorBlink: boolean;
  /** Bold text in the bright colors. */
  boldBright: boolean;
  /** Ratio colors are adjusted to against their background; null = the scheme's own. */
  minimumContrast: number | null;
}

export type ThemeSource = { kind: "text"; text: string } | { kind: "file"; path: string };

export const appearance = {
  themes: () => invoke<VaultTheme[]>("themes_list"),
  /** Ghostty, Alacritty (.toml), iTerm2 (.itermcolors) or Windows Terminal (JSON). */
  importTheme: (source: ThemeSource, name: string, vaultId?: string) =>
    invoke<VaultTheme>("theme_import", { input: { source, name, vaultId } }),
  deleteTheme: (id: string) => invoke<void>("theme_delete", { id }),
  settings: () => invoke<TerminalSettings>("terminal_settings"),
  setSettings: (settings: TerminalSettings) => invoke<void>("terminal_settings_set", { settings }),
};

// ------------------------------------------------------------------ offboarding

/** A vault a member can open, and what's in it (this device's copy). */
export interface Reach {
  vaultId: string;
  name: string;
  access: Access;
  hosts: number;
  keys: number;
  vpns: number;
  other: number;
  /** The member key directory: members' public keys only. */
  directory: boolean;
}

/** A secret the member could read: change it after they leave. */
export interface Secret {
  kind: "password" | "key" | "vpn";
  itemId: string;
  label: string;
  vaultName: string;
  /** Keys: hosts that log in with it. */
  usedBy: string[];
}

export interface OffboardSummary {
  vaults: Reach[];
  secrets: Secret[];
  /** Fingerprints of the SSH keys they published (what a host scan looks for). */
  keys: string[];
}

export interface HostResult {
  hostId: string;
  label: string;
  /** Lines found or removed; null when the host couldn't be checked. */
  keys: number | null;
  problem: string | null;
}

export interface KeyReplaced {
  fingerprint: string;
  hosts: HostResult[];
  /** Hosts that still accept the old key. */
  oldKeyLeft: string[];
}

export const offboard = {
  summary: (orgId: string, accountId: string) => invoke<OffboardSummary>("offboard_summary", { orgId, accountId }),
  /** Connects to every organization host and looks for their published keys in authorized_keys. */
  scan: (orgId: string, accountId: string) => invoke<HostResult[]>("offboard_scan", { orgId, accountId }),
  clean: (orgId: string, accountId: string, hostIds: string[]) =>
    invoke<HostResult[]>("offboard_clean", { orgId, accountId, hostIds }),
  /** A new key in place of this one on every host that logs in with it, then in the vault. */
  replaceKey: (keyId: string) => invoke<KeyReplaced>("key_replace", { keyId }),
};

const PLATFORMS: Record<string, string> = { ios: "iOS", macos: "macOS", linux: "Linux", windows: "Windows", android: "Android" };

/** A device's operating system as people write it ("macos" → "macOS"). */
export const platformName = (p: string) => PLATFORMS[p.toLowerCase()] ?? p;

/** "just now", "5 min ago", "3 h ago", or a date. */
export function ago(ms: number): string {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return dateText(ms);
}

/** A date with the month's name ("Nov 3, 2026" or "3 Nov 2026" by locale), never "11/3/2026". */
export function dateText(at: number | string): string {
  return new Date(at).toLocaleDateString(undefined, { dateStyle: "medium" });
}

/** A date and time, the same way. */
export function dateTimeText(at: number | string): string {
  return new Date(at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1"]);
export const isLoopback = (host: string) => LOOPBACK.has(host.trim()) || host.trim().startsWith("127.");

/** `L :15432 → db:5432` style one-liner. */
export function describeForward(f: Pick<ForwardView, "rule" | "port">): string {
  const r = f.rule;
  const port = f.port ?? r.bindPort;
  const listen = `${isLoopback(r.bindHost) ? "" : r.bindHost}:${port || "auto"}`;
  if (r.kind === "dynamic") return `SOCKS ${listen}`;
  const to = `${r.targetHost}:${r.targetPort}`;
  return r.kind === "local" ? `L ${listen} → ${to}` : `R server${listen} → ${to}`;
}

export type VpnKind = "wireguard" | "openvpn" | "openconnect";

export const VPN_KINDS: { kind: VpnKind; name: string }[] = [
  { kind: "wireguard", name: "WireGuard" },
  { kind: "openvpn", name: "OpenVPN" },
  { kind: "openconnect", name: "OpenConnect" },
];

export const vpnKindName = (k: VpnKind) => VPN_KINDS.find((v) => v.kind === k)?.name ?? k;

/** openconnect `--protocol` values. */
export const OC_PROTOCOLS: { value: string; name: string }[] = [
  { value: "anyconnect", name: "Cisco AnyConnect / ocserv" },
  { value: "gp", name: "Palo Alto GlobalProtect" },
  { value: "fortinet", name: "Fortinet FortiGate" },
  { value: "pulse", name: "Pulse / Ivanti Connect Secure" },
  { value: "f5", name: "F5 BIG-IP" },
  { value: "nc", name: "Juniper Network Connect" },
  { value: "array", name: "Array Networks" },
];

export interface VpnView {
  id: string;
  /** The vault it lives in. */
  vaultId: string;
  label: string;
  kind: VpnKind;
  /** Where it connects, for lists. */
  server: string;
  facts: { label: string; value: string }[];
  /** WireGuard: this device's public key, for the VPN admin. */
  publicKey: string | null;
  username: string | null;
  hasPassword: boolean;
  protocol: string | null;
  authgroup: string | null;
  serverCert: string | null;
  active: boolean;
  /** While connected: this device's address inside the VPN. */
  address: string | null;
  problem: string | null;
  updatedAt: number;
}

export interface VpnInput {
  id?: string;
  /** A new item goes into this vault (default: the personal one). */
  vaultId?: string;
  kind: VpnKind;
  label: string;
  config?: string;
  configPath?: string;
  /** With `config` from a picked .ovpn: the files it refers to, picked along with it (base64). */
  configFiles?: { name: string; data: string }[];
  server?: string;
  protocol?: string;
  authgroup?: string;
  username?: string;
  /** Omit to keep the saved password; "" removes it. */
  password?: string;
  forgetServerCert?: boolean;
}

/** A VPN asks for input while connecting (`vpn-prompt` event). */
export type VpnPrompt =
  | {
      kind: "fields";
      promptId: number;
      vpn: string;
      title: string;
      message: string;
      fields: { label: string; secret: boolean; value: string }[];
    }
  | { kind: "certificate"; promptId: number; vpn: string; host: string; reason: string; fingerprint: string }
  /** Sign in on a web page (SAML / SSO); `error` says why the browser didn't open by itself. */
  | { kind: "browser"; promptId: number; vpn: string; title: string; url: string; error: string | null };

export const vpns = {
  list: () => invoke<VpnView[]>("vpns_list"),
  save: (input: VpnInput) => invoke<VpnView>("vpn_save", { input }),
  remove: (id: string) => invoke<void>("vpn_delete", { id }),
  test: (id: string) => invoke<{ server: string; address: string; millis: number }>("vpn_test", { id }),
  /** `null` = cancel (or don't trust); `[]` = trust a certificate. */
  answer: (promptId: number, answers: string[] | null) => invoke<void>("vpn_prompt_answer", { promptId, answers }),
};

export type EntryKind = "dir" | "file" | "symlink" | "other";

export interface FileEntry {
  name: string;
  kind: EntryKind;
  size: number;
  /** Unix seconds. */
  modified: number | null;
  /** Permission bits, e.g. 0o755. */
  mode: number | null;
  /** A symlink to a directory. */
  linkDir: boolean;
}

export const isDir = (e: FileEntry) => e.kind === "dir" || e.linkDir;

export interface Listing {
  path: string;
  entries: FileEntry[];
}

export interface TransferProgress {
  bytesDone: number;
  bytesTotal: number;
  filesDone: number;
  filesTotal: number;
  current: string;
}

export type TransferEvent =
  | ({ kind: "progress" } & TransferProgress)
  | { kind: "done"; bytes: number; files: number; skipped: string[] }
  | { kind: "failed"; message: string; exists: string | null }
  | { kind: "cancelled" };

function transferChannel(onEvent: (e: TransferEvent) => void) {
  const ch = new Channel<TransferEvent>();
  ch.onmessage = onEvent;
  return ch;
}

export const sftp = {
  open: (target: ConnectTarget) => invoke<{ id: number; home: string }>("sftp_open", { target }),
  close: (id: number) => invoke<void>("sftp_close", { id }),
  list: (id: number, path: string) => invoke<Listing>("sftp_list", { id, path }),
  mkdir: (id: number, path: string) => invoke<void>("sftp_mkdir", { id, path }),
  rename: (id: number, from: string, to: string) => invoke<void>("sftp_rename", { id, from, to }),
  remove: (id: number, paths: string[]) => invoke<void>("sftp_remove", { id, paths }),
  chmod: (id: number, path: string, mode: number) => invoke<void>("sftp_chmod", { id, path, mode }),
  /** Resolves to the transfer id (for cancel) right away; progress arrives on `onEvent`. */
  download: (id: number, paths: string[], localDir: string, overwrite: boolean, onEvent: (e: TransferEvent) => void) =>
    invoke<number>("sftp_download", { id, paths, localDir, overwrite, onEvent: transferChannel(onEvent) }),
  upload: (id: number, paths: string[], remoteDir: string, overwrite: boolean, onEvent: (e: TransferEvent) => void) =>
    invoke<number>("sftp_upload", { id, paths, remoteDir, overwrite, onEvent: transferChannel(onEvent) }),
  cancel: (transfer: number) => invoke<void>("sftp_cancel", { transfer }),
};

export const localFs = {
  home: () => invoke<string>("local_home"),
  list: (path: string) => invoke<Listing>("local_list", { path }),
  mkdir: (path: string) => invoke<void>("local_mkdir", { path }),
};

// ------------------------------------------------------------------ attachments

/** A file kept with a host. */
export interface AttachmentView {
  id: string;
  hostId: string | null;
  name: string;
  size: number;
  /** `remote`: added on another device, fetched when saved; `failed`: the server refused it. */
  state: "local" | "uploading" | "remote" | "failed";
  problem: string | null;
  upgradeUrl: string | null;
}

/** The largest file an attachment holds. */
export const MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024;

export const attachments = {
  list: (hostId: string) => invoke<AttachmentView[]>("attachments", { hostId }),
  /** The file's bytes go as the raw body; where and what in headers. */
  add: async (hostId: string, file: File) =>
    invoke<AttachmentView>("attachment_add", new Uint8Array(await file.arrayBuffer()), {
      headers: { "x-host-id": encodeURIComponent(hostId), "x-file-name": encodeURIComponent(file.name) },
    }),
  /** Saves it in Downloads; resolves to the path. */
  save: (id: string) => invoke<string>("attachment_save", { id }),
  remove: (id: string) => invoke<void>("attachment_delete", { id }),
};

// ------------------------------------------------------------------ moving between vaults

/** What happens to an item: it moves (same id), a copy goes, or it stays and what goes stops using it. */
export type Carry = "move" | "copy" | "leave";

export interface PlannedItem {
  id: string;
  /** The item kind (`host`, `ssh_key`, `identity`, …). */
  kind: string;
  label: string;
  why: { kind: "chosen" } | { kind: "rides"; with: string } | { kind: "used"; by: string[] };
  carry: Carry;
  /** What it can be switched to; empty when there is no choice. */
  choices: Carry[];
  /** Items that stay and use it: why a copy goes instead. */
  keptBy: string[];
}

export interface MovePlan {
  from: string;
  to: string;
  items: PlannedItem[];
  notes: string[];
}

export interface Moved {
  moved: number;
  copied: number;
  /** Each picked item's id in the other vault (a copy's is new). */
  ids: Record<string, string>;
}

export const moving = {
  plan: (ids: string[], to: string, choices: Record<string, Carry>) => invoke<MovePlan>("items_move_plan", { ids, to, choices }),
  move: (ids: string[], to: string, choices: Record<string, Carry>) => invoke<Moved>("items_move", { ids, to, choices }),
};

// ------------------------------------------------------------------ several items at once

/** What a change to several items did: how many changed, and why the others didn't. */
export interface BulkResult {
  done: number;
  refused: string[];
}

export const bulk = {
  /** Hosts, groups, keys, identities and snippets, in an order that works (a jump host after the
   * hosts behind it). Tunnels and VPNs have their own `remove`. */
  remove: (ids: string[]) => invoke<BulkResult>("items_delete", { ids }),
  /** Into a group of their vault, or out of any (null). */
  setGroup: (ids: string[], groupId: string | null) => invoke<BulkResult>("hosts_set_group", { ids, groupId }),
};

/** Opens a web page in the browser. */
export const openLink = (url: string) => invoke<void>("open_link", { url });

// ------------------------------------------------------------------ Cloud sources

export type CloudProvider = "vallic" | "aws" | "gcp" | "azure" | "hetzner" | "digitalocean";

/** Reaching a machine through its cloud rather than an address. */
export type CloudReachKind = "aws-ssm" | "aws-eice" | "gcp-iap";

export const REACH_NAMES: Record<CloudReachKind, string> = {
  "aws-ssm": "AWS Session Manager",
  "aws-eice": "an EC2 Instance Connect Endpoint",
  "gcp-iap": "IAP",
};

/** What a provider is called, and the CLI it lists with (none for Vallic Cloud). */
export const PROVIDERS: Record<CloudProvider, { name: string; cli: string | null }> = {
  vallic: { name: "Vallic Cloud", cli: null },
  aws: { name: "AWS", cli: "aws" },
  gcp: { name: "Google Cloud", cli: "gcloud" },
  azure: { name: "Azure", cli: "az" },
  hetzner: { name: "Hetzner Cloud", cli: "hcloud" },
  digitalocean: { name: "DigitalOcean", cli: "doctl" },
};

/** Hosts kept in step with a cloud: Vallic Cloud (each device signs in itself), or AWS, Google
 * Cloud and Azure (listed with their CLI on this device). */
export interface CloudSource {
  id: string;
  vaultId: string;
  label: string;
  provider: CloudProvider;
  endpoint: string | null;
  /** Who signed in when it was made. */
  account: string;
  /** The key its hosts sign in with; null: the SSH agent. */
  keyId: string | null;
  /** Unix seconds; 0 before the first refresh. */
  refreshedAt: number;
  /** This device can refresh it: signed in (Vallic Cloud), or it lists through a CLI. */
  signedIn: boolean;
  hosts: number;
  /** Hosts the provider no longer lists. */
  gone: number;
  /** AWS: the CLI profile; Hetzner Cloud and DigitalOcean: the CLI context. */
  profile: string | null;
  /** Regions, projects or subscription ids; empty: all. */
  scopes: string[];
  /** null: public addresses; "private": through `jumpId`; or through the cloud. */
  reach: "private" | CloudReachKind | null;
  jumpId: string | null;
  /** Who to log in as where a machine doesn't say. */
  user: string | null;
  /** Group by this tag instead of region, project or resource group. */
  groupTag: string | null;
  /** Where this device runs the CLI from, when it was given. */
  cliPath: string | null;
}

/** What a CLI source lists and how its machines become hosts. */
export interface SourceSettings {
  label?: string | null;
  profile?: string | null;
  scopes: string[];
  reach: "public" | "private" | CloudReachKind;
  jumpId?: string | null;
  user?: string | null;
  groupTag?: string | null;
}

/** A sign-in in progress: the code to type at the page. */
export interface DeviceAuth {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  interval: number | null;
}

export interface CloudRefresh {
  added: number;
  updated: number;
  gone: number;
  /** Environments with no shell for this person, or not running yet. */
  withoutShell: string[];
  /** Machines without the address the source uses. */
  withoutAddress: string[];
  /** Regions, projects or subscriptions that couldn't be listed, and why. */
  skipped: string[];
}

export type SignInStatus =
  | { status: "pending"; slower: boolean }
  | { status: "denied" }
  | { status: "expired" }
  | { status: "done"; source: CloudSource; refresh: CloudRefresh };

export const cloud = {
  sources: () => invoke<CloudSource[]>("cloud_sources"),
  signIn: (endpoint?: string | null) => invoke<DeviceAuth>("vallic_sign_in", { endpoint: endpoint ?? null }),
  /** `sourceId`: signing this device in to a source; else a new one in `vaultId` (default personal). */
  poll: (deviceCode: string, opts: { sourceId?: string | null; vaultId?: string | null; endpoint?: string | null } = {}) =>
    invoke<SignInStatus>("vallic_sign_in_poll", { deviceCode, sourceId: opts.sourceId ?? null, vaultId: opts.vaultId ?? null, endpoint: opts.endpoint ?? null }),
  refresh: (sourceId: string) => invoke<CloudRefresh>("cloud_refresh", { sourceId }),
  signOut: (sourceId: string) => invoke<void>("cloud_sign_out", { sourceId }),
  remove: (sourceId: string, deleteHosts: boolean) => invoke<void>("cloud_source_delete", { sourceId, deleteHosts }),
  setKey: (sourceId: string, keyId: string | null) => invoke<void>("cloud_source_key", { sourceId, keyId }),
  addKey: (sourceId: string, keyId: string) => invoke<void>("cloud_add_key", { sourceId, keyId }),
  /** The provider's CLI on this device, and who it's signed in as. */
  check: (provider: CloudProvider, profile?: string | null) => invoke<{ path: string; account: string }>("cloud_check", { provider, profile: profile ?? null }),
  /** Where this device runs a provider's CLI from (null: wherever it's found). */
  cliPath: (provider: CloudProvider, path: string | null) => invoke<void>("cloud_cli_path", { provider, path }),
  /** An AWS, Google Cloud or Azure source, listed right away. */
  add: (provider: CloudProvider, settings: SourceSettings, opts: { vaultId?: string | null; keyId?: string | null } = {}) =>
    invoke<{ source: CloudSource; refresh: CloudRefresh }>("cloud_source_add", { provider, settings, vaultId: opts.vaultId ?? null, keyId: opts.keyId ?? null }),
  settings: (sourceId: string, settings: SourceSettings) => invoke<void>("cloud_source_settings", { sourceId, settings }),
};

export const errorText = (e: unknown) => (typeof e === "string" ? e : e instanceof Error ? e.message : String(e));

/** The user closed an OS prompt (Touch ID, Windows Hello, polkit): nothing to report. */
export const isCancelled = (e: unknown) => errorText(e) === "cancelled";
/** The sync account has two-step verification: ask for a code and sign in again with it. */
export const isTotpRequired = (e: unknown) => errorText(e) === "totp_required";
/** Creating a team refused for too many teams without a plan: the message, or null. */
export const teamLimit = (e: unknown): string | null => {
  const text = errorText(e);
  return text.startsWith("team_limit: ") ? text.slice("team_limit: ".length) : null;
};
/** Deleting the account refused while it owns a team. */
export const ownsTeam = (e: unknown) => errorText(e).startsWith("you own a team");

// ------------------------------------------------------------------ session logs

export interface SessionLogView {
  id: string;
  vaultId: string;
  hostId: string | null;
  title: string;
  /** `user@host:port`, as connected. */
  address: string;
  /** Unix ms. */
  startedAt: number;
  /** Unix ms; null while recording (or if the recorder stopped without saying). */
  endedAt: number | null;
  outputBytes: number;
  /** Encrypted size. */
  size: number;
  /** The device that recorded it. */
  device: string;
  /** `local`: here and uploaded; `uploading`; `remote`: recorded elsewhere, fetched to play;
   *  `failed`: the server refused it (`problem` says why). */
  state: "local" | "uploading" | "remote" | "failed";
  problem: string | null;
  /** When the plan is why: where the team gets the plan that keeps recordings. */
  upgradeUrl: string | null;
}

export const sessionLogs = {
  list: (hostId?: string) => invoke<SessionLogView[]>("session_logs", { hostId: hostId ?? null }),
  /** The recording as an asciicast v2 file. */
  cast: (id: string) => invoke<string>("session_log_cast", { id }),
  /** Saves it as a `.cast` file in Downloads; returns the path. */
  save: (id: string) => invoke<string>("session_log_save", { id }),
  remove: (id: string) => invoke<void>("session_log_delete", { id }),
  /** Uploads refused recordings again. */
  retry: () => invoke<number>("session_logs_retry"),
};
